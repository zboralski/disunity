// Package pipeline orchestrates the disunity extraction stages.
package pipeline

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"disunity/internal/binary"
	"disunity/internal/metadata"
	"disunity/internal/output"
)

// Opts controls pipeline execution.
type Opts struct {
	LibPath    string // path to libil2cpp.so
	MetaPath   string // path to global-metadata.dat
	OutDir     string // output directory
	FromDir    string // reuse existing output (skip binary scan)
	All        bool   // include all functions in focus list
	Quiet      bool   // suppress verbose output
	SkipDisasm bool   // skip disasm and meta stages (fast mode)
	Log        io.Writer
}

// Result summarizes pipeline output.
type Result struct {
	OutDir        string
	LibPath       string
	MetaPath      string
	IL2CPPVersion float64
	MethodCount   int
	GenericCount  int
	ClassCount    int
	TypeCount     int
	ScriptJSON    string // path to script.json
	StructHeader  string // path to il2cpp.h
	MetaJSON      string // path to unity_meta.json
	Diags         []string
}

func (o *Opts) log(format string, args ...any) {
	if o.Quiet {
		return
	}
	fmt.Fprintf(o.Log, format, args...)
}

// Run executes the full extraction pipeline.
func Run(opts Opts) (*Result, error) {
	if opts.Log == nil {
		opts.Log = os.Stderr
	}

	result := &Result{
		OutDir:   opts.OutDir,
		LibPath:  opts.LibPath,
		MetaPath: opts.MetaPath,
	}

	// Create output directory
	if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	// Stage 1: Parse global-metadata.dat
	opts.log("\nmeta %s\n", filepath.Base(opts.MetaPath))
	t0 := time.Now()

	meta, err := metadata.ParseFile(opts.MetaPath)
	if err != nil {
		// Only attempt auto-decryption for encrypted metadata or structural
		// parse failures (wrong image count, etc.). Skip for truncated files
		// where the error is about tables extending beyond EOF - those are
		// corrupt, not encrypted, and Kasiski will hang on large files.
		errStr := err.Error()
		truncated := strings.Contains(errStr, "beyond file") ||
			strings.Contains(errStr, "too small")
		if !truncated {
			opts.log("  parse failed: %v\n", err)
			opts.log("  attempting auto-decrypt...\n")
			decrypted, key, decErr := metadata.TryAutoDecrypt(opts.LibPath, opts.MetaPath)
			if decErr == nil {
				meta, err = metadata.Parse(decrypted)
				if err == nil {
					if key != nil {
						opts.log("  decrypted with key: %q (length=%d)\n", key.KeyString, len(key.Key))
					} else {
						opts.log("  decrypted (no key info)\n")
					}
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("parse metadata: %w", err)
		}
	}

	result.IL2CPPVersion = float64(meta.Header.Version)
	allMethods := meta.GetAllMethods()
	opts.log("  version: %d\n", meta.Header.Version)
	opts.log("  types: %d  methods: %d  images: %d\n",
		len(meta.TypeDefinitions), len(meta.MethodDefinitions), len(meta.ImageDefinitions))
	opts.log("  parsed in %v\n", time.Since(t0).Round(time.Millisecond))

	// Stage 2: Scan libil2cpp.so
	opts.log("\nbinary %s\n", filepath.Base(opts.LibPath))
	t1 := time.Now()

	analyzer, err := binary.NewIL2CPPStaticAnalyzer(
		opts.LibPath, float64(meta.Header.Version),
		len(meta.ImageDefinitions), len(meta.TypeDefinitions),
		len(meta.MethodDefinitions),
	)
	if err != nil {
		return nil, fmt.Errorf("open binary: %w", err)
	}
	defer analyzer.Close()

	// Find CodeRegistration
	codeRegVA, err := analyzer.FindCodeRegistration()
	if err != nil {
		return nil, fmt.Errorf("find CodeRegistration: %w", err)
	}
	opts.log("  CodeRegistration: 0x%X\n", codeRegVA)

	// Read CodeGenModules (v24.2+) or flat method pointers (pre-v24.2)
	modules, err := analyzer.ReadCodeGenModules(codeRegVA)
	if err != nil || len(modules) == 0 {
		// Try old-style flat method pointers
		flatModules, flatErr := analyzer.ReadMethodPointersFlat(codeRegVA)
		if flatErr == nil && len(flatModules) > 0 && len(flatModules[0].MethodPointers) > 0 {
			modules = flatModules
			opts.log("  MethodPointers (flat): %d methods\n", len(modules[0].MethodPointers))
		} else if err != nil {
			result.Diags = append(result.Diags, fmt.Sprintf("CodeGenModules: %v", err))
			opts.log("  CodeGenModules: %v (continuing)\n", err)
		} else {
			opts.log("  CodeGenModules: 0 assemblies (continuing)\n")
		}
	} else {
		opts.log("  CodeGenModules: %d assemblies\n", len(modules))
	}

	// Read generic method pointers
	// Try old-style first if we used flat method pointers (pre-CodeGenModules)
	isOldStyle := len(modules) == 1 && modules[0].Name == ""
	var genericPtrs []uint64
	if isOldStyle {
		genericPtrs, err = analyzer.ReadGenericMethodPointersOld(codeRegVA)
	} else {
		genericPtrs, err = analyzer.ReadGenericMethodPointers(codeRegVA)
	}
	if err != nil {
		result.Diags = append(result.Diags, fmt.Sprintf("genericMethodPointers: %v", err))
	} else if len(genericPtrs) > 0 {
		opts.log("  genericMethodPointers: %d\n", len(genericPtrs))
	}

	// Find MetadataRegistration
	metaRegVA, err := analyzer.FindMetadataRegistration()
	if err != nil && isOldStyle {
		// Old-style: MetadataRegistration follows CodeRegistration immediately.
		// v24 CodeRegistration is 14 fields = 112 bytes.
		metaRegVA = codeRegVA + 14*8
		opts.log("  MetadataRegistration (old-style, after CodeReg): 0x%X\n", metaRegVA)
		err = nil
	}
	if err != nil {
		result.Diags = append(result.Diags, fmt.Sprintf("MetadataRegistration: %v", err))
		opts.log("  MetadataRegistration: %v (continuing)\n", err)
	} else if !isOldStyle {
		opts.log("  MetadataRegistration: 0x%X\n", metaRegVA)
	}

	// Read types from MetadataRegistration
	var il2cppTypes []*binary.Il2CppType
	if metaRegVA != 0 {
		il2cppTypes, err = analyzer.ReadTypes(metaRegVA)
		if err != nil {
			result.Diags = append(result.Diags, fmt.Sprintf("types: %v", err))
		} else {
			opts.log("  types: %d\n", len(il2cppTypes))
			result.TypeCount = len(il2cppTypes)
		}
	}

	// Read generic methods
	var genericMethods []binary.GenericMethodInfo
	if metaRegVA != 0 && len(genericPtrs) > 0 {
		genericMethods, err = analyzer.ReadGenericMethods(metaRegVA, genericPtrs)
		if err != nil {
			result.Diags = append(result.Diags, fmt.Sprintf("genericMethods: %v", err))
		} else {
			result.GenericCount = len(genericMethods)
			opts.log("  generic methods: %d\n", len(genericMethods))
		}
	}

	// Read RGCTX data
	rgctxData, err := analyzer.ReadRGCTXData(codeRegVA)
	if err != nil {
		result.Diags = append(result.Diags, fmt.Sprintf("RGCTX: %v", err))
	} else if rgctxData != nil {
		opts.log("  RGCTX: %d types, %d methods\n",
			len(rgctxData.TypeRGCTXs), len(rgctxData.MethodRGCTXs))
	}

	opts.log("  scanned in %v\n", time.Since(t1).Round(time.Millisecond))

	// Stage 3: Generate script.json
	opts.log("\nscript %d methods\n", len(allMethods))
	t2 := time.Now()

	// Convert CodeGenModuleStatic to output.CodeGenModuleInfo
	var outModules []*output.CodeGenModuleInfo
	for _, m := range modules {
		outModules = append(outModules, &output.CodeGenModuleInfo{
			Name:           m.Name,
			MethodPointers: m.MethodPointers,
		})
	}

	// Convert generic methods
	var outGenericMethods []output.GenericMethodEntry
	for _, gm := range genericMethods {
		outGenericMethods = append(outGenericMethods, output.GenericMethodEntry{
			MethodDefinitionIndex: gm.MethodDefinitionIndex,
			ClassIndexIndex:       gm.ClassIndexIndex,
			MethodIndexIndex:      gm.MethodIndexIndex,
			Address:               gm.Address,
		})
	}

	var sj *output.ScriptJSON
	// Detect flat method pointers (single module, empty name = old-style CodeRegistration)
	if len(outModules) == 1 && outModules[0].Name == "" && len(outModules[0].MethodPointers) > 0 {
		sj, err = output.GenerateScriptJSONFromGlobal(meta, outModules[0].MethodPointers)
		// Merge generic methods into the result
		if err == nil && len(outGenericMethods) > 0 {
			for _, gm := range outGenericMethods {
				if gm.Address == 0 {
					continue
				}
				name := meta.GetMethodFullName(int(gm.MethodDefinitionIndex))
				if name == "" {
					continue
				}
				key := fmt.Sprintf("0x%X", gm.Address)
				if _, exists := sj.Methods[key]; !exists {
					sj.Methods[key] = &output.ScriptEntry{
						Address:  gm.Address,
						FullName: name,
						Name:     meta.GetMethodName(int(gm.MethodDefinitionIndex)),
					}
					sj.Count++
				}
			}
		}
	} else if len(outGenericMethods) > 0 {
		sj, err = output.GenerateScriptJSONWithGenerics(meta, outModules, outGenericMethods)
	} else {
		sj, err = output.GenerateScriptJSON(meta, outModules)
	}
	if err != nil {
		return nil, fmt.Errorf("generate script.json: %w", err)
	}

	result.MethodCount = sj.Count

	// Write string literals for signal stage.
	stringLiterals := meta.GetAllStringLiterals()
	if len(stringLiterals) > 0 {
		slPath := filepath.Join(opts.OutDir, "string_literals.jsonl")
		if slFile, err := os.Create(slPath); err == nil {
			slEnc := json.NewEncoder(slFile)
			for _, s := range stringLiterals {
				slEnc.Encode(s)
			}
			slFile.Close()
			opts.log("  string literals: %d\n", len(stringLiterals))
		}
	}

	sjPath := filepath.Join(opts.OutDir, "script.json")
	if err := output.WriteScriptJSON(sj, sjPath); err != nil {
		return nil, fmt.Errorf("write script.json: %w", err)
	}
	result.ScriptJSON = sjPath

	// Write IDA and Ghidra import scripts
	idaPath := filepath.Join(opts.OutDir, "ida_script.py")
	if err := output.WriteIDAScript(sj, idaPath); err != nil {
		result.Diags = append(result.Diags, fmt.Sprintf("ida_script: %v", err))
	}
	ghidraPath := filepath.Join(opts.OutDir, "ghidra_script.py")
	if err := output.WriteGhidraScript(sj, ghidraPath); err != nil {
		result.Diags = append(result.Diags, fmt.Sprintf("ghidra_script: %v", err))
	}

	opts.log("  resolved: %d methods (%d generic)\n", sj.Count, result.GenericCount)
	opts.log("  -> script.json (%d bytes)\n", fileSize(sjPath))

	// Stage 4: Generate il2cpp.h
	var sg *output.StructGenerator
	if len(il2cppTypes) > 0 {
		sg = output.NewStructGeneratorWithAnalyzer(meta, il2cppTypes, float64(meta.Header.Version), analyzer)

		// Set RGCTX data if available
		if rgctxData != nil {
			rgctx := output.NewRGCTXData(rgctxData)
			sg.SetRGCTXData(rgctx)
		}

		headerContent := sg.GenerateHeader()
		headerPath := filepath.Join(opts.OutDir, "il2cpp.h")
		if err := os.WriteFile(headerPath, []byte(headerContent), 0644); err != nil {
			result.Diags = append(result.Diags, fmt.Sprintf("il2cpp.h: %v", err))
			opts.log("  il2cpp.h: %v\n", err)
		} else {
			result.StructHeader = headerPath
			result.ClassCount = sg.ClassCount()
			opts.log("  -> il2cpp.h (%d bytes, %d classes)\n", fileSize(headerPath), result.ClassCount)
		}
	}

	opts.log("  generated in %v\n", time.Since(t2).Round(time.Millisecond))

	var disasmResult *DisasmResult
	if !opts.SkipDisasm {
		// Stage 5: Disassemble functions
		opts.log("\ndisasm %d methods\n", sj.Count)
		t3 := time.Now()

		disasmResult, err = RunDisasmStage(opts.LibPath, sj, opts.OutDir, opts.Quiet, opts.Log)
		if err != nil {
			result.Diags = append(result.Diags, fmt.Sprintf("disasm: %v", err))
			opts.log("  disasm: %v\n", err)
		} else {
			opts.log("  functions: %d\n", disasmResult.Written)
			opts.log("  call edges: %d (%d BL, %d BLR)\n",
				disasmResult.TotalEdges, disasmResult.TotalBL, disasmResult.TotalBLR)
			opts.log("  disassembled in %v\n", time.Since(t3).Round(time.Millisecond))
		}

		// Stage 6: Generate unity_meta.json
		opts.log("\nmeta\n")
		t4 := time.Now()

		// Pass type resolver from StructGenerator if available
		var typeResolver TypeResolver
		if sg != nil {
			typeResolver = sg.ParseTypeIndex
		}
		metaPath, err := RunMetaStage(meta, sj, opts.OutDir, opts.All, opts.Quiet, opts.Log, typeResolver)
		if err != nil {
			result.Diags = append(result.Diags, fmt.Sprintf("unity_meta: %v", err))
			opts.log("  unity_meta: %v\n", err)
		} else {
			result.MetaJSON = metaPath
			opts.log("  generated in %v\n", time.Since(t4).Round(time.Millisecond))
		}
	}

	// Summary
	opts.log("\nsummary\n")
	opts.log("  output:     %s\n", opts.OutDir)
	opts.log("  il2cpp:     v%d\n", meta.Header.Version)
	opts.log("  methods:    %d (%d generic)\n", result.MethodCount, result.GenericCount)
	if result.ClassCount > 0 {
		opts.log("  classes:    %d\n", result.ClassCount)
	}
	if disasmResult != nil {
		opts.log("  disasm:     %d functions, %d edges\n", disasmResult.Written, disasmResult.TotalEdges)
	}

	return result, nil
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
