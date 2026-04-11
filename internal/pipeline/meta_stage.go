package pipeline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"disunity/internal/metadata"
	"disunity/internal/output"
)

// UnityMeta is the unified metadata interchange format for Ghidra/IDA scripts.
type UnityMeta struct {
	Version       string           `json:"version"`
	IL2CPPVersion int32            `json:"il2cpp_version"`
	PointerSize   int              `json:"pointer_size"`
	Functions     []UnityMetaFunc  `json:"functions"`
	Comments      []UnityMetaComment `json:"comments,omitempty"`
	FocusFunctions []string        `json:"focus_functions,omitempty"`
	Classes       []UnityMetaClass `json:"classes"`
}

// TypeResolver converts an Il2CppType index to a C type string.
type TypeResolver func(typeIndex int32) string

// UnityMetaFunc describes a function for decompiler import.
type UnityMetaFunc struct {
	Addr       string           `json:"addr"`
	Name       string           `json:"name"`
	Size       int              `json:"size,omitempty"`
	Owner      string           `json:"owner,omitempty"`
	Image      string           `json:"image,omitempty"`
	ParamCount int              `json:"param_count,omitempty"`
	ReturnType string           `json:"return_type,omitempty"`
	IsStatic   bool             `json:"is_static,omitempty"`
	Params     []UnityMetaParam `json:"params,omitempty"`
}

// UnityMetaParam describes a function parameter.
type UnityMetaParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// UnityMetaComment describes an inline comment for decompiler import.
type UnityMetaComment struct {
	Addr string `json:"addr"`
	Text string `json:"text"`
}

// UnityMetaClass describes a class layout for struct generation.
type UnityMetaClass struct {
	ClassName    string           `json:"class_name"`
	Namespace    string           `json:"namespace,omitempty"`
	InstanceSize int32            `json:"instance_size"`
	Fields       []UnityMetaField `json:"fields,omitempty"`
	ParentClass  string           `json:"parent_class,omitempty"`
}

// UnityMetaField describes a class field.
type UnityMetaField struct {
	Name       string `json:"name"`
	TypeName   string `json:"type_name"`
	ByteOffset int32  `json:"byte_offset"`
}

// RunMetaStage generates unity_meta.json from parsed metadata and disasm output.
func RunMetaStage(
	meta *metadata.GlobalMetadata,
	sj *output.ScriptJSON,
	outDir string,
	decompAll bool,
	quiet bool,
	log io.Writer,
	typeResolver TypeResolver,
) (string, error) {
	um := &UnityMeta{
		Version:       "1",
		IL2CPPVersion: meta.Header.Version,
		PointerSize:   8, // ARM64
	}

	// Build fullName → methodDef index map for signature lookup
	nameToMethodIdx := make(map[string]int)
	if typeResolver != nil {
		for _, mi := range meta.GetAllMethods() {
			nameToMethodIdx[mi.Name] = mi.Index
		}
	}

	// Build functions list from script.json
	sigCount := 0
	for _, entry := range sj.Methods {
		owner, _ := splitMethodName(entry.FullName)
		f := UnityMetaFunc{
			Addr:  fmt.Sprintf("0x%X", entry.Address),
			Name:  entry.FullName,
			Owner: owner,
			Image: entry.Image,
		}

		// Populate signature if type resolver is available
		if typeResolver != nil {
			if methodIdx, ok := nameToMethodIdx[entry.FullName]; ok {
				populateSignature(&f, meta, methodIdx, typeResolver)
				sigCount++
			}
		}

		um.Functions = append(um.Functions, f)
	}

	// Build class layouts from metadata.
	// Instance sizes and field offsets live in the binary (not metadata),
	// so we use the il2cpp.h struct generator for full layouts.
	// Here we capture the name/namespace/parent/fields from metadata only.
	for i, td := range meta.TypeDefinitions {
		className := meta.GetTypeName(i)
		if className == "" {
			continue
		}

		// Get namespace from the full name
		ns := ""
		if idx := strings.LastIndex(className, "."); idx >= 0 {
			ns = className[:idx]
			className = className[idx+1:]
		}

		cls := UnityMetaClass{
			ClassName: className,
			Namespace: ns,
		}

		// Get parent class name
		if td.ParentIndex >= 0 && int(td.ParentIndex) < len(meta.TypeDefinitions) {
			cls.ParentClass = meta.GetTypeName(int(td.ParentIndex))
		}

		// Get field names (offsets require binary data, stored as 0 here)
		if td.FieldStart >= 0 && td.FieldCount > 0 {
			for fi := int(td.FieldStart); fi < int(td.FieldStart)+int(td.FieldCount); fi++ {
				if fi >= len(meta.FieldDefinitions) {
					break
				}
				fd := meta.FieldDefinitions[fi]
				fieldName := meta.GetFieldName(fi)
				cls.Fields = append(cls.Fields, UnityMetaField{
					Name:     fieldName,
					TypeName: fmt.Sprintf("type_%d", fd.TypeIndex),
				})
			}
		}

		um.Classes = append(um.Classes, cls)
	}

	// Build focus functions list
	if !decompAll {
		// Focus on Assembly-CSharp methods only
		for _, f := range um.Functions {
			if strings.Contains(f.Image, "Assembly-CSharp") {
				um.FocusFunctions = append(um.FocusFunctions, f.Addr)
			}
		}
	}

	// Extract comments from asm files
	asmDir := filepath.Join(outDir, "asm")
	um.Comments = extractAsmComments(asmDir)

	// Write unity_meta.json
	outPath := filepath.Join(outDir, "unity_meta.json")
	data, err := json.MarshalIndent(um, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal unity_meta.json: %w", err)
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return "", fmt.Errorf("write unity_meta.json: %w", err)
	}

	if !quiet {
		fmt.Fprintf(log, "  functions: %d\n", len(um.Functions))
		if sigCount > 0 {
			fmt.Fprintf(log, "  signatures: %d\n", sigCount)
		}
		fmt.Fprintf(log, "  classes: %d\n", len(um.Classes))
		if len(um.FocusFunctions) > 0 {
			fmt.Fprintf(log, "  focus: %d (Assembly-CSharp)\n", len(um.FocusFunctions))
		}
		fmt.Fprintf(log, "  comments: %d\n", len(um.Comments))
		fmt.Fprintf(log, "  -> unity_meta.json (%d bytes)\n", len(data))
	}

	return outPath, nil
}

// populateSignature fills return type, parameters, and static flag for a function.
func populateSignature(f *UnityMetaFunc, meta *metadata.GlobalMetadata, methodIdx int, resolve TypeResolver) {
	if methodIdx < 0 || methodIdx >= len(meta.MethodDefinitions) {
		return
	}
	md := meta.MethodDefinitions[methodIdx]
	if md == nil {
		return
	}

	f.ReturnType = resolve(md.ReturnTypeIndex)
	f.IsStatic = (md.Flags & 0x10) != 0
	f.ParamCount = int(md.ParameterCount)

	// Build parameter list: [this], user params, MethodInfo*
	var params []UnityMetaParam

	if !f.IsStatic {
		// Instance method - add 'this' pointer using owner's type
		if md.DeclaringTypeIndex >= 0 && int(md.DeclaringTypeIndex) < len(meta.TypeDefinitions) {
			td := meta.TypeDefinitions[md.DeclaringTypeIndex]
			thisType := resolve(td.ByvalTypeIndex)
			params = append(params, UnityMetaParam{Name: "__this", Type: thisType})
		} else {
			params = append(params, UnityMetaParam{Name: "__this", Type: "void*"})
		}
	}

	// User-declared parameters
	paramEnd := md.ParameterStart + int32(md.ParameterCount)
	for pi := md.ParameterStart; pi < paramEnd; pi++ {
		if int(pi) >= len(meta.ParameterDefinitions) {
			break
		}
		pd := meta.ParameterDefinitions[pi]
		pName := meta.GetParameterName(int(pi))
		pType := resolve(pd.TypeIndex)
		params = append(params, UnityMetaParam{Name: pName, Type: pType})
	}

	// Trailing MethodInfo* parameter
	params = append(params, UnityMetaParam{Name: "method", Type: "const MethodInfo*"})

	f.Params = params
}

// extractAsmComments parses asm files for BL annotation comments.
func extractAsmComments(asmDir string) []UnityMetaComment {
	var comments []UnityMetaComment

	filepath.Walk(asmDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".txt") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(data), "\n") {
			// Parse lines like: 0x00d29cb0  f6 fc 20 94  BL .+0x83f3d8  ; System.Convert$$FromBase64String
			semi := strings.Index(line, " ; ")
			if semi < 0 {
				continue
			}
			// Extract address (first 10+ chars "0x00d29cb0")
			addr := strings.TrimSpace(strings.Fields(line)[0])
			comment := line[semi+3:]
			if addr != "" && comment != "" {
				comments = append(comments, UnityMetaComment{
					Addr: addr,
					Text: comment,
				})
			}
		}
		return nil
	})

	return comments
}
