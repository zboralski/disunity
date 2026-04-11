package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"disunity/internal/pipeline"
)

// cmdIDA handles "disunity ida <lib> <meta>" -- full pipeline + IDA decompilation.
func cmdIDA(args []string) error {
	fs := flag.NewFlagSet("ida", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.disunity/)")
	all := fs.Bool("all", false, "decompile ALL functions")
	pythonBin := fs.String("python", "", "python3 binary (default: auto-detect)")
	from := fs.String("from", "", "reuse existing disasm output directory")
	quiet := false
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Parse positional args: <lib> <meta>
	libPath, metaFilePath, _ := parseLibMeta(fs)

	if libPath == "" && *from == "" {
		return fmt.Errorf("usage: disunity ida <libil2cpp.so> <global-metadata.dat> [flags]\n       disunity ida --from <existing_output> [flags]")
	}

	absLibPath := ""
	if libPath != "" {
		absLibPath = resolvePositionalLib(libPath)
		if absLibPath == "" {
			return fmt.Errorf("file not found: %s", libPath)
		}
	}

	if *outDir == "" && libPath != "" {
		*outDir = defaultOutDir(libPath)
	}

	// Step 1: Run pipeline (or reuse existing output).
	var pipeResult *pipeline.Result
	if *from != "" {
		metaJSON := filepath.Join(*from, "unity_meta.json")
		if _, err := os.Stat(metaJSON); err != nil {
			return fmt.Errorf("no unity_meta.json in --from directory: %s\n  run the full pipeline first: disunity <lib> <meta>", *from)
		}
		pipeResult = &pipeline.Result{
			OutDir:   *from,
			MetaJSON: metaJSON,
		}
		if *outDir == "" {
			*outDir = *from
		}
		if absLibPath == "" {
			candidates := []string{
				filepath.Join(filepath.Dir(*from), "libil2cpp.so"),
				filepath.Join(*from, "..", "libil2cpp.so"),
			}
			for _, c := range candidates {
				if _, err := os.Stat(c); err == nil {
					absLibPath, _ = filepath.Abs(c)
					break
				}
			}
			if absLibPath == "" {
				return fmt.Errorf("cannot find libil2cpp.so; specify as positional arg:\n  disunity ida --from %s <libil2cpp.so> <global-metadata.dat>", *from)
			}
		}
	} else {
		var err error
		pipeResult, err = pipeline.Run(pipeline.Opts{
			LibPath:  libPath,
			MetaPath: metaFilePath,
			OutDir:   *outDir,
			All:      *all,
			Quiet:    quiet,
			Log:      os.Stderr,
		})
		if err != nil {
			return err
		}
	}

	metaPath := pipeResult.MetaJSON
	if metaPath == "" {
		metaPath = filepath.Join(pipeResult.OutDir, "unity_meta.json")
	}

	// Step 2: Copy script into artifact directory.
	if copyErr := copyIDAArtifacts(pipeResult.OutDir); copyErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not copy IDA script: %v\n", copyErr)
	}

	// Step 3: Find python3 with idapro.
	python, err := findPython(*pythonBin)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "python: %s\n", python)

	// Step 4: Find IDA script.
	scriptPath, err := findIDAScript()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "script: %s\n", scriptPath)

	// Step 5: Run idalib.
	decompDir := filepath.Join(pipeResult.OutDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)

	if *all {
		fmt.Fprintf(os.Stderr, "running IDA idalib analysis (decompiling ALL functions)...\n")
	} else {
		fmt.Fprintf(os.Stderr, "running IDA idalib analysis (Assembly-CSharp only, use --all for everything)...\n")
	}
	fmt.Fprintf(os.Stderr, "  decompile output: %s\n", absDecompDir)

	cmd := exec.Command(python, scriptPath, absLibPath, absMetaPath, absDecompDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ida script failed: %w", err)
	}

	cCount := countDecompiledFiles(absDecompDir)
	fmt.Fprintf(os.Stderr, "decompiled %d functions -> %s\n", cCount, absDecompDir)

	return nil
}
