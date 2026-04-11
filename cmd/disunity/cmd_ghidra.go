package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"disunity/internal/pipeline"
)

// cmdGhidra handles "disunity ghidra <lib> <meta>" -- full pipeline + Ghidra decompilation.
func cmdGhidra(args []string) error {
	fs := flag.NewFlagSet("ghidra", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.disunity/)")
	ghidraHome := fs.String("ghidra-home", "", "Ghidra installation directory")
	all := fs.Bool("all", false, "decompile ALL functions")
	full := fs.Bool("full", false, "run all Ghidra analyzers (slower, slightly better output)")
	gui := fs.Bool("gui", false, "launch Ghidra GUI after generating artifacts")
	projectDir := fs.String("projects", "", "Ghidra project directory (default: <outdir>/ghidra-projects)")
	from := fs.String("from", "", "reuse existing disasm output directory")
	quiet := false
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Parse positional args: <lib> <meta>
	libPath, metaFilePath, _ := parseLibMeta(fs)

	// Need either positional args or --from.
	if libPath == "" && *from == "" {
		return fmt.Errorf("usage: disunity ghidra <libil2cpp.so> <global-metadata.dat> [flags]\n       disunity ghidra --from <existing_output> [flags]")
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
		// Reuse existing output. Check for unity_meta.json.
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
		// If lib not given as positional, look for it in --from parent.
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
				return fmt.Errorf("cannot find libil2cpp.so; specify as positional arg:\n  disunity ghidra --from %s <libil2cpp.so> <global-metadata.dat>", *from)
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

	// Step 2: Copy scripts into artifact directory and use that as scriptPath.
	absOutDir, _ := filepath.Abs(pipeResult.OutDir)
	scriptPath := filepath.Join(absOutDir, "ghidra")
	if copyErr := copyGhidraArtifacts(pipeResult.OutDir); copyErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not copy Ghidra scripts: %v\n", copyErr)
		var findErr error
		scriptPath, findErr = findGhidraScriptPath()
		if findErr != nil {
			return fmt.Errorf("Ghidra scripts not found: %v (copy also failed: %v)", findErr, copyErr)
		}
	}

	// Step 3: Find Ghidra.
	ghLauncher, ghHome, err := findGhidra(*ghidraHome)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ghidra: %s\n", ghHome)

	// Step 4: Handle --gui (launch interactive Ghidra).
	if *gui {
		return launchGhidraGUI(ghHome, absLibPath, pipeResult.OutDir)
	}

	// Step 5: Run headless analysis.
	decompDir := filepath.Join(pipeResult.OutDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)

	projectName := sanitizeProjectName(filepath.Base(filepath.Dir(pipeResult.OutDir)))

	if *projectDir == "" {
		*projectDir = filepath.Join(pipeResult.OutDir, "ghidra-projects")
	}
	absProjDir := sanitizeGhidraPath(*projectDir)
	if err := os.MkdirAll(absProjDir, 0o755); err != nil {
		return fmt.Errorf("create project dir: %w", err)
	}

	fmt.Fprintf(os.Stderr, "running Ghidra headless analysis (Assembly-CSharp only, use --all for everything)...\n")
	fmt.Fprintf(os.Stderr, "  project: %s/%s\n", absProjDir, projectName)
	fmt.Fprintf(os.Stderr, "  import: %s\n", absLibPath)
	fmt.Fprintf(os.Stderr, "  decompile output: %s\n", absDecompDir)

	ghidraArgs := []string{
		absProjDir,
		projectName,
		"-import", absLibPath,
		"-overwrite",
		"-processor", "AARCH64:LE:64:v8A",
		"-scriptPath", scriptPath,
	}

	// By default, run prescript to disable unnecessary analyzers (~2 min savings).
	// --full skips the prescript and runs all Ghidra analyzers.
	if !*full {
		ghidraArgs = append(ghidraArgs, "-preScript", "disunity_prescript.py")
	}

	ghidraArgs = append(ghidraArgs,
		"-postScript", "disunity_apply.py", absMetaPath, absDecompDir,
	)

	env := os.Environ()
	if os.Getenv("JAVA_HOME") == "" {
		javaHome := findJavaHome(ghHome)
		if javaHome != "" {
			env = append(env, "JAVA_HOME="+javaHome)
		}
	}

	cmd := exec.Command(ghLauncher.cmd, append(ghLauncher.prefix, ghidraArgs...)...)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("analyzeHeadless failed: %w", err)
	}

	cCount := countDecompiledFiles(absDecompDir)
	fmt.Fprintf(os.Stderr, "decompiled %d functions -> %s\n", cCount, absDecompDir)

	return nil
}

// launchGhidraGUI starts Ghidra in interactive mode and prints instructions.
func launchGhidraGUI(ghidraHome, libPath, outDir string) error {
	ghidraRun := filepath.Join(ghidraHome, "ghidraRun")
	if _, err := os.Stat(ghidraRun); err != nil {
		return fmt.Errorf("ghidraRun not found at %s", ghidraRun)
	}

	scriptPath, err := findGhidraScriptPath()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nLaunching Ghidra GUI...\n")
	fmt.Fprintf(os.Stderr, "  1. Import: %s\n", libPath)
	fmt.Fprintf(os.Stderr, "  2. Open Script Manager (Window > Script Manager)\n")
	fmt.Fprintf(os.Stderr, "  3. Add script directory: %s\n", scriptPath)
	fmt.Fprintf(os.Stderr, "  4. Run disunity_prescript.py first, then disunity_apply.py\n")
	fmt.Fprintf(os.Stderr, "     (or pass unity_meta.json path as script argument)\n")
	fmt.Fprintf(os.Stderr, "  Meta: %s/unity_meta.json\n\n", outDir)

	env := os.Environ()
	if os.Getenv("JAVA_HOME") == "" {
		javaHome := findJavaHome(ghidraHome)
		if javaHome != "" {
			env = append(env, "JAVA_HOME="+javaHome)
		}
	}

	cmd := exec.Command(ghidraRun)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Start()
}
