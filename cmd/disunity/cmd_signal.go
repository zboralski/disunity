package main

import (
	"flag"
	"fmt"
	"os"

	"disunity/internal/pipeline"
)

func cmdSignal(args []string) error {
	fs := flag.NewFlagSet("signal", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory")
	from := fs.String("from", "", "reuse existing disasm output")
	k := fs.Int("k", 2, "context depth hops")
	quiet := false
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// If --from is provided, run signal stage directly on existing disasm output.
	if *from != "" {
		result, err := pipeline.RunSignalStage(*from, *k, quiet, os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\n%d signal, %d context, %d edges\n",
			result.SignalCount, result.ContextCount, result.EdgeCount)
		return nil
	}

	// Otherwise, run full pipeline first then signal stage.
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: disunity signal <libil2cpp.so> <global-metadata.dat>\n       disunity signal --from <disasm-dir>")
	}

	libPath := fs.Arg(0)
	metaPath := fs.Arg(1)

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	// Run extraction + disasm pipeline.
	pipeResult, err := pipeline.Run(pipeline.Opts{
		LibPath:  libPath,
		MetaPath: metaPath,
		OutDir:   *outDir,
		Quiet:    quiet,
		Log:      os.Stderr,
	})
	if err != nil {
		return err
	}
	for _, d := range pipeResult.Diags {
		fmt.Fprintf(os.Stderr, "  warning: %s\n", d)
	}

	// Run signal stage on the pipeline output.
	result, err := pipeline.RunSignalStage(*outDir, *k, quiet, os.Stderr)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%d signal, %d context, %d edges\n",
		result.SignalCount, result.ContextCount, result.EdgeCount)
	return nil
}
