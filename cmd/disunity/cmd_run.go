package main

import (
	"flag"
	"fmt"
	"os"

	"disunity/internal/pipeline"
)

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("disunity", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory")
	quiet := false
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	fast := fs.Bool("fast", false, "skip disasm and meta stages (extraction only)")
	all := fs.Bool("all", false, "include all functions (not just signal)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 2 {
		return fmt.Errorf("usage: disunity <libil2cpp.so> <global-metadata.dat>")
	}

	libPath := fs.Arg(0)
	metaPath := fs.Arg(1)

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	result, err := pipeline.Run(pipeline.Opts{
		LibPath:    libPath,
		MetaPath:   metaPath,
		OutDir:     *outDir,
		Quiet:      quiet,
		All:        *all,
		SkipDisasm: *fast,
		Log:        os.Stderr,
	})
	if err != nil {
		return err
	}

	for _, d := range result.Diags {
		fmt.Fprintf(os.Stderr, "  warning: %s\n", d)
	}

	return nil
}
