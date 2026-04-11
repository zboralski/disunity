package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// Find the first non-flag argument to determine the command.
	// This allows flags to appear before or after the subcommand.
	cmd := ""
	cmdIdx := 0
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--" {
			break
		}
		if len(arg) > 0 && arg[0] == '-' {
			// Skip flag values (e.g., --out dir)
			if arg == "--out" || arg == "--from" || arg == "--k" {
				i++ // skip the value
			}
			continue
		}
		cmd = arg
		cmdIdx = i
		break
	}

	if cmd == "" {
		// Check for help flags
		for _, a := range os.Args[1:] {
			if a == "-h" || a == "--help" || a == "help" {
				usage()
				os.Exit(0)
			}
		}
		usage()
		os.Exit(1)
	}

	var err error

	switch cmd {
	case "meta":
		err = cmdMeta(withoutCmd(cmdIdx))
	case "ghidra":
		err = cmdGhidra(withoutCmd(cmdIdx))
	case "ida":
		err = cmdIDA(withoutCmd(cmdIdx))
	case "signal":
		err = cmdSignal(withoutCmd(cmdIdx))
	case "doctor":
		err = cmdDoctor(withoutCmd(cmdIdx))

	case "help":
		usage()
		os.Exit(0)

	default:
		// If first non-flag arg is a file, run full pipeline with all args.
		if resolveLib(cmd) != "" {
			err = cmdRun(os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
			usage()
			os.Exit(1)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// withoutCmd returns os.Args with the subcommand at index i removed,
// preserving all flags and other positional arguments.
func withoutCmd(i int) []string {
	result := make([]string, 0, len(os.Args)-2)
	result = append(result, os.Args[1:i]...)
	result = append(result, os.Args[i+1:]...)
	return result
}

func usage() {
	fmt.Fprintf(os.Stderr, `disunity: static IL2CPP metadata extractor

Usage:
  disunity <libil2cpp.so> <global-metadata.dat>    Full analysis pipeline
  disunity meta <lib> <meta>                        Generate unity_meta.json
  disunity ghidra <lib> <meta>                      Ghidra headless decompilation
  disunity ida <lib> <meta>                         IDA headless decompilation
  disunity signal <lib> <meta>                      Signal analysis
  disunity doctor <lib> <meta>                      Diagnostic scan

Flags:
  --out <dir>         Output directory (default: ./<basename>.disunity/)
  --quiet, -q         Suppress verbose output
  --all               Include all functions (not just signal)
  --from <dir>        Reuse existing disasm output
  --k <n>             Signal context hops (default: 2)
`)
}
