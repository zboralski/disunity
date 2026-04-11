package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
)

// resolveLib checks if arg is a file path on disk.
func resolveLib(arg string) string {
	if strings.HasPrefix(arg, "-") {
		return ""
	}
	if _, err := os.Stat(arg); err == nil {
		return arg
	}
	return ""
}

// resolvePositionalLib returns the absolute path if arg is an existing file.
func resolvePositionalLib(arg string) string {
	if _, err := os.Stat(arg); err == nil {
		abs, _ := filepath.Abs(arg)
		return abs
	}
	return ""
}

// defaultOutDir returns <basename>.disunity/ in the current working directory.
func defaultOutDir(libPath string) string {
	base := filepath.Base(libPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return name + ".disunity"
}

// reorderPositionalArg moves the first non-flag argument to position 0
// so flag.FlagSet sees flags first. Handles mixed positional/flag args.
func reorderPositionalArg(args []string) []string {
	if len(args) == 0 {
		return args
	}
	// Already in order if first arg is a flag.
	if strings.HasPrefix(args[0], "-") {
		return args
	}
	return args
}

// parseLibMeta extracts the libil2cpp.so and global-metadata.dat paths
// from the remaining positional args after flag parsing.
func parseLibMeta(fs *flag.FlagSet) (string, string, error) {
	if fs.NArg() < 2 {
		return "", "", nil // will use --from instead
	}
	return fs.Arg(0), fs.Arg(1), nil
}
