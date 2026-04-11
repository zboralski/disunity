package main

import (
	"flag"
	"fmt"
	"os"

	"disunity/internal/binary"
	"disunity/internal/metadata"
)

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 2 {
		return fmt.Errorf("usage: disunity doctor <libil2cpp.so> <global-metadata.dat>")
	}

	libPath := fs.Arg(0)
	metaPath := fs.Arg(1)

	// Check metadata
	fmt.Fprintf(os.Stderr, "metadata %s\n", metaPath)
	meta, err := metadata.ParseFile(metaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FAIL: %v\n", err)
		return err
	}
	fmt.Fprintf(os.Stderr, "  OK: version %d, %d types, %d methods, %d images\n",
		meta.Header.Version, len(meta.TypeDefinitions), len(meta.MethodDefinitions), len(meta.ImageDefinitions))

	// Check binary
	fmt.Fprintf(os.Stderr, "\nbinary %s\n", libPath)
	analyzer, err := binary.NewIL2CPPStaticAnalyzer(
		libPath, float64(meta.Header.Version),
		len(meta.ImageDefinitions), len(meta.TypeDefinitions),
		len(meta.MethodDefinitions),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FAIL: %v\n", err)
		return err
	}
	defer analyzer.Close()

	codeRegVA, err := analyzer.FindCodeRegistration()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  CodeRegistration: FAIL: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  CodeRegistration: 0x%X\n", codeRegVA)

		modules, err := analyzer.ReadCodeGenModules(codeRegVA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  CodeGenModules: FAIL: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "  CodeGenModules: %d assemblies\n", len(modules))
			for _, m := range modules {
				fmt.Fprintf(os.Stderr, "    %s: %d methods\n", m.Name, len(m.MethodPointers))
			}
		}
	}

	metaRegVA, err := analyzer.FindMetadataRegistration()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  MetadataRegistration: FAIL: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  MetadataRegistration: 0x%X\n", metaRegVA)

		types, err := analyzer.ReadTypes(metaRegVA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  types: FAIL: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "  types: %d\n", len(types))
		}
	}

	fmt.Fprintf(os.Stderr, "\ndiagnostics complete\n")
	return nil
}
