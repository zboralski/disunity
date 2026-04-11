package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"disunity/internal/cli"
	"disunity/internal/render"
	"disunity/internal/signal"
)

// SignalResult holds summary stats from the signal stage.
type SignalResult struct {
	SignalCount  int
	ContextCount int
	EdgeCount    int
}

// RunSignalStage runs the signal analysis on existing disasm output.
func RunSignalStage(inDir string, k int, quiet bool, log io.Writer) (*SignalResult, error) {
	if log == nil {
		log = os.Stderr
	}
	logf := func(format string, args ...interface{}) {
		if !quiet {
			fmt.Fprintf(log, format, args...)
		}
	}
	stagef := func(name string, format string, args ...interface{}) {
		if !quiet {
			detail := fmt.Sprintf(format, args...)
			fmt.Fprintf(log, "\n%s%s%s %s\n", cli.Pink, name, cli.Reset, detail)
		}
	}

	// Read functions.jsonl.
	funcs, err := ReadJSONL[FuncRecord](filepath.Join(inDir, "functions.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read functions.jsonl: %w", err)
	}

	// Read call_edges.jsonl.
	edges, err := ReadJSONL[CallEdgeRecord](filepath.Join(inDir, "call_edges.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read call_edges.jsonl: %w", err)
	}

	// Read string_refs.jsonl.
	stringRefs, err := ReadJSONL[StringRefRecord](filepath.Join(inDir, "string_refs.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read string_refs.jsonl: %w", err)
	}

	// Compute entry points.
	entryList := findEntryPoints(funcs, edges)
	entrySet := make(map[string]bool, len(entryList))
	for _, ep := range entryList {
		entrySet[ep] = true
	}

	// Convert pipeline types to signal input types.
	sigFuncs := make([]signal.InputFunc, len(funcs))
	for i, f := range funcs {
		sigFuncs[i] = signal.InputFunc{PC: f.PC, Size: f.Size, Name: f.Name, Owner: f.Owner}
	}
	sigEdges := make([]signal.InputEdge, len(edges))
	for i, e := range edges {
		sigEdges[i] = signal.InputEdge{FromFunc: e.FromFunc, Kind: e.Kind, Target: e.Target}
	}
	sigRefs := make([]signal.InputStringRef, len(stringRefs))
	for i, sr := range stringRefs {
		sigRefs[i] = signal.InputStringRef{Func: sr.Func, PC: sr.PC, Value: sr.Value}
	}

	// Build signal graph.
	g := signal.BuildSignalGraph(sigFuncs, sigEdges, sigRefs, k, entrySet)

	// Read and classify metadata string literals.
	slPath := filepath.Join(inDir, "string_literals.jsonl")
	if rawStrings, err := ReadJSONL[string](slPath); err == nil && len(rawStrings) > 0 {
		for _, s := range rawStrings {
			cats := signal.ClassifyString(s)
			if len(cats) == 0 {
				continue
			}
			g.StringLiterals = append(g.StringLiterals, signal.ClassifiedStringRef{
				Value:      s,
				Categories: cats,
			})
		}
		g.Stats.StringRefCount += len(g.StringLiterals)
		logf("  %sstring literals:%s %d classified / %d total\n",
			cli.Muted, cli.Reset, len(g.StringLiterals), len(rawStrings))
	}

	stagef("signal", "%s%d%s signal + %s%d%s context, %s%d%s edges",
		cli.Gold, g.Stats.SignalFuncs, cli.Reset,
		cli.Gold, g.Stats.ContextFuncs, cli.Reset,
		cli.Gold, g.Stats.TotalEdges, cli.Reset)
	for cat, count := range g.Stats.Categories {
		logf("  %s%s:%s %d\n", cli.Muted, cat, cli.Reset, count)
	}

	// Load asm snippets.
	const contextAsmLines = 30
	asmSnippets := make(map[string]string)
	asmDir := filepath.Join(inDir, "asm")
	for _, sf := range g.Funcs {
		if sf.Role == "" {
			continue
		}
		ownerDir := ownerToPath(sf.Owner)
		path := filepath.Join(asmDir, ownerDir, sanitizePathComponent(sf.Name)+".txt")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s := strings.TrimRight(string(data), "\n")
		if sf.Role == "context" {
			lines := strings.SplitN(s, "\n", contextAsmLines+1)
			if len(lines) > contextAsmLines {
				s = strings.Join(lines[:contextAsmLines], "\n") + "\n[... truncated]"
			}
		}
		asmSnippets[sf.Name] = s
	}
	logf("  %sasm snippets:%s %d\n", cli.Muted, cli.Reset, len(asmSnippets))

	// Write signal_graph.json.
	outPath := filepath.Join(inDir, "signal.html")
	jsonPath := filepath.Join(inDir, "signal_graph.json")
	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("create signal_graph.json: %w", err)
	}
	enc := json.NewEncoder(jsonFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		jsonFile.Close()
		return nil, fmt.Errorf("write signal_graph.json: %w", err)
	}
	jsonFile.Close()
	fi, _ := os.Stat(jsonPath)
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, jsonPath, cli.Reset, fi.Size())

	// Write signal.html.
	htmlFile, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("create signal.html: %w", err)
	}
	title := "disunity"
	digest := filepath.Base(filepath.Dir(inDir))
	filename := inDir
	if metaBytes, err := os.ReadFile(filepath.Join(filepath.Dir(inDir), "meta.json")); err == nil {
		var meta struct {
			Hash   string `json:"hash"`
			Source string `json:"source"`
		}
		if json.Unmarshal(metaBytes, &meta) == nil {
			if meta.Hash != "" {
				digest = meta.Hash
			}
			if meta.Source != "" {
				filename = filepath.Base(meta.Source)
			}
		}
	}
	render.WriteSignalHTML(htmlFile, g, title, filename, digest, asmSnippets)
	if err := htmlFile.Close(); err != nil {
		return nil, fmt.Errorf("close signal.html: %w", err)
	}
	fi, _ = os.Stat(outPath)
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, outPath, cli.Reset, fi.Size())

	// Write signal.dot.
	dotPath := filepath.Join(inDir, "signal.dot")
	dotContent := render.SignalDOT(g, title, render.NASA)
	if err := os.WriteFile(dotPath, []byte(dotContent), 0644); err != nil {
		return nil, fmt.Errorf("write signal.dot: %w", err)
	}
	fi, _ = os.Stat(dotPath)
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, dotPath, cli.Reset, fi.Size())

	// Build connected signal CFG.
	cfgContent := buildSignalContent(g, inDir)
	if len(cfgContent) > 0 {
		cfgTitle := "disunity signal CFG"
		cfgDOT := render.SignalCFGDOT(g, cfgContent, cfgTitle, render.NASA)
		cfgPath := filepath.Join(inDir, "signal_cfg.dot")
		if err := os.WriteFile(cfgPath, []byte(cfgDOT), 0644); err != nil {
			return nil, fmt.Errorf("write signal_cfg.dot: %w", err)
		}
		fi, _ = os.Stat(cfgPath)
		logf("  %s->%s %s%s%s (%d functions, %d bytes)\n",
			cli.Muted, cli.Reset, cli.Blue, cfgPath, cli.Reset, len(cfgContent), fi.Size())
	}

	// Render SVG via dot if available.
	const dotTimeout = 120 * time.Second
	const largeDOTThreshold = 1 << 20 // 1 MB
	dotBin, err := exec.LookPath("dot")
	if err != nil {
		logf("  %s!%s dot not found, install Graphviz for SVG: %sbrew install graphviz%s\n",
			cli.Red, cli.Reset, cli.Gold, cli.Reset)
	} else {
		dotFiles := []string{dotPath}
		cfgDotPath := filepath.Join(inDir, "signal_cfg.dot")
		if _, statErr := os.Stat(cfgDotPath); statErr == nil {
			dotFiles = append(dotFiles, cfgDotPath)
		}
		for _, df := range dotFiles {
			svgPath := strings.TrimSuffix(df, ".dot") + ".svg"
			dfi, _ := os.Stat(df)
			if dfi != nil && dfi.Size() > largeDOTThreshold {
				logf("  %s!%s skipping SVG for %s (%d KB), too large for dot\n",
					cli.Red, cli.Reset, filepath.Base(df), dfi.Size()/1024)
				logf("    render manually: %ssfdp -Tsvg -o %s %s%s\n",
					cli.Muted, filepath.Base(svgPath), filepath.Base(df), cli.Reset)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), dotTimeout)
			cmd := exec.CommandContext(ctx, dotBin, "-Tsvg", "-o", svgPath, df)
			out, err := cmd.CombinedOutput()
			cancel()
			if ctx.Err() == context.DeadlineExceeded {
				logf("  %s!%s dot timed out after %v for %s\n",
					cli.Red, cli.Reset, dotTimeout, filepath.Base(df))
				logf("    render manually: %ssfdp -Tsvg -o %s %s%s\n",
					cli.Muted, filepath.Base(svgPath), filepath.Base(df), cli.Reset)
			} else if err != nil {
				logf("  %s!%s dot render failed for %s: %v\n%s\n", cli.Red, cli.Reset, filepath.Base(df), err, out)
			} else {
				fi, _ = os.Stat(svgPath)
				logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, svgPath, cli.Reset, fi.Size())
			}
		}
	}

	return &SignalResult{
		SignalCount:  g.Stats.SignalFuncs,
		ContextCount: g.Stats.ContextFuncs,
		EdgeCount:    g.Stats.TotalEdges,
	}, nil
}

// buildSignalContent extracts interesting calls and string refs for each signal function
// from the signal graph edges and string refs (no re-disassembly needed).
func buildSignalContent(
	g *signal.SignalGraph,
	inDir string,
) map[string]*render.SignalFuncContent {
	// Build callee list from edges.
	calleesByFunc := make(map[string][]string)
	for _, e := range g.Edges {
		if e.Kind == "bl" && e.To != "" {
			calleesByFunc[e.From] = append(calleesByFunc[e.From], e.To)
		}
	}

	result := make(map[string]*render.SignalFuncContent)

	for _, sf := range g.Funcs {
		if sf.Role != "signal" {
			continue
		}

		// Deduplicate callees, filter to interesting ones.
		seenCalls := make(map[string]bool)
		var calls []string
		for _, callee := range calleesByFunc[sf.Name] {
			if seenCalls[callee] {
				continue
			}
			seenCalls[callee] = true
			if isInterestingCallee(callee) {
				calls = append(calls, callee)
			}
		}

		// Collect classified string refs.
		seenStrs := make(map[string]bool)
		var strs []render.ClassifiedString
		for _, sr := range sf.StringRefs {
			if seenStrs[sr.Value] {
				continue
			}
			seenStrs[sr.Value] = true
			cat := ""
			if len(sr.Categories) > 0 {
				cat = sr.Categories[0]
			}
			strs = append(strs, render.ClassifiedString{Value: sr.Value, Category: cat})
		}

		if len(calls) > 0 || len(strs) > 0 {
			result[sf.Name] = &render.SignalFuncContent{
				Calls:   calls,
				Strings: strs,
			}
		}
	}

	return result
}

// isInterestingCallee filters out mundane runtime callees from CFG content.
func isInterestingCallee(name string) bool {
	if name == "" {
		return false
	}
	if signal.IsMundaneRuntime(name) {
		return false
	}
	if strings.HasPrefix(name, "sub_") {
		return false
	}
	return true
}

// findEntryPoints returns functions that have no incoming BL edges.
func findEntryPoints(funcs []FuncRecord, edges []CallEdgeRecord) []string {
	blTargets := make(map[string]bool)
	for _, e := range edges {
		if e.Kind == "bl" && e.Target != "" {
			blTargets[e.Target] = true
		}
	}

	var entries []string
	for _, f := range funcs {
		if strings.HasPrefix(f.Name, "sub_") {
			continue
		}
		if !blTargets[f.Name] {
			entries = append(entries, f.Name)
		}
	}
	sort.Strings(entries)
	return entries
}
