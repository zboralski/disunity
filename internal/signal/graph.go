package signal

import (
	"sort"
	"strings"
)

// InputFunc is a function record for signal graph construction.
type InputFunc struct {
	PC    string
	Size  int
	Name  string
	Owner string
}

// InputEdge is a call edge record for signal graph construction.
type InputEdge struct {
	FromFunc string
	Kind     string
	Target   string
}

// InputStringRef is a string reference record for signal graph construction.
type InputStringRef struct {
	Func  string
	PC    string
	Value string
}

// ClassifiedStringRef is a string reference with its signal categories.
type ClassifiedStringRef struct {
	Func       string   `json:"func"`
	PC         string   `json:"pc"`
	Value      string   `json:"value"`
	Categories []string `json:"categories,omitempty"`
}

// SignalFunc is a function in the signal graph.
type SignalFunc struct {
	Name         string                `json:"name"`
	Owner        string                `json:"owner,omitempty"`
	PC           string                `json:"pc"`
	Size         int                   `json:"size"`
	StringRefs   []ClassifiedStringRef `json:"string_refs,omitempty"`
	Categories   []string              `json:"categories"`
	Severity     string                `json:"severity"` // "high", "medium", "low"
	Role         string                `json:"role"`     // "signal", "context", ""
	IsEntryPoint bool                  `json:"is_entry_point,omitempty"`
}

// SignalEdge is an edge in the signal graph.
type SignalEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // "bl", "blr"
}

// SignalGraph is the complete signal graph.
type SignalGraph struct {
	Funcs          []SignalFunc         `json:"funcs"`
	Edges          []SignalEdge         `json:"edges"`
	StringLiterals []ClassifiedStringRef `json:"string_literals,omitempty"`
	Stats          SignalStats          `json:"stats"`
}

// SignalStats holds summary statistics.
type SignalStats struct {
	TotalFuncs     int            `json:"total_funcs"`
	SignalFuncs    int            `json:"signal_funcs"`
	ContextFuncs   int            `json:"context_funcs"`
	TotalEdges     int            `json:"total_edges"`
	StringRefCount int            `json:"string_ref_count"`
	Categories     map[string]int `json:"categories"`
}

// BuildSignalGraph constructs a signal graph from disasm artifacts.
// k = number of context hops from each signal function.
// entryPoints is the set of functions with no incoming BL edges (may be nil).
func BuildSignalGraph(
	funcs []InputFunc,
	edges []InputEdge,
	stringRefs []InputStringRef,
	k int,
	entryPoints map[string]bool,
) *SignalGraph {
	// Index functions by name.
	funcByName := make(map[string]*InputFunc, len(funcs))
	for i := range funcs {
		funcByName[funcs[i].Name] = &funcs[i]
	}

	// Group string refs by function and classify each string.
	type funcSignal struct {
		refs       []ClassifiedStringRef
		categories map[string]bool
	}
	funcSignals := make(map[string]*funcSignal)
	catCounts := make(map[string]int)

	for _, sr := range stringRefs {
		cats := ClassifyString(sr.Value)
		if len(cats) == 0 {
			continue
		}
		fs, ok := funcSignals[sr.Func]
		if !ok {
			fs = &funcSignal{categories: make(map[string]bool)}
			funcSignals[sr.Func] = fs
		}
		csr := ClassifiedStringRef{
			Func:       sr.Func,
			PC:         sr.PC,
			Value:      sr.Value,
			Categories: cats,
		}
		fs.refs = append(fs.refs, csr)
		for _, c := range cats {
			if !fs.categories[c] {
				fs.categories[c] = true
				catCounts[c]++
			}
		}
	}

	// IL2CPP-specific: classify function names themselves.
	// Unlike Dart AOT, IL2CPP preserves full C# method names like
	// AES$$Encrypt, HttpClient$$SendRequest, etc.
	// Skip framework namespaces - they implement crypto/net/etc. but are
	// standard library, not app-specific behavior.
	for _, f := range funcs {
		if f.Name == "" {
			continue
		}
		if IsFrameworkNamespace(f.Name) {
			continue
		}
		cats := ClassifyString(f.Name)
		if len(cats) == 0 {
			continue
		}
		fs, ok := funcSignals[f.Name]
		if !ok {
			fs = &funcSignal{categories: make(map[string]bool)}
			funcSignals[f.Name] = fs
		}
		for _, c := range cats {
			if !fs.categories[c] {
				fs.categories[c] = true
				catCounts[c]++
			}
		}
	}

	// Filter out mundane runtime functions from signal set.
	for name := range funcSignals {
		if IsMundaneRuntime(name) {
			delete(funcSignals, name)
		}
	}

	// Signal function set.
	signalSet := make(map[string]bool, len(funcSignals))
	for name := range funcSignals {
		signalSet[name] = true
	}

	// Build bidirectional adjacency for BFS context expansion.
	fwd := make(map[string][]string) // caller → callees
	rev := make(map[string][]string) // callee → callers
	for _, e := range edges {
		if e.Kind == "bl" && e.Target != "" {
			fwd[e.FromFunc] = append(fwd[e.FromFunc], e.Target)
			rev[e.Target] = append(rev[e.Target], e.FromFunc)
		}
	}

	// BFS k hops from signal functions (bidirectional).
	// Skip framework namespaces during expansion to avoid pulling in the
	// entire standard library through common functions like String$$Concat.
	contextSet := make(map[string]bool)
	visited := make(map[string]bool)
	type queueItem struct {
		name  string
		depth int
	}
	var queue []queueItem
	for name := range signalSet {
		visited[name] = true
		queue = append(queue, queueItem{name, 0})
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if item.depth >= k {
			continue
		}
		for _, next := range fwd[item.name] {
			if !visited[next] && !IsFrameworkNamespace(next) && !IsMundaneRuntime(next) {
				visited[next] = true
				contextSet[next] = true
				queue = append(queue, queueItem{next, item.depth + 1})
			}
		}
		for _, prev := range rev[item.name] {
			if !visited[prev] && !IsFrameworkNamespace(prev) && !IsMundaneRuntime(prev) {
				visited[prev] = true
				contextSet[prev] = true
				queue = append(queue, queueItem{prev, item.depth + 1})
			}
		}
	}

	// Build funcs with role annotations.
	var allFuncs []SignalFunc
	for _, f := range funcs {
		sf := SignalFunc{
			Name:         f.Name,
			Owner:        f.Owner,
			PC:           f.PC,
			Size:         f.Size,
			IsEntryPoint: entryPoints[f.Name],
		}
		if signalSet[f.Name] {
			sf.Role = "signal"
		} else if contextSet[f.Name] {
			sf.Role = "context"
		}
		if fs, ok := funcSignals[f.Name]; ok {
			sf.StringRefs = fs.refs
			for c := range fs.categories {
				sf.Categories = append(sf.Categories, c)
			}
			sort.Strings(sf.Categories)
			sf.Severity = MaxSeverity(sf.Categories)
		}
		allFuncs = append(allFuncs, sf)
	}

	// Sort: signal → context → other.
	roleOrd := map[string]int{"signal": 0, "context": 1, "": 2}
	sevOrd := map[string]int{"high": 0, "medium": 1, "low": 2, "": 3}
	sort.Slice(allFuncs, func(i, j int) bool {
		si, sj := &allFuncs[i], &allFuncs[j]
		if si.Role != sj.Role {
			return roleOrd[si.Role] < roleOrd[sj.Role]
		}
		if si.Role == "signal" && si.IsEntryPoint != sj.IsEntryPoint {
			return si.IsEntryPoint
		}
		if si.Severity != sj.Severity {
			return sevOrd[si.Severity] < sevOrd[sj.Severity]
		}
		if len(si.Categories) != len(sj.Categories) {
			return len(si.Categories) > len(sj.Categories)
		}
		return si.Name < sj.Name
	})

	// Include all BL edges (deduped).
	var allEdges []SignalEdge
	seen := make(map[string]bool)
	for _, e := range edges {
		if e.Kind == "bl" {
			if e.Target == "" {
				continue
			}
		} else {
			continue // skip BLR and other edge types
		}

		key := e.FromFunc + "|" + e.Target + "|" + e.Kind
		if seen[key] {
			continue
		}
		seen[key] = true
		allEdges = append(allEdges, SignalEdge{From: e.FromFunc, To: e.Target, Kind: e.Kind})
	}

	// Filter to only include edges involving signal/context funcs.
	relevantFuncs := make(map[string]bool)
	for _, f := range allFuncs {
		if f.Role != "" {
			relevantFuncs[f.Name] = true
		}
	}
	var filteredEdges []SignalEdge
	for _, e := range allEdges {
		if relevantFuncs[e.From] || relevantFuncs[e.To] {
			filteredEdges = append(filteredEdges, e)
		}
	}

	// Filter funcs to only signal + context (drop unrelated).
	var filteredFuncs []SignalFunc
	for _, f := range allFuncs {
		if f.Role != "" {
			filteredFuncs = append(filteredFuncs, f)
		}
	}

	return &SignalGraph{
		Funcs: filteredFuncs,
		Edges: filteredEdges,
		Stats: SignalStats{
			TotalFuncs:     len(funcs),
			SignalFuncs:    len(signalSet),
			ContextFuncs:   len(contextSet),
			TotalEdges:     len(filteredEdges),
			StringRefCount: len(stringRefs),
			Categories:     catCounts,
		},
	}
}

// SplitMethodName splits "Namespace.Class$$Method" into (owner, method).
func SplitMethodName(fullName string) (string, string) {
	idx := strings.LastIndex(fullName, "$$")
	if idx < 0 {
		return "", fullName
	}
	return fullName[:idx], fullName[idx+2:]
}
