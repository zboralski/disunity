package pipeline

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"disunity/internal/disasm"
	"disunity/internal/output"
)

// FuncRecord describes a single function for JSONL output.
type FuncRecord struct {
	PC    string `json:"pc"`
	Size  int    `json:"size"`
	Name  string `json:"name"`
	Owner string `json:"owner,omitempty"`
	Image string `json:"image,omitempty"`
}

// CallEdgeRecord describes a call edge for JSONL output.
type CallEdgeRecord struct {
	FromFunc string `json:"from_func"`
	FromPC   string `json:"from_pc"`
	Kind     string `json:"kind"`
	Target   string `json:"target,omitempty"`
	Reg      string `json:"reg,omitempty"`
}

// StringRefRecord describes a string reference for JSONL output.
type StringRefRecord struct {
	Func  string `json:"func"`
	PC    string `json:"pc"`
	Value string `json:"value"`
}

// DisasmResult holds summary stats from the disassembly stage.
type DisasmResult struct {
	Written    int
	TotalEdges int
	TotalBL    int
	TotalBLR   int
}

// FuncEntry is a function with address, size, and metadata.
type FuncEntry struct {
	Addr  uint64
	Size  int
	Name  string
	Owner string
	Image string
}

// RunDisasmStage executes per-function disassembly using script.json and the ELF binary.
func RunDisasmStage(
	libPath string,
	sj *output.ScriptJSON,
	outDir string,
	quiet bool,
	log io.Writer,
) (*DisasmResult, error) {
	// Open ELF and find the executable section
	f, err := elf.Open(libPath)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	// Load all executable PROGBITS sections into a unified code map.
	// IL2CPP binaries typically have .text + an "il2cpp" section.
	var codeSections []codeSectionEntry
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Type == elf.SHT_PROGBITS && s.Size > 0 {
			data, err := s.Data()
			if err != nil {
				continue
			}
			codeSections = append(codeSections, codeSectionEntry{va: s.Addr, data: data})
		}
	}
	if len(codeSections) == 0 {
		return nil, fmt.Errorf("no executable sections found")
	}

	// Build function list from script.json using all code sections
	funcs := buildFuncListFromSections(sj, codeSections)

	// Build symbol lookup for BL/B/ADRP target resolution
	symbols := make(map[uint64]string, len(funcs))
	for _, fn := range funcs {
		symbols[fn.Addr] = fn.Name
	}
	lookup := disasm.PlaceholderLookup(symbols)
	tracker := disasm.NewAdrpTracker(lookup)

	// Create output directories
	asmDir := filepath.Join(outDir, "asm")
	if err := os.MkdirAll(asmDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir asm: %w", err)
	}

	// Open JSONL writers
	funcFile, err := os.Create(filepath.Join(outDir, "functions.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create functions.jsonl: %w", err)
	}
	defer funcFile.Close()
	funcEnc := json.NewEncoder(funcFile)

	edgeFile, err := os.Create(filepath.Join(outDir, "call_edges.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create call_edges.jsonl: %w", err)
	}
	defer edgeFile.Close()
	edgeEnc := json.NewEncoder(edgeFile)

	stringFile, err := os.Create(filepath.Join(outDir, "string_refs.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create string_refs.jsonl: %w", err)
	}
	defer stringFile.Close()
	stringEnc := json.NewEncoder(stringFile)

	result := &DisasmResult{}

	// Per-function disassembly
	for _, fn := range funcs {
		if fn.Size <= 0 {
			continue
		}

		// Extract code bytes for this function from the right section
		funcCode := findCodeBytes(codeSections, fn.Addr, fn.Size)
		if funcCode == nil {
			continue
		}

		// Disassemble
		insts := disasm.Disassemble(funcCode, disasm.Options{
			BaseAddr: fn.Addr,
			Symbols:  lookup,
		})

		// Format and write assembly file with header + annotations
		tracker.Reset()
		asmText := disasm.FormatFunction(fn.Name, fn.Owner, fn.Addr, fn.Size, insts, lookup, tracker.Annotate)
		ownerDir := ownerToPath(fn.Owner)
		funcDir := filepath.Join(asmDir, ownerDir)
		os.MkdirAll(funcDir, 0755)
		funcFileName := sanitizePathComponent(fn.Name) + ".txt"
		os.WriteFile(filepath.Join(funcDir, funcFileName), []byte(asmText), 0644)

		// Write function record
		funcEnc.Encode(FuncRecord{
			PC:    fmt.Sprintf("0x%X", fn.Addr),
			Size:  fn.Size,
			Name:  fn.Name,
			Owner: fn.Owner,
			Image: fn.Image,
		})

		// Extract and write call edges
		edges := disasm.ExtractCallEdges(insts, fn.Name, lookup)
		for _, e := range edges {
			edgeEnc.Encode(CallEdgeRecord{
				FromFunc: e.FromFunc,
				FromPC:   fmt.Sprintf("0x%X", e.FromPC),
				Kind:     e.Kind,
				Target:   e.Target,
				Reg:      e.Reg,
			})
			result.TotalEdges++
			if e.Kind == "bl" {
				result.TotalBL++
			} else {
				result.TotalBLR++
			}
		}

		// Extract string references from BL targets that resolve to string-like names
		for _, e := range edges {
			if e.Kind == "bl" && isStringRef(e.Target) {
				stringEnc.Encode(StringRefRecord{
					Func:  fn.Name,
					PC:    fmt.Sprintf("0x%X", e.FromPC),
					Value: e.Target,
				})
			}
		}

		result.Written++
	}

	return result, nil
}

// codeSection represents a loaded executable ELF section.
type codeSectionEntry struct {
	va   uint64
	data []byte
}

// buildFuncListFromSections creates a sorted function list from script.json,
// filtering to functions within any of the provided code sections.
func buildFuncListFromSections(sj *output.ScriptJSON, sections []codeSectionEntry) []FuncEntry {
	// Collect all functions that fall within any code section
	var entries []FuncEntry
	for _, entry := range sj.Methods {
		if !inAnySections(sections, entry.Address) {
			continue
		}

		owner, _ := splitMethodName(entry.FullName)

		entries = append(entries, FuncEntry{
			Addr:  entry.Address,
			Name:  entry.FullName,
			Owner: owner,
			Image: entry.Image,
		})
	}

	// Sort by address
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Addr < entries[j].Addr
	})

	// Compute sizes from address gaps
	for i := range entries {
		if i+1 < len(entries) {
			gap := int(entries[i+1].Addr - entries[i].Addr)
			if gap > 65536 {
				gap = 65536
			}
			entries[i].Size = gap
		} else {
			entries[i].Size = 256 // last function: conservative default
		}
	}

	return entries
}

// inAnySections checks if an address falls within any code section.
func inAnySections(sections []codeSectionEntry, addr uint64) bool {
	for _, s := range sections {
		end := s.va + uint64(len(s.data))
		if addr >= s.va && addr < end {
			return true
		}
	}
	return false
}

// findCodeBytes extracts code bytes for a function from the right section.
func findCodeBytes(sections []codeSectionEntry, addr uint64, size int) []byte {
	for _, s := range sections {
		end := s.va + uint64(len(s.data))
		if addr >= s.va && addr < end {
			off := addr - s.va
			endOff := off + uint64(size)
			if endOff > uint64(len(s.data)) {
				endOff = uint64(len(s.data))
			}
			if off >= endOff {
				return nil
			}
			return s.data[off:endOff]
		}
	}
	return nil
}

// splitMethodName splits "Namespace.Class$$Method" into (owner, method).
func splitMethodName(fullName string) (string, string) {
	idx := strings.LastIndex(fullName, "$$")
	if idx < 0 {
		return "", fullName
	}
	return fullName[:idx], fullName[idx+2:]
}

// sanitizePathComponent makes a string safe for use as a filename.
func sanitizePathComponent(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	result := b.String()
	if len(result) > 200 {
		result = result[:200]
	}
	return result
}

// ownerToPath converts a dotted C# owner like "System.Net.Http.HttpClient"
// to a hierarchical path "System/Net/Http/HttpClient". Each component is
// sanitized individually. Generic backtick suffixes are stripped.
func ownerToPath(owner string) string {
	if owner == "" {
		return "global"
	}
	parts := strings.Split(owner, ".")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		// Strip generic arity suffix: List`1 → List
		if idx := strings.Index(p, "`"); idx > 0 {
			p = p[:idx]
		}
		s := sanitizePathComponent(p)
		if s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if len(cleaned) == 0 {
		return "global"
	}
	return filepath.Join(cleaned...)
}

// isStringRef checks if a resolved call target looks like a string literal.
func isStringRef(target string) bool {
	return strings.Contains(target, "\"") || strings.HasPrefix(target, "String$$")
}
