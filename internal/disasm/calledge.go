package disasm

import "fmt"

// CallEdge represents a call site extracted from disassembly.
type CallEdge struct {
	FromFunc string // caller function name
	FromPC   uint64 // call site address
	Kind     string // "bl" or "blr"
	Target   string // resolved target name or hex address
	Reg      string // register name for BLR (e.g. "X16")
	Via      string // provenance annotation
}

// ExtractCallEdges finds BL and BLR call sites in decoded instructions.
func ExtractCallEdges(insts []Inst, funcName string, lookup SymbolLookup) []CallEdge {
	var edges []CallEdge

	for _, inst := range insts {
		if isBL(inst.Raw) {
			target := blTarget(inst.Raw, inst.Addr)
			name := fmt.Sprintf("0x%X", target)
			if lookup != nil {
				if resolved, ok := lookup(target); ok {
					name = resolved
				}
			}
			edges = append(edges, CallEdge{
				FromFunc: funcName,
				FromPC:   inst.Addr,
				Kind:     "bl",
				Target:   name,
			})
		} else if isBLR(inst.Raw) {
			reg := blrReg(inst.Raw)
			edges = append(edges, CallEdge{
				FromFunc: funcName,
				FromPC:   inst.Addr,
				Kind:     "blr",
				Reg:      fmt.Sprintf("X%d", reg),
			})
		}
	}
	return edges
}
