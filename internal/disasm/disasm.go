// Package disasm provides ARM64 disassembly for IL2CPP code regions.
package disasm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// Inst is a decoded ARM64 instruction with address and raw bytes.
type Inst struct {
	Addr     uint64
	Raw      uint32
	Size     int // always 4 for ARM64
	Mnemonic string
	Operands string
	Text     string // full disassembly line
}

// SymbolLookup resolves an address to a symbolic name. Returns ("", false) if unknown.
type SymbolLookup func(addr uint64) (name string, ok bool)

// Annotator produces an inline comment for an instruction. Returns "" if none.
type Annotator func(inst Inst) string

// Options controls disassembly behavior.
type Options struct {
	BaseAddr uint64       // VA of the first byte in Data
	MaxSteps int          // maximum instructions to decode; 0 = 10M
	Symbols  SymbolLookup // optional symbol resolver
}

const defaultMaxSteps = 10_000_000

func (o Options) effectiveMax() int {
	if o.MaxSteps > 0 {
		return o.MaxSteps
	}
	return defaultMaxSteps
}

// Disassemble decodes ARM64 instructions from a byte region.
func Disassemble(data []byte, opts Options) []Inst {
	maxSteps := opts.effectiveMax()
	n := len(data) / 4
	if n > maxSteps {
		n = maxSteps
	}

	result := make([]Inst, 0, n)
	for i := 0; i < n; i++ {
		off := i * 4
		if off+4 > len(data) {
			break
		}
		raw := binary.LittleEndian.Uint32(data[off : off+4])
		addr := opts.BaseAddr + uint64(off)

		inst, err := arm64asm.Decode(data[off : off+4])
		var mnemonic, operands, text string
		if err != nil {
			mnemonic = ".word"
			operands = fmt.Sprintf("0x%08x", raw)
			text = fmt.Sprintf(".word 0x%08x", raw)
		} else {
			text = inst.String()
			parts := strings.SplitN(text, " ", 2)
			mnemonic = parts[0]
			if len(parts) > 1 {
				operands = parts[1]
			}
		}

		result = append(result, Inst{
			Addr:     addr,
			Raw:      raw,
			Size:     4,
			Mnemonic: mnemonic,
			Operands: operands,
			Text:     text,
		})
	}
	return result
}

// Format renders decoded instructions as text.
// Each line: <addr>  <hex bytes>  <disasm>  ; <comment>
func Format(insts []Inst, lookup SymbolLookup, annotators ...Annotator) string {
	var b strings.Builder
	for _, inst := range insts {
		fmt.Fprintf(&b, "0x%08x  ", inst.Addr)
		fmt.Fprintf(&b, "%02x %02x %02x %02x  ",
			byte(inst.Raw), byte(inst.Raw>>8), byte(inst.Raw>>16), byte(inst.Raw>>24))
		b.WriteString(inst.Text)

		// Symbol or annotation comment.
		var comment string
		if lookup != nil {
			if isBL(inst.Raw) {
				target := blTarget(inst.Raw, inst.Addr)
				if name, ok := lookup(target); ok {
					comment = name
				}
			} else if isB(inst.Raw) {
				// Unconditional B - tail call if target is a known function
				target := bTarget(inst.Raw, inst.Addr)
				if name, ok := lookup(target); ok {
					comment = "-> " + name
				}
			}
		}
		if comment == "" {
			for _, ann := range annotators {
				if s := ann(inst); s != "" {
					comment = s
					break
				}
			}
		}
		if comment != "" {
			b.WriteString("  ; ")
			b.WriteString(comment)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// FormatFunction renders a function with a header banner followed by assembly.
func FormatFunction(name, owner string, addr uint64, size int,
	insts []Inst, lookup SymbolLookup, annotators ...Annotator) string {

	var b strings.Builder
	fmt.Fprintf(&b, "; %s\n", name)
	if owner != "" {
		fmt.Fprintf(&b, "; Owner: %s\n", owner)
	}
	fmt.Fprintf(&b, "; Address: 0x%X, Size: 0x%X\n;\n", addr, size)
	b.WriteString(Format(insts, lookup, annotators...))
	return b.String()
}

// PlaceholderLookup creates a SymbolLookup from a map.
func PlaceholderLookup(m map[uint64]string) SymbolLookup {
	return func(addr uint64) (string, bool) {
		s, ok := m[addr]
		return s, ok
	}
}

// isB returns true if the instruction is unconditional B (not BL).
func isB(raw uint32) bool {
	return raw&0xFC000000 == 0x14000000
}

// bTarget computes the absolute target of an unconditional B instruction.
func bTarget(raw uint32, pc uint64) uint64 {
	imm26 := raw & 0x03FFFFFF
	offset := signExtend(imm26, 26) * 4
	return uint64(int64(pc) + int64(offset))
}
