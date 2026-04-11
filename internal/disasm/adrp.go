package disasm

import "fmt"

// AdrpTracker resolves ADRP+ADD and ADRP+LDR instruction pairs to
// symbolic names. ARM64 uses ADRP to load a page-aligned base into a
// register, then ADD/LDR to apply the page offset. This tracker records
// pending ADRP bases per register and annotates the resolving instruction.
type AdrpTracker struct {
	pending [32]uint64
	set     [32]bool
	lookup  SymbolLookup
}

// NewAdrpTracker creates a tracker that resolves addresses via lookup.
func NewAdrpTracker(lookup SymbolLookup) *AdrpTracker {
	return &AdrpTracker{lookup: lookup}
}

// Reset clears all pending ADRP state (call between functions).
func (t *AdrpTracker) Reset() {
	t.set = [32]bool{}
}

// Annotate implements Annotator. It tracks ADRP instructions and resolves
// ADRP+ADD / ADRP+LDR pairs to symbolic names.
func (t *AdrpTracker) Annotate(inst Inst) string {
	raw := inst.Raw

	// ADRP Xd, #imm - record page base
	if isADRP(raw) {
		rd := int(raw & 0x1F)
		t.pending[rd] = adrpTarget(raw, inst.Addr)
		t.set[rd] = true
		return ""
	}

	// ADD Xd, Xn, #imm12{, lsl #12}
	if isADDImm(raw) {
		rn := int((raw >> 5) & 0x1F)
		if t.set[rn] {
			offset := addImmValue(raw)
			addr := t.pending[rn] + offset
			rd := int(raw & 0x1F)
			// Propagate: ADD result becomes new base for this register
			t.pending[rd] = addr
			t.set[rd] = true
			return t.resolve(addr)
		}
		return ""
	}

	// LDR/LDRB/LDRH/LDRSW (unsigned immediate) - [Xn, #imm]
	if isLDRUnsigned(raw) {
		rn := int((raw >> 5) & 0x1F)
		if t.set[rn] {
			offset := ldrUnsignedOffset(raw)
			addr := t.pending[rn] + offset
			return t.resolve(addr)
		}
		return ""
	}

	return ""
}

func (t *AdrpTracker) resolve(addr uint64) string {
	if t.lookup != nil {
		if name, ok := t.lookup(addr); ok {
			return "-> " + name
		}
	}
	return fmt.Sprintf("[0x%X]", addr)
}

// --- ARM64 instruction decoders ---

// ADRP: 1 immlo(2) 10000 immhi(19) Rd(5)
// Mask: bit31=1, bits28-24=10000 → (raw & 0x9F000000) == 0x90000000
func isADRP(raw uint32) bool {
	return raw&0x9F000000 == 0x90000000
}

func adrpTarget(raw uint32, pc uint64) uint64 {
	immhi := uint64((raw >> 5) & 0x7FFFF)
	immlo := uint64((raw >> 29) & 0x3)
	imm := (immhi << 2) | immlo // 21-bit page number
	// Sign-extend from 21 bits
	if imm&(1<<20) != 0 {
		imm |= 0xFFFFFFFFFFE00000
	}
	return (pc &^ 0xFFF) + (imm << 12)
}

// ADD (immediate): sf 0 0 100010 sh imm12 Rn Rd
// 64-bit: (raw & 0x7F800000) == 0x11000000
func isADDImm(raw uint32) bool {
	return raw&0x7FC00000 == 0x91000000 // sf=1 (64-bit), op=0 (ADD), S=0
}

func addImmValue(raw uint32) uint64 {
	imm12 := uint64((raw >> 10) & 0xFFF)
	sh := (raw >> 22) & 1
	if sh != 0 {
		imm12 <<= 12
	}
	return imm12
}

// LDR/LDRB/LDRH/LDRSW (unsigned immediate offset):
// size(2) 111 0 01 opc(2) imm12(12) Rn(5) Rt(5)
// We match: bits 29-27 = 111, bit 24 = 1, bits 23-22 = 01 (load, not store)
// Full mask: (raw & 0x3B400000) == 0x39400000
func isLDRUnsigned(raw uint32) bool {
	return raw&0x3B400000 == 0x39400000
}

func ldrUnsignedOffset(raw uint32) uint64 {
	imm12 := uint64((raw >> 10) & 0xFFF)
	size := (raw >> 30) & 0x3 // 0=byte, 1=half, 2=word, 3=dword
	return imm12 << size
}
