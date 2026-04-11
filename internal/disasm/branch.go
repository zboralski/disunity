package disasm

// ARM64 branch instruction detection from raw 32-bit encoding.

// BranchInfo describes a decoded branch instruction.
type BranchInfo struct {
	Target uint64 // absolute target address (0 if RET)
	Cond   bool   // true if conditional (has fallthrough)
	IsRet  bool   // true if RET
}

// DecodeBranch attempts to decode a branch instruction from raw encoding at the given PC.
// Returns nil if the instruction is not a branch/ret.
func DecodeBranch(raw uint32, pc uint64) *BranchInfo {
	// RET (RET Xn = 0xD65F0000 | Rn<<5)
	if raw&0xFFFFFC1F == 0xD65F0000 {
		return &BranchInfo{IsRet: true}
	}

	// B (unconditional): 000101 imm26
	if raw&0xFC000000 == 0x14000000 {
		imm26 := raw & 0x03FFFFFF
		offset := signExtend(imm26, 26) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset))}
	}

	// B.cond: 01010100 imm19 0 cond
	if raw&0xFF000010 == 0x54000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// CBZ: 0 sf 110100 imm19 Rt
	if raw&0x7F000000 == 0x34000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// CBNZ: 0 sf 110101 imm19 Rt
	if raw&0x7F000000 == 0x35000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// TBZ: 0 b5 110110 b40 imm14 Rt
	if raw&0x7F000000 == 0x36000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := signExtend(imm14, 14) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// TBNZ: 0 b5 110111 b40 imm14 Rt
	if raw&0x7F000000 == 0x37000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := signExtend(imm14, 14) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	return nil
}

func signExtend(val uint32, bits int) int32 {
	sign := uint32(1) << (bits - 1)
	mask := sign - 1
	if val&sign != 0 {
		return int32(val | ^mask)
	}
	return int32(val & mask)
}

// IsBranchTerminator returns true if the instruction terminates a basic block.
func IsBranchTerminator(raw uint32) bool {
	return DecodeBranch(raw, 0) != nil
}

// isBL returns true if the instruction is BL (branch with link).
func isBL(raw uint32) bool {
	return raw&0xFC000000 == 0x94000000
}

// isBLR returns true if the instruction is BLR (branch with link to register).
func isBLR(raw uint32) bool {
	return raw&0xFFFFFC1F == 0xD63F0000
}

// blTarget computes the absolute target of a BL instruction.
func blTarget(raw uint32, pc uint64) uint64 {
	imm26 := raw & 0x03FFFFFF
	offset := signExtend(imm26, 26) * 4
	return uint64(int64(pc) + int64(offset))
}

// blrReg returns the register number for a BLR instruction.
func blrReg(raw uint32) int {
	return int((raw >> 5) & 0x1F)
}
