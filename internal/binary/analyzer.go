package binary

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
)

// SearchSection represents a memory/file section for scanning
type SearchSection struct {
	offset     uint64 // File offset
	offsetEnd  uint64 // File offset end
	address    uint64 // Virtual address
	addressEnd uint64 // Virtual address end
}

// IL2CPPStaticAnalyzer performs static analysis of IL2CPP binaries
// to extract CodeGenModules without emulation.
type IL2CPPStaticAnalyzer struct {
	data       []byte
	elfFile    *elf.File
	baseAddr   uint64 // Virtual address where file is loaded (typically 0 for shared libs)
	version    float64
	imageCount int
	typeDefinitionsCount int // From metadata, used for MetadataRegistration search
	methodCount int // From metadata, used for old-style CodeRegistration search
	log        func(string, ...any) (int, error) // diagnostic logging

	// Sections for searching
	execSections []SearchSection
	dataSections []SearchSection
	bssSections  []SearchSection
}

// CodeGenModuleStatic represents a statically extracted CodeGenModule
type CodeGenModuleStatic struct {
	Name           string
	MethodPointers []uint64
}

// GenericMethodInfo represents a resolved generic method instantiation
type GenericMethodInfo struct {
	MethodDefinitionIndex int32  // Index into methodDefs
	ClassIndexIndex       int32  // Index into genericInsts for class type args (-1 if none)
	MethodIndexIndex      int32  // Index into genericInsts for method type args (-1 if none)
	Address               uint64 // Native address
}

// IL2CPPStaticResult contains all extracted data from static analysis
type IL2CPPStaticResult struct {
	CodeGenModules        []*CodeGenModuleStatic
	GenericMethodPointers []uint64           // Raw genericMethodPointers array
	GenericMethods        []GenericMethodInfo // Resolved generic methods
	Types                 []*Il2CppType       // Il2CppType array from MetadataRegistration
	FieldOffsets          []uint64            // Field offsets array
}

// Il2CppTypeEnum represents the IL2CPP type enumeration
type Il2CppTypeEnum uint8

const (
	IL2CPP_TYPE_END        Il2CppTypeEnum = 0x00
	IL2CPP_TYPE_VOID       Il2CppTypeEnum = 0x01
	IL2CPP_TYPE_BOOLEAN    Il2CppTypeEnum = 0x02
	IL2CPP_TYPE_CHAR       Il2CppTypeEnum = 0x03
	IL2CPP_TYPE_I1         Il2CppTypeEnum = 0x04
	IL2CPP_TYPE_U1         Il2CppTypeEnum = 0x05
	IL2CPP_TYPE_I2         Il2CppTypeEnum = 0x06
	IL2CPP_TYPE_U2         Il2CppTypeEnum = 0x07
	IL2CPP_TYPE_I4         Il2CppTypeEnum = 0x08
	IL2CPP_TYPE_U4         Il2CppTypeEnum = 0x09
	IL2CPP_TYPE_I8         Il2CppTypeEnum = 0x0a
	IL2CPP_TYPE_U8         Il2CppTypeEnum = 0x0b
	IL2CPP_TYPE_R4         Il2CppTypeEnum = 0x0c
	IL2CPP_TYPE_R8         Il2CppTypeEnum = 0x0d
	IL2CPP_TYPE_STRING     Il2CppTypeEnum = 0x0e
	IL2CPP_TYPE_PTR        Il2CppTypeEnum = 0x0f
	IL2CPP_TYPE_BYREF      Il2CppTypeEnum = 0x10
	IL2CPP_TYPE_VALUETYPE  Il2CppTypeEnum = 0x11
	IL2CPP_TYPE_CLASS      Il2CppTypeEnum = 0x12
	IL2CPP_TYPE_VAR        Il2CppTypeEnum = 0x13
	IL2CPP_TYPE_ARRAY      Il2CppTypeEnum = 0x14
	IL2CPP_TYPE_GENERICINST Il2CppTypeEnum = 0x15
	IL2CPP_TYPE_TYPEDBYREF Il2CppTypeEnum = 0x16
	IL2CPP_TYPE_I          Il2CppTypeEnum = 0x18
	IL2CPP_TYPE_U          Il2CppTypeEnum = 0x19
	IL2CPP_TYPE_FNPTR      Il2CppTypeEnum = 0x1b
	IL2CPP_TYPE_OBJECT     Il2CppTypeEnum = 0x1c
	IL2CPP_TYPE_SZARRAY    Il2CppTypeEnum = 0x1d
	IL2CPP_TYPE_MVAR       Il2CppTypeEnum = 0x1e
	IL2CPP_TYPE_CMOD_REQD  Il2CppTypeEnum = 0x1f
	IL2CPP_TYPE_CMOD_OPT   Il2CppTypeEnum = 0x20
	IL2CPP_TYPE_INTERNAL   Il2CppTypeEnum = 0x21
	IL2CPP_TYPE_MODIFIER   Il2CppTypeEnum = 0x40
	IL2CPP_TYPE_SENTINEL   Il2CppTypeEnum = 0x41
	IL2CPP_TYPE_PINNED     Il2CppTypeEnum = 0x45
	IL2CPP_TYPE_ENUM       Il2CppTypeEnum = 0x55
)

// Il2CppType represents the parsed Il2CppType structure from the binary
type Il2CppType struct {
	Data      uint64         // Union data (klassIndex, type ptr, etc.)
	Attrs     uint16         // Type attributes
	Type      Il2CppTypeEnum // Type enum
	NumMods   uint8          // Number of modifiers
	Byref     bool           // Is byref
	Pinned    bool           // Is pinned
	ValueType bool           // Is value type (v27.2+)
}

// Il2CppGenericClass represents a generic class instantiation
type Il2CppGenericClass struct {
	TypeDefinitionIndex int64  // v24.5 and below
	Type                uint64 // v27+ (pointer to Il2CppType)
	ClassInst           uint64 // Il2CppGenericInst for class type args
	MethodInst          uint64 // Il2CppGenericInst for method type args
}

// Il2CppGenericInst represents a generic instantiation
type Il2CppGenericInst struct {
	TypeArgc int64    // Number of type arguments
	TypeArgv []uint64 // Pointers to Il2CppType for each argument
}

// Il2CppArrayType represents an array type
type Il2CppArrayType struct {
	EType      uint64 // Element type (pointer to Il2CppType)
	Rank       uint8  // Array rank
	NumSizes   uint8  // Number of sizes
	NumLoBounds uint8 // Number of lower bounds
}

// Il2CppMethodSpec mirrors Il2CppDumper's struct
type Il2CppMethodSpec struct {
	MethodDefinitionIndex int32
	ClassIndexIndex       int32
	MethodIndexIndex      int32
}

// Il2CppGenericMethodIndices mirrors Il2CppDumper's struct
type Il2CppGenericMethodIndices struct {
	MethodIndex    int32
	InvokerIndex   int32
	AdjustorThunk  int32 // Only for v24.5 or v27.1+
}

// Il2CppGenericMethodFunctionsDefinitions mirrors Il2CppDumper's struct
type Il2CppGenericMethodFunctionsDefinitions struct {
	GenericMethodIndex int32
	Indices            Il2CppGenericMethodIndices
}

// Elf64_Rela represents an ELF64 relocation entry with addend
type Elf64_Rela struct {
	Offset uint64 // Address to relocate
	Info   uint64 // Relocation type and symbol index
	Addend int64  // Addend
}

// NewIL2CPPStaticAnalyzer creates a static analyzer for an IL2CPP binary
func NewIL2CPPStaticAnalyzer(path string, version float64, imageCount, typeDefinitionsCount, methodCount int) (*IL2CPPStaticAnalyzer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}

	// Find base address (lowest PT_LOAD vaddr)
	var baseAddr uint64 = 0xFFFFFFFFFFFFFFFF
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && prog.Vaddr < baseAddr {
			baseAddr = prog.Vaddr
		}
	}
	if baseAddr == 0xFFFFFFFFFFFFFFFF {
		baseAddr = 0
	}

	analyzer := &IL2CPPStaticAnalyzer{
		data:                 data,
		elfFile:              f,
		baseAddr:             baseAddr,
		version:              version,
		imageCount:           imageCount,
		typeDefinitionsCount: typeDefinitionsCount,
		methodCount:          methodCount,
		log:                  fmt.Printf,
	}

	// Classify sections based on flags (following Il2CppDumper's Elf64.cs logic exactly)
	// Il2CppDumper uses p_flags values:
	//   1 (PF_X), 3, 5, 7 → execList
	//   2 (PF_W), 4 (PF_R), 6 (PF_W|PF_R) → dataList
	// Key insight: Read-only segments (flags 4 = PF_R) are classified as DATA, not skipped!
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || prog.Memsz == 0 {
			continue
		}

		sec := SearchSection{
			offset:     prog.Off,
			offsetEnd:  prog.Off + prog.Filesz,
			address:    prog.Vaddr,
			addressEnd: prog.Vaddr + prog.Memsz,
		}

		flags := uint32(prog.Flags)
		switch flags {
		case 1, 3, 5, 7: // PF_X or any combination with PF_X
			analyzer.execSections = append(analyzer.execSections, sec)
		case 2, 4, 6: // PF_W, PF_R, or PF_W|PF_R (no execute)
			if prog.Filesz > 0 {
				analyzer.dataSections = append(analyzer.dataSections, sec)
			}
			// BSS handling for segments where memsz > filesz
			if prog.Memsz > prog.Filesz {
				analyzer.bssSections = append(analyzer.bssSections, SearchSection{
					offset:     prog.Off + prog.Filesz,
					offsetEnd:  prog.Off + prog.Filesz, // BSS has no file backing
					address:    prog.Vaddr + prog.Filesz,
					addressEnd: prog.Vaddr + prog.Memsz,
				})
			}
		}
	}

	analyzer.log("[il2cpp static] Loaded: exec=%d, data=%d, bss=%d sections\n",
		len(analyzer.execSections), len(analyzer.dataSections), len(analyzer.bssSections))

	// Apply ELF relocations (critical for IL2CPP binaries where pointers are zeroed)
	if err := analyzer.applyRelocations(); err != nil {
		analyzer.log("[il2cpp static] Warning: could not apply relocations: %v\n", err)
	}

	return analyzer, nil
}

// Close releases resources
func (a *IL2CPPStaticAnalyzer) Close() {
	if a.elfFile != nil {
		a.elfFile.Close()
	}
}

// ARM64 relocation type
const R_AARCH64_RELATIVE = 1027

// ELF dynamic tags (not in debug/elf)
const (
	DT_RELA   = 7
	DT_RELASZ = 8
)

// applyRelocations processes ELF relocations in-place
// This is critical for IL2CPP binaries where CodeRegistration/MetadataRegistration
// pointers are zeroed and only filled in by R_AARCH64_RELATIVE relocations
func (a *IL2CPPStaticAnalyzer) applyRelocations() error {
	// Find PT_DYNAMIC segment
	var dynamicOff, dynamicSize uint64
	for _, prog := range a.elfFile.Progs {
		if prog.Type == elf.PT_DYNAMIC {
			dynamicOff = prog.Off
			dynamicSize = prog.Filesz
			break
		}
	}
	if dynamicOff == 0 {
		return fmt.Errorf("no PT_DYNAMIC segment")
	}

	// Parse dynamic section to find DT_RELA and DT_RELASZ
	var relaVA, relaSize uint64
	for off := dynamicOff; off < dynamicOff+dynamicSize; off += 16 {
		tag := int64(binary.LittleEndian.Uint64(a.data[off:]))
		val := binary.LittleEndian.Uint64(a.data[off+8:])
		if tag == 0 {
			break // DT_NULL
		}
		switch tag {
		case DT_RELA:
			relaVA = val
		case DT_RELASZ:
			relaSize = val
		}
	}

	if relaVA == 0 || relaSize == 0 {
		return fmt.Errorf("no RELA section found")
	}

	// Map RELA VA to file offset
	relaOff, err := a.mapVATR(relaVA)
	if err != nil {
		return fmt.Errorf("map RELA: %w", err)
	}

	// Process relocations (Elf64_Rela is 24 bytes: offset(8) + info(8) + addend(8))
	relaCount := relaSize / 24
	applied := 0

	for i := uint64(0); i < relaCount; i++ {
		off := relaOff + i*24
		relaOffset := binary.LittleEndian.Uint64(a.data[off:])
		relaInfo := binary.LittleEndian.Uint64(a.data[off+8:])
		relaAddend := int64(binary.LittleEndian.Uint64(a.data[off+16:]))

		relType := relaInfo & 0xFFFFFFFF
		// For R_AARCH64_RELATIVE, value = base + addend (for shared libs, base is 0)
		if relType == R_AARCH64_RELATIVE {
			// Map relocation target to file offset
			targetOff, err := a.mapVATR(relaOffset)
			if err != nil {
				continue
			}
			// Write the relocated value
			value := uint64(relaAddend)
			binary.LittleEndian.PutUint64(a.data[targetOff:], value)
			applied++
		}
	}

	a.log("[il2cpp static] Applied %d/%d relocations\n", applied, relaCount)
	return nil
}

// mapVATR converts a virtual address to a raw file offset
func (a *IL2CPPStaticAnalyzer) mapVATR(va uint64) (uint64, error) {
	for _, prog := range a.elfFile.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if va >= prog.Vaddr && va < prog.Vaddr+prog.Filesz {
			return prog.Off + (va - prog.Vaddr), nil
		}
	}
	return 0, fmt.Errorf("address 0x%x not in any loadable segment", va)
}

// readUInt64At reads a uint64 from a file offset
func (a *IL2CPPStaticAnalyzer) readUInt64At(off uint64) (uint64, error) {
	if off+8 > uint64(len(a.data)) {
		return 0, fmt.Errorf("read past end of file")
	}
	return binary.LittleEndian.Uint64(a.data[off:]), nil
}

// readInt64At reads an int64 from a file offset
func (a *IL2CPPStaticAnalyzer) readInt64At(off uint64) (int64, error) {
	if off+8 > uint64(len(a.data)) {
		return 0, fmt.Errorf("read past end of file")
	}
	return int64(binary.LittleEndian.Uint64(a.data[off:])), nil
}

// readStringAt reads a null-terminated string from a file offset
func (a *IL2CPPStaticAnalyzer) readStringAt(off uint64) (string, error) {
	if off >= uint64(len(a.data)) {
		return "", fmt.Errorf("offset past end of file")
	}
	end := off
	for end < uint64(len(a.data)) && a.data[end] != 0 {
		end++
	}
	return string(a.data[off:end]), nil
}

// FindCodeRegistration searches for the CodeRegistration structure in the binary
// using pattern matching similar to Il2CppDumper.
//
// For v24+, it searches for "mscorlib.dll" string and traces references back.
// For older versions, it scans for method count patterns.
func (a *IL2CPPStaticAnalyzer) FindCodeRegistration() (uint64, error) {
	// Try the CodeGenModules-based search first (v24.2+)
	if a.version >= 24 {
		va, err := a.findCodeRegistration2019()
		if err == nil {
			return va, nil
		}
		// Fall back to old-style search (pre-CodeGenModules v24)
		va, err2 := a.findCodeRegistrationOld()
		if err2 == nil {
			return va, nil
		}
		return 0, fmt.Errorf("CodeRegistration not found (2019: %v, old: %v)", err, err2)
	}
	return a.findCodeRegistrationOld()
}

// mscorlib.dll as bytes
var mscorlibDll = []byte("mscorlib.dll\x00")

// findAllOccurrences finds all occurrences of pattern in data
func findAllOccurrences(data, pattern []byte) []int {
	var indices []int
	offset := 0
	for {
		idx := bytes.Index(data[offset:], pattern)
		if idx < 0 {
			break
		}
		indices = append(indices, offset+idx)
		offset += idx + 1
	}
	return indices
}

// findCodeRegistration2019 finds CodeRegistration for v24.2+ using string search
// This mirrors Il2CppDumper's FindCodeRegistration2019 algorithm exactly
func (a *IL2CPPStaticAnalyzer) findCodeRegistration2019() (uint64, error) {
	a.log("[il2cpp static] Version: %.1f, imageCount: %d\n", a.version, a.imageCount)
	a.log("[il2cpp static] Exec sections: %d, Data sections: %d\n", len(a.execSections), len(a.dataSections))

	// For ELF, try exec sections first (like Il2CppDumper does)
	codeReg := a.findCodeRegistrationInSections(a.execSections)
	if codeReg != 0 {
		return codeReg, nil
	}

	// Fall back to data sections
	codeReg = a.findCodeRegistrationInSections(a.dataSections)
	if codeReg != 0 {
		return codeReg, nil
	}

	return 0, fmt.Errorf("CodeRegistration not found")
}

// findCodeRegistrationInSections searches for CodeRegistration in given sections
func (a *IL2CPPStaticAnalyzer) findCodeRegistrationInSections(sections []SearchSection) uint64 {
	// Search for "mscorlib.dll" in each section
	for _, sec := range sections {
		end := sec.offsetEnd
		if end > uint64(len(a.data)) {
			end = uint64(len(a.data))
		}

		sectionData := a.data[sec.offset:end]
		indices := findAllOccurrences(sectionData, mscorlibDll)

		for _, idx := range indices {
			// Convert to VA
			dllVA := sec.address + uint64(idx)
			a.log("[il2cpp static] Found mscorlib.dll at VA 0x%x\n", dllVA)

			// Find references to this string (always search in data sections)
			refs := a.findReferences(dllVA)
			for _, ref := range refs {
				// Find references to this reference (ref is CodeGenModule pointer)
				refs2 := a.findReferences(ref)
				for _, ref2 := range refs2 {
					// ref2 is in the codeGenModules array
					// For v27+, search backwards for module count
					// Note: codeGenModulesCount can be larger than imageCount (from metadata)
					// so we search a wider range and accept any reasonable count
					if a.version >= 27 {
						maxSearchRange := 1000 // Search up to 1000 positions
						for i := maxSearchRange - 1; i >= 0; i-- {
							// Try to find the array start
							targetVA := ref2 - uint64(i)*8
							refs3 := a.findReferences(targetVA)
							for _, ref3 := range refs3 {
								// ref3 should point to codeGenModules array
								// Check if there's a reasonable count at ref3 - 8
								off, err := a.mapVATR(ref3 - 8)
								if err != nil {
									continue
								}
								count, err := a.readInt64At(off)
								if err != nil {
									continue
								}
								// Accept any reasonable module count (must be >= imageCount and <= 1000)
								// Also require count > i (the index we found mscorlib at)
								if count >= int64(a.imageCount) && count <= 1000 && count > int64(i) {
									// Verify this looks like CodeRegistration by checking the modules pointer
									// ref3 should be codeGenModules, and it should point to ref2 - i*8
									ptrOff, err := a.mapVATR(ref3)
									if err != nil {
										continue
									}
									ptrVal, err := a.readUInt64At(ptrOff)
									if err != nil {
										continue
									}
									if ptrVal != targetVA {
										continue
									}

									// Found it! Calculate CodeRegistration base
									// ref3 points to codeGenModules pointer
									// CodeRegistration base depends on version

									var codeRegVA uint64
									if a.version == 29 || a.version >= 31 {
										// v29/v31: probe v29.0 (14 fields) vs v29.1/v31 (16 fields)
										codeRegVA = a.detectV29VariantAndCalculateBase(ref3)
									} else {
										// v27-28: 14 fields before codeGenModules
										codeRegVA = ref3 - 8*14
									}

									return codeRegVA
								}
							}
						}
					} else {
						// Pre-v27 logic (v24.2 to v26)
						for i := 0; i < a.imageCount; i++ {
							targetVA := ref2 - uint64(i)*8
							refs3 := a.findReferences(targetVA)
							for _, ref3 := range refs3 {
								return a.detectV24VariantAndCalculateBase(ref3)
							}
						}
					}
				}
			}
		}
	}

	return 0
}

// detectV29VariantAndCalculateBase detects v29.0 vs v29.1/v31 layout and returns
// the correct CodeRegistration base address.
// Il2CppDumper's approach: try v29.0 first (14 fields), check genericMethodPointersCount.
// If it's > 0x50000, the struct is misaligned because it's actually v29.1/v31 (16 fields).
// For v31 binaries: if v29.0 layout is valid, downgrade version to 29.
func (a *IL2CPPStaticAnalyzer) detectV29VariantAndCalculateBase(codeGenModulesPtr uint64) uint64 {
	// v29.0: 14 fields before codeGenModules
	// v29.1/v31: 16 fields before codeGenModules (has 2 extra fields)
	origVersion := a.version

	// Try v29.0 first
	codeRegVA_v29_0 := codeGenModulesPtr - 8*14

	codeRegOff, err := a.mapVATR(codeRegVA_v29_0)
	if err != nil {
		// Can't validate, assume v29.0
		return codeRegVA_v29_0
	}

	// Read genericMethodPointersCount (at offset 16 for v22+: after reversePInvoke fields)
	gmPtrsCount, err := a.readInt64At(codeRegOff + 16)
	if err != nil {
		return codeRegVA_v29_0
	}

	const limit int64 = 0x50000
	if gmPtrsCount > 0 && gmPtrsCount <= limit {
		// Valid for v29.0 layout
		if origVersion >= 31 {
			a.version = 29
			a.log("[il2cpp static] Detected v29.0 layout for v%g binary (genericMethodPointersCount=%d <= %d)\n", origVersion, gmPtrsCount, limit)
		} else {
			a.log("[il2cpp static] Detected v29.0 (genericMethodPointersCount=%d <= %d)\n", gmPtrsCount, limit)
		}
		return codeRegVA_v29_0
	}

	// Invalid for v29.0, use v29.1/v31 layout (16 fields)
	if origVersion >= 31 {
		// Keep version as-is (v31)
		a.log("[il2cpp static] Confirmed v31 layout (genericMethodPointersCount=%d > %d)\n", gmPtrsCount, limit)
	} else {
		a.version = 29.1
		a.log("[il2cpp static] Detected v29.1 (genericMethodPointersCount=%d > %d)\n", gmPtrsCount, limit)
	}
	codeRegVA_v29_1 := codeGenModulesPtr - 8*16
	return codeRegVA_v29_1
}

// detectV24VariantAndCalculateBase detects v24.x sub-version and returns the correct
// CodeRegistration base address.
// v24 field counts before codeGenModules vary by sub-version:
//   v24.0-v24.2: 13 fields (no windowsRuntimeFactory)
//   v24.3-v24.4: 15 fields (+windowsRuntimeFactoryCount, +windowsRuntimeFactoryTable)
//   v24.5:       16 fields (+genericAdjustorThunks)
func (a *IL2CPPStaticAnalyzer) detectV24VariantAndCalculateBase(codeGenModulesPtr uint64) uint64 {
	const limit int64 = 0x50000

	// Try each layout from largest to smallest field count.
	// Validate by checking genericMethodPointersCount at base+16.
	candidates := []struct {
		fields  uint64
		version float64
		label   string
	}{
		{16, 24.5, "v24.5"},
		{15, 24.3, "v24.3"},
		{13, 24.0, "v24.0"},
	}

	for _, c := range candidates {
		codeRegVA := codeGenModulesPtr - 8*c.fields
		codeRegOff, err := a.mapVATR(codeRegVA)
		if err != nil {
			continue
		}

		gmPtrsCount, err := a.readInt64At(codeRegOff + 16)
		if err != nil {
			continue
		}

		if gmPtrsCount > 0 && gmPtrsCount <= limit {
			a.version = c.version
			a.log("[il2cpp static] Detected %s (genericMethodPointersCount=%d, fields=%d)\n", c.label, gmPtrsCount, c.fields)
			return codeRegVA
		}
	}

	// Fall back to v24.0
	a.log("[il2cpp static] Could not detect v24 sub-version, falling back to v24.0\n")
	return codeGenModulesPtr - 8*13
}

// findCodeRegistrationOld finds CodeRegistration for pre-CodeGenModules binaries.
// Scans data sections for a (count, pointer) pair where count is plausible and
// the pointer references an array of valid code addresses in exec sections.
func (a *IL2CPPStaticAnalyzer) findCodeRegistrationOld() (uint64, error) {
	// Determine valid code VA range from exec sections
	if len(a.execSections) == 0 {
		return 0, fmt.Errorf("no exec sections")
	}
	codeMin := a.execSections[0].address
	codeMax := a.execSections[0].address + (a.execSections[0].offsetEnd - a.execSections[0].offset)
	for _, sec := range a.execSections[1:] {
		if sec.address < codeMin {
			codeMin = sec.address
		}
		end := sec.address + (sec.offsetEnd - sec.offset)
		if end > codeMax {
			codeMax = end
		}
	}

	for _, sec := range a.dataSections {
		end := sec.offsetEnd
		if end > uint64(len(a.data)) {
			end = uint64(len(a.data))
		}

		for off := sec.offset; off+16 <= end; off += 8 {
			count := binary.LittleEndian.Uint64(a.data[off : off+8])
			// methodPointersCount should be reasonable
			if count < 1000 || count > 200000 {
				continue
			}
			ptr := binary.LittleEndian.Uint64(a.data[off+8 : off+16])
			// methodPointers should point somewhere in the file's VA space
			ptrOff, err := a.mapVATR(ptr)
			if err != nil || ptrOff+8 > uint64(len(a.data)) {
				continue
			}
			// Read first entry of the method pointers array - should be a code address
			firstMethod := binary.LittleEndian.Uint64(a.data[ptrOff : ptrOff+8])
			if firstMethod < codeMin || firstMethod > codeMax {
				continue
			}
			// Spot-check a few more entries
			valid := 1
			for i := uint64(1); i < min(count, 10); i++ {
				moff := ptrOff + i*8
				if moff+8 > uint64(len(a.data)) {
					break
				}
				mv := binary.LittleEndian.Uint64(a.data[moff : moff+8])
				if mv >= codeMin && mv <= codeMax {
					valid++
				}
			}
			if valid < 5 {
				continue
			}

			va := sec.address + (off - sec.offset)
			a.log("[il2cpp static] Old-style CodeRegistration at VA 0x%x (methodPointersCount=%d)\n", va, count)
			return va, nil
		}
	}

	return 0, fmt.Errorf("no CodeRegistration candidate found in data sections")
}

// findReferencesInSections finds all places in given sections that contain a pointer to addr
func (a *IL2CPPStaticAnalyzer) findReferencesInSections(addr uint64, sections []SearchSection) []uint64 {
	var refs []uint64
	addrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrBytes, addr)

	for _, sec := range sections {
		end := sec.offsetEnd
		if end > uint64(len(a.data)) {
			end = uint64(len(a.data))
		}

		// Search for the 8-byte pattern (aligned to 8 bytes)
		for off := sec.offset; off+8 <= end; off += 8 {
			if bytes.Equal(a.data[off:off+8], addrBytes) {
				// Convert file offset back to VA
				va := sec.address + (off - sec.offset)
				refs = append(refs, va)
			}
		}
	}
	return refs
}

// findReferences finds all places in data sections that contain a pointer to addr
func (a *IL2CPPStaticAnalyzer) findReferences(addr uint64) []uint64 {
	return a.findReferencesInSections(addr, a.dataSections)
}

// getCodeGenModulesOffset returns the offset of codeGenModulesCount in CodeRegistration
// based on IL2CPP version (fields are version-dependent)
func (a *IL2CPPStaticAnalyzer) getCodeGenModulesOffset() uint64 {
	// Count fields before codeGenModulesCount based on version
	// Each field is 8 bytes (ulong)
	offset := uint64(0)

	// v24.2+: No methodPointersCount/methodPointers at start
	// v22+: reversePInvokeWrapperCount + reversePInvokeWrappers (2 fields)
	if a.version >= 22 {
		offset += 16
	}

	// genericMethodPointersCount + genericMethodPointers (2 fields)
	offset += 16

	// v24.5 or v27.1+: genericAdjustorThunks (1 field)
	if (a.version >= 24.5 && a.version < 25) || a.version >= 27.1 {
		offset += 8
	}

	// invokerPointersCount + invokerPointers (2 fields)
	offset += 16

	// v24.5 and below: customAttributeCount + customAttributeGenerators (2 fields)
	if a.version <= 24.5 {
		offset += 16
	}

	// v22+: unresolvedVirtualCallCount + unresolvedVirtualCallPointers (2 fields)
	if a.version >= 22 {
		offset += 16
	}

	// v29.1+: unresolvedInstanceCallPointers + unresolvedStaticCallPointers (2 fields)
	if a.version >= 29.1 {
		offset += 16
	}

	// v23+: interopDataCount + interopData (2 fields)
	if a.version >= 23 {
		offset += 16
	}

	// v24.3+: windowsRuntimeFactoryCount + windowsRuntimeFactoryTable (2 fields)
	if a.version >= 24.3 {
		offset += 16
	}

	// Now we're at codeGenModulesCount
	return offset
}

// autoDetectMinorVersion probes the CodeRegistration structure to detect minor version.
// For v27, metadata only specifies major version 27, but binaries can be 27.0, 27.1, or 27.2.
// Il2CppDumper handles this by checking if count fields have unrealistic values (pointers instead of counts).
func (a *IL2CPPStaticAnalyzer) autoDetectMinorVersion(codeRegOff uint64) error {
	const limit = 0x50000 // Il2CppDumper's heuristic limit for count fields

	// Only auto-detect for v27.x
	if a.version < 27 || a.version >= 28 {
		return nil
	}

	// For v27.0: try reading invokerPointersCount at offset 0x20
	// (reversePInvokeWrapper 16 + genericMethodPointers 16 = 32)
	invokerCountOff := codeRegOff + 0x20
	invokerCount, err := a.readInt64At(invokerCountOff)
	if err != nil {
		return fmt.Errorf("probe invokerPointersCount: %w", err)
	}

	// If invokerCount looks like a pointer (exceeds limit), upgrade to v27.1
	if invokerCount > limit {
		a.log("[il2cpp static] Auto-detected v27.1 (invokerPointersCount=0x%x exceeds limit)\n", invokerCount)
		a.version = 27.1
		return nil
	}

	// Check reversePInvokeWrapperCount at offset 0x00
	reverseCount, err := a.readInt64At(codeRegOff)
	if err != nil {
		return fmt.Errorf("probe reversePInvokeWrapperCount: %w", err)
	}

	if reverseCount > limit {
		a.log("[il2cpp static] Auto-detected v27.1 (reversePInvokeWrapperCount=0x%x exceeds limit)\n", reverseCount)
		a.version = 27.1
		return nil
	}

	a.log("[il2cpp static] Using metadata version v%.1f (counts within expected range)\n", a.version)
	return nil
}

// ReadCodeGenModules reads CodeGenModule structures starting from the codeGenModules pointer
// in the CodeRegistration structure.
func (a *IL2CPPStaticAnalyzer) ReadCodeGenModules(codeRegVA uint64) ([]*CodeGenModuleStatic, error) {
	// Map CodeRegistration VA to file offset
	codeRegOff, err := a.mapVATR(codeRegVA)
	if err != nil {
		return nil, fmt.Errorf("map CodeRegistration: %w", err)
	}

	a.log("[il2cpp static] CodeRegistration at VA 0x%x (offset 0x%x)\n", codeRegVA, codeRegOff)

	// Auto-detect minor version by probing structure (for v27.x)
	if err := a.autoDetectMinorVersion(codeRegOff); err != nil {
		return nil, fmt.Errorf("auto-detect version: %w", err)
	}

	// Calculate offset to codeGenModulesCount based on version
	modulesFieldOffset := a.getCodeGenModulesOffset()
	a.log("[il2cpp static] codeGenModulesCount offset: 0x%x (version %.1f)\n", modulesFieldOffset, a.version)

	modulesCountOff := codeRegOff + modulesFieldOffset
	modulesCount, err := a.readInt64At(modulesCountOff)
	if err != nil {
		return nil, fmt.Errorf("read modules count: %w", err)
	}

	modulesPtrOff := codeRegOff + modulesFieldOffset + 8
	modulesPtr, err := a.readUInt64At(modulesPtrOff)
	if err != nil {
		return nil, fmt.Errorf("read modules pointer: %w", err)
	}

	a.log("[il2cpp static] codeGenModulesCount=%d, codeGenModules=0x%x\n", modulesCount, modulesPtr)

	if modulesCount <= 0 || modulesCount > 10000 {
		return nil, fmt.Errorf("invalid modules count: %d", modulesCount)
	}

	// Map modules array pointer to file offset
	modulesArrayOff, err := a.mapVATR(modulesPtr)
	if err != nil {
		return nil, fmt.Errorf("map modules array: %w", err)
	}

	// Read array of pointers to CodeGenModule
	var modules []*CodeGenModuleStatic
	for i := int64(0); i < modulesCount; i++ {
		ptrOff := modulesArrayOff + uint64(i)*8
		modPtr, err := a.readUInt64At(ptrOff)
		if err != nil || modPtr == 0 {
			continue
		}

		mod, err := a.readCodeGenModule(modPtr)
		if err != nil {
			continue
		}
		if mod.Name != "" {
			modules = append(modules, mod)
		}
	}

	a.log("[il2cpp static] Read %d valid modules\n", len(modules))
	return modules, nil
}

// readCodeGenModule reads a single CodeGenModule structure
func (a *IL2CPPStaticAnalyzer) readCodeGenModule(va uint64) (*CodeGenModuleStatic, error) {
	off, err := a.mapVATR(va)
	if err != nil {
		return nil, err
	}

	// CodeGenModule layout:
	//   +0:  moduleName (pointer to string)
	//   +8:  methodPointerCount (int64)
	//   +16: methodPointers (pointer to array)

	namePtr, err := a.readUInt64At(off)
	if err != nil {
		return nil, err
	}

	methodCount, err := a.readInt64At(off + 8)
	if err != nil {
		return nil, err
	}

	methodsPtr, err := a.readUInt64At(off + 16)
	if err != nil {
		return nil, err
	}

	// Read module name
	var name string
	if namePtr != 0 {
		nameOff, err := a.mapVATR(namePtr)
		if err == nil {
			name, _ = a.readStringAt(nameOff)
		}
	}

	// methodCount can be 0 for modules with no methods
	if name == "" || methodCount < 0 || methodCount > 1000000 {
		return nil, fmt.Errorf("invalid module: name=%q count=%d", name, methodCount)
	}

	// Read method pointers array
	var pointers []uint64
	if methodsPtr != 0 {
		methodsOff, err := a.mapVATR(methodsPtr)
		if err == nil {
			for j := int64(0); j < methodCount; j++ {
				ptr, err := a.readUInt64At(methodsOff + uint64(j)*8)
				if err != nil {
					break
				}
				pointers = append(pointers, ptr)
			}
		}
	}

	return &CodeGenModuleStatic{
		Name:           name,
		MethodPointers: pointers,
	}, nil
}

// GetCodeGenModulesStatic performs static analysis to extract CodeGenModules
// without emulation. This is the preferred method for v24.2+ binaries.
func GetCodeGenModulesStatic(binaryPath string, metadataVersion float64, imageCount, typeDefinitionsCount int) ([]*CodeGenModuleStatic, error) {
	analyzer, err := NewIL2CPPStaticAnalyzer(binaryPath, metadataVersion, imageCount, typeDefinitionsCount, 0)
	if err != nil {
		return nil, err
	}
	defer analyzer.Close()

	// Find CodeRegistration
	codeRegVA, err := analyzer.FindCodeRegistration()
	if err != nil {
		return nil, fmt.Errorf("find CodeRegistration: %w", err)
	}

	analyzer.log("[il2cpp static] Found CodeRegistration at VA 0x%x\n", codeRegVA)

	// Read CodeGenModules
	return analyzer.ReadCodeGenModules(codeRegVA)
}

// GetFullStaticAnalysis performs complete static analysis including generic methods
func GetFullStaticAnalysis(binaryPath string, metadataVersion float64, imageCount, typeDefinitionsCount int) (*IL2CPPStaticResult, error) {
	analyzer, err := NewIL2CPPStaticAnalyzer(binaryPath, metadataVersion, imageCount, typeDefinitionsCount, 0)
	if err != nil {
		return nil, err
	}
	defer analyzer.Close()

	// Find CodeRegistration
	codeRegVA, err := analyzer.FindCodeRegistration()
	if err != nil {
		return nil, fmt.Errorf("find CodeRegistration: %w", err)
	}
	analyzer.log("[il2cpp static] Found CodeRegistration at VA 0x%x\n", codeRegVA)

	// Read CodeGenModules
	modules, err := analyzer.ReadCodeGenModules(codeRegVA)
	if err != nil {
		return nil, fmt.Errorf("read CodeGenModules: %w", err)
	}

	result := &IL2CPPStaticResult{
		CodeGenModules: modules,
	}

	// Read genericMethodPointers from CodeRegistration
	genericPtrs, err := analyzer.ReadGenericMethodPointers(codeRegVA)
	if err != nil {
		analyzer.log("[il2cpp static] Warning: could not read genericMethodPointers: %v\n", err)
	} else {
		result.GenericMethodPointers = genericPtrs
		analyzer.log("[il2cpp static] Read %d genericMethodPointers\n", len(genericPtrs))
	}

	// Find MetadataRegistration
	metaRegVA, err := analyzer.FindMetadataRegistration()
	if err != nil {
		analyzer.log("[il2cpp static] Warning: could not find MetadataRegistration: %v\n", err)
		return result, nil
	}
	analyzer.log("[il2cpp static] Found MetadataRegistration at VA 0x%x\n", metaRegVA)

	// Read generic method table and method specs
	genericMethods, err := analyzer.ReadGenericMethods(metaRegVA, result.GenericMethodPointers)
	if err != nil {
		analyzer.log("[il2cpp static] Warning: could not read generic methods: %v\n", err)
		return result, nil
	}
	result.GenericMethods = genericMethods
	analyzer.log("[il2cpp static] Resolved %d generic method instantiations\n", len(genericMethods))

	return result, nil
}

// readInt32At reads an int32 from a file offset
func (a *IL2CPPStaticAnalyzer) readInt32At(off uint64) (int32, error) {
	if off+4 > uint64(len(a.data)) {
		return 0, fmt.Errorf("read past end of file")
	}
	return int32(binary.LittleEndian.Uint32(a.data[off:])), nil
}

// getGenericMethodPointersOffset returns the offset of genericMethodPointersCount in CodeRegistration
func (a *IL2CPPStaticAnalyzer) getGenericMethodPointersOffset() uint64 {
	offset := uint64(0)

	// v22+: reversePInvokeWrapperCount + reversePInvokeWrappers (2 fields)
	if a.version >= 22 {
		offset += 16
	}

	// Now we're at genericMethodPointersCount
	return offset
}

// ReadMethodPointersFlat reads method pointers from old-style (pre-CodeGenModules)
// CodeRegistration. Returns a single synthetic CodeGenModuleStatic containing all
// method pointers. The struct layout (Unity 2018.x, IL2CPP v24):
//
//	methodPointersCount      uint32 (padded to 8)
//	methodPointers           *Il2CppMethodPointer
//	reversePInvokeWrapperCount ...
//	genericMethodPointersCount ...
//	genericMethodPointers    ...
//	invokerPointersCount     ...
//	invokerPointers          ...
//	customAttributeCount     ...
//	customAttributeGenerators ...
//	unresolvedVirtualCallCount ...
//	unresolvedVirtualCallPointers ...
//	interopDataCount         ...
//	interopData              ...
func (a *IL2CPPStaticAnalyzer) ReadMethodPointersFlat(codeRegVA uint64) ([]*CodeGenModuleStatic, error) {
	off, err := a.mapVATR(codeRegVA)
	if err != nil {
		return nil, fmt.Errorf("map CodeRegistration: %w", err)
	}

	// Field 0: methodPointersCount (uint64 on 64-bit)
	count, err := a.readInt64At(off)
	if err != nil || count <= 0 || count > 500000 {
		return nil, fmt.Errorf("invalid methodPointersCount: %d", count)
	}

	// Field 1: methodPointers (pointer)
	ptrVA, err := a.readUInt64At(off + 8)
	if err != nil {
		return nil, fmt.Errorf("read methodPointers VA: %w", err)
	}

	ptrOff, err := a.mapVATR(ptrVA)
	if err != nil {
		return nil, fmt.Errorf("map methodPointers: %w", err)
	}

	methods := make([]uint64, 0, count)
	for i := int64(0); i < count; i++ {
		mOff := ptrOff + uint64(i)*8
		if mOff+8 > uint64(len(a.data)) {
			break
		}
		addr := binary.LittleEndian.Uint64(a.data[mOff : mOff+8])
		methods = append(methods, addr)
	}

	a.log("[il2cpp static] Old-style methodPointers: %d entries from VA 0x%x\n", len(methods), ptrVA)

	// Return as single synthetic module so the pipeline works unchanged
	return []*CodeGenModuleStatic{
		{Name: "", MethodPointers: methods},
	}, nil
}

// ReadGenericMethodPointersOld reads generic method pointers from old-style
// CodeRegistration (fields [4] and [5]: genericMethodPointersCount + genericMethodPointers).
func (a *IL2CPPStaticAnalyzer) ReadGenericMethodPointersOld(codeRegVA uint64) ([]uint64, error) {
	off, err := a.mapVATR(codeRegVA)
	if err != nil {
		return nil, err
	}

	// Old-style layout: [0]count [1]ptrs [2]revCount [3]revPtrs [4]gmCount [5]gmPtrs
	gmCount, err := a.readInt64At(off + 32) // field [4]
	if err != nil || gmCount <= 0 || gmCount > 500000 {
		return nil, fmt.Errorf("invalid genericMethodPointersCount: %d", gmCount)
	}

	gmPtrVA, err := a.readUInt64At(off + 40) // field [5]
	if err != nil {
		return nil, err
	}

	gmOff, err := a.mapVATR(gmPtrVA)
	if err != nil {
		return nil, err
	}

	ptrs := make([]uint64, 0, gmCount)
	for i := int64(0); i < gmCount; i++ {
		mOff := gmOff + uint64(i)*8
		if mOff+8 > uint64(len(a.data)) {
			break
		}
		ptrs = append(ptrs, binary.LittleEndian.Uint64(a.data[mOff:mOff+8]))
	}

	a.log("[il2cpp static] Old-style genericMethodPointers: %d entries\n", len(ptrs))
	return ptrs, nil
}

// ReadGenericMethodPointers reads the genericMethodPointers array from CodeRegistration
func (a *IL2CPPStaticAnalyzer) ReadGenericMethodPointers(codeRegVA uint64) ([]uint64, error) {
	codeRegOff, err := a.mapVATR(codeRegVA)
	if err != nil {
		return nil, fmt.Errorf("map CodeRegistration: %w", err)
	}

	// Get offset to genericMethodPointersCount
	gmPtrsOffset := a.getGenericMethodPointersOffset()

	countOff := codeRegOff + gmPtrsOffset
	count, err := a.readInt64At(countOff)
	if err != nil {
		return nil, fmt.Errorf("read genericMethodPointersCount: %w", err)
	}

	ptrOff := codeRegOff + gmPtrsOffset + 8
	ptr, err := a.readUInt64At(ptrOff)
	if err != nil {
		return nil, fmt.Errorf("read genericMethodPointers: %w", err)
	}

	a.log("[il2cpp static] genericMethodPointersCount=%d, genericMethodPointers=0x%x\n", count, ptr)

	if count <= 0 || count > 1000000 {
		return nil, fmt.Errorf("invalid genericMethodPointersCount: %d", count)
	}

	// Read the array
	arrayOff, err := a.mapVATR(ptr)
	if err != nil {
		return nil, fmt.Errorf("map genericMethodPointers array: %w", err)
	}

	pointers := make([]uint64, count)
	for i := int64(0); i < count; i++ {
		pointers[i], err = a.readUInt64At(arrayOff + uint64(i)*8)
		if err != nil {
			return nil, fmt.Errorf("read pointer[%d]: %w", i, err)
		}
	}

	return pointers, nil
}

// FindMetadataRegistration finds the MetadataRegistration structure by scanning
// for typeDefinitionsCount pattern (Il2CppDumper's FindMetadataRegistrationV21)
func (a *IL2CPPStaticAnalyzer) FindMetadataRegistration() (uint64, error) {
	if a.version < 21 {
		return 0, fmt.Errorf("MetadataRegistration search not supported for version %.1f", a.version)
	}

	// Search for typeDefinitionsCount pattern in data sections
	// Layout (v21+):
	//   +80: typeDefinitionsSizesCount (== typeDefinitionsCount)
	//   +88: typeDefinitionsSizes (pointer)
	//   +96: metadataUsagesCount (v19+)
	//   +104: metadataUsages (v19+)

	// We search for: [typeDefinitionsCount][padding][typeDefinitionsCount][pointer valid in data]
	// This is at offset +80 in MetadataRegistration

	typeDefCount := int64(a.typeDefinitionsCount)

	for _, sec := range a.dataSections {
		end := sec.offsetEnd
		if end > uint64(len(a.data)) {
			end = uint64(len(a.data))
		}

		// Scan every 8 bytes (aligned)
		for off := sec.offset; off+24 <= end; off += 8 {
			// Check for typeDefinitionsSizesCount == typeDefinitionsCount
			val1, err := a.readInt64At(off)
			if err != nil || val1 != typeDefCount {
				continue
			}

			// Check next field (typeDefinitionsSizes pointer or padding)
			// Skip 8 bytes and check for another typeDefinitionsCount (this is the metadataUsagesCount if same)
			// Actually the pattern is: fieldOffsetsCount, fieldOffsets, typeDefinitionsSizesCount, typeDefinitionsSizes
			// Let's look for the specific v21 pattern

			// In v21+, the layout around typeDefinitionsSizes is:
			//   +64: fieldOffsetsCount
			//   +72: fieldOffsets
			//   +80: typeDefinitionsSizesCount (== typeDefinitionsCount)
			//   +88: typeDefinitionsSizes

			// We found typeDefinitionsSizesCount at 'off', so MetadataRegistration base = off - 80 (as file offset)
			// But we need to verify by checking the typeDefinitionsSizes pointer

			sizesPtr, err := a.readUInt64At(off + 8)
			if err != nil {
				continue
			}

			// Check if sizesPtr points to valid data section
			sizesPtrOff, err := a.mapVATR(sizesPtr)
			if err != nil {
				continue
			}

			if !a.isInDataSections(sizesPtrOff) {
				continue
			}

			// Calculate the MetadataRegistration VA
			// off is the file offset of typeDefinitionsSizesCount
			// typeDefinitionsSizesCount is at offset 80 (10 * 8) in Il2CppMetadataRegistration
			metaRegFileOff := off - 80
			metaRegVA := sec.address + (metaRegFileOff - sec.offset)

			// Verify by checking earlier fields
			// genericClassesCount should be reasonable
			gcCount, err := a.readInt64At(metaRegFileOff)
			if err != nil || gcCount < 0 || gcCount > 1000000 {
				continue
			}

			// genericMethodTableCount should be reasonable
			gmtCount, err := a.readInt64At(metaRegFileOff + 32)
			if err != nil || gmtCount < 0 || gmtCount > 1000000 {
				continue
			}

			// typesCount should be reasonable
			typesCount, err := a.readInt64At(metaRegFileOff + 48)
			if err != nil || typesCount < 0 || typesCount > 1000000 {
				continue
			}

			a.log("[il2cpp static] MetadataRegistration candidate: gcCount=%d, gmtCount=%d, typesCount=%d\n",
				gcCount, gmtCount, typesCount)

			return metaRegVA, nil
		}
	}

	return 0, fmt.Errorf("MetadataRegistration not found")
}

// isInDataSections checks if a file offset falls within a data section
func (a *IL2CPPStaticAnalyzer) isInDataSections(off uint64) bool {
	for _, sec := range a.dataSections {
		if off >= sec.offset && off < sec.offsetEnd {
			return true
		}
	}
	return false
}

// ReadGenericMethods reads the genericMethodTable and methodSpecs to resolve
// generic method instantiation addresses
func (a *IL2CPPStaticAnalyzer) ReadGenericMethods(metaRegVA uint64, genericMethodPointers []uint64) ([]GenericMethodInfo, error) {
	metaRegOff, err := a.mapVATR(metaRegVA)
	if err != nil {
		return nil, fmt.Errorf("map MetadataRegistration: %w", err)
	}

	// Il2CppMetadataRegistration layout:
	//   +0:  genericClassesCount
	//   +8:  genericClasses
	//   +16: genericInstsCount
	//   +24: genericInsts
	//   +32: genericMethodTableCount
	//   +40: genericMethodTable
	//   +48: typesCount
	//   +56: types
	//   +64: methodSpecsCount
	//   +72: methodSpecs
	//   ... (more fields)

	// Read genericMethodTableCount and pointer
	gmtCount, err := a.readInt64At(metaRegOff + 32)
	if err != nil {
		return nil, fmt.Errorf("read genericMethodTableCount: %w", err)
	}
	gmtPtr, err := a.readUInt64At(metaRegOff + 40)
	if err != nil {
		return nil, fmt.Errorf("read genericMethodTable ptr: %w", err)
	}

	// Read methodSpecsCount and pointer
	msCount, err := a.readInt64At(metaRegOff + 64)
	if err != nil {
		return nil, fmt.Errorf("read methodSpecsCount: %w", err)
	}
	msPtr, err := a.readUInt64At(metaRegOff + 72)
	if err != nil {
		return nil, fmt.Errorf("read methodSpecs ptr: %w", err)
	}

	a.log("[il2cpp static] genericMethodTableCount=%d, methodSpecsCount=%d\n", gmtCount, msCount)

	if gmtCount <= 0 || gmtCount > 1000000 {
		return nil, fmt.Errorf("invalid genericMethodTableCount: %d", gmtCount)
	}
	if msCount <= 0 || msCount > 1000000 {
		return nil, fmt.Errorf("invalid methodSpecsCount: %d", msCount)
	}

	// Read methodSpecs array (Il2CppMethodSpec is 12 bytes: 3 x int32)
	msOff, err := a.mapVATR(msPtr)
	if err != nil {
		return nil, fmt.Errorf("map methodSpecs: %w", err)
	}

	methodSpecs := make([]Il2CppMethodSpec, msCount)
	for i := int64(0); i < msCount; i++ {
		off := msOff + uint64(i)*12
		methodSpecs[i].MethodDefinitionIndex, _ = a.readInt32At(off)
		methodSpecs[i].ClassIndexIndex, _ = a.readInt32At(off + 4)
		methodSpecs[i].MethodIndexIndex, _ = a.readInt32At(off + 8)
	}

	// Read genericMethodTable array
	// Size depends on version: 8 bytes base + 4 extra for v24.5/v27.1+
	gmtOff, err := a.mapVATR(gmtPtr)
	if err != nil {
		return nil, fmt.Errorf("map genericMethodTable: %w", err)
	}

	// Il2CppGenericMethodFunctionsDefinitions structure size
	entrySize := uint64(8) // genericMethodIndex(4) + methodIndex(4) + invokerIndex(4) = 12, but aligned?
	if (a.version >= 24.5 && a.version < 25) || a.version >= 27.1 {
		// Has adjustorThunk field
		entrySize = 16 // 4 + 4 + 4 + 4 = 16
	} else {
		entrySize = 12 // 4 + 4 + 4 = 12
	}

	var genericMethods []GenericMethodInfo
	for i := int64(0); i < gmtCount; i++ {
		off := gmtOff + uint64(i)*entrySize

		genericMethodIndex, _ := a.readInt32At(off)
		methodIndex, _ := a.readInt32At(off + 4)

		if genericMethodIndex < 0 || int64(genericMethodIndex) >= msCount {
			continue
		}
		if methodIndex < 0 || int64(methodIndex) >= int64(len(genericMethodPointers)) {
			continue
		}

		methodSpec := methodSpecs[genericMethodIndex]
		address := genericMethodPointers[methodIndex]

		if address == 0 {
			continue
		}

		genericMethods = append(genericMethods, GenericMethodInfo{
			MethodDefinitionIndex: methodSpec.MethodDefinitionIndex,
			ClassIndexIndex:       methodSpec.ClassIndexIndex,
			MethodIndexIndex:      methodSpec.MethodIndexIndex,
			Address:               address,
		})
	}

	return genericMethods, nil
}

// ReadTypes reads the Il2CppType array from MetadataRegistration
func (a *IL2CPPStaticAnalyzer) ReadTypes(metaRegVA uint64) ([]*Il2CppType, error) {
	metaRegOff, err := a.mapVATR(metaRegVA)
	if err != nil {
		return nil, fmt.Errorf("map MetadataRegistration: %w", err)
	}

	// Il2CppMetadataRegistration layout:
	//   +48: typesCount
	//   +56: types (pointer to array of Il2CppType pointers)

	typesCount, err := a.readInt64At(metaRegOff + 48)
	if err != nil {
		return nil, fmt.Errorf("read typesCount: %w", err)
	}
	typesPtr, err := a.readUInt64At(metaRegOff + 56)
	if err != nil {
		return nil, fmt.Errorf("read types ptr: %w", err)
	}

	a.log("[il2cpp static] typesCount=%d, types=0x%x\n", typesCount, typesPtr)

	if typesCount <= 0 || typesCount > 1000000 {
		return nil, fmt.Errorf("invalid typesCount: %d", typesCount)
	}

	// Read array of pointers to Il2CppType
	typePtrsOff, err := a.mapVATR(typesPtr)
	if err != nil {
		return nil, fmt.Errorf("map types array: %w", err)
	}

	types := make([]*Il2CppType, typesCount)
	for i := int64(0); i < typesCount; i++ {
		typePtr, err := a.readUInt64At(typePtrsOff + uint64(i)*8)
		if err != nil || typePtr == 0 {
			continue
		}

		il2cppType, err := a.readIl2CppType(typePtr)
		if err != nil {
			continue
		}
		types[i] = il2cppType
	}

	return types, nil
}

// readIl2CppType reads a single Il2CppType structure
func (a *IL2CPPStaticAnalyzer) readIl2CppType(va uint64) (*Il2CppType, error) {
	off, err := a.mapVATR(va)
	if err != nil {
		return nil, err
	}

	// Il2CppType layout (12 bytes):
	//   +0: data (uint64) - union: klassIndex, type ptr, etc.
	//   +8: bits (uint32) - packed: attrs(16), type(8), flags(8)
	data, err := a.readUInt64At(off)
	if err != nil {
		return nil, err
	}

	bits, err := a.readUInt32At(off + 8)
	if err != nil {
		return nil, err
	}

	t := &Il2CppType{
		Data:  data,
		Attrs: uint16(bits & 0xFFFF),
		Type:  Il2CppTypeEnum((bits >> 16) & 0xFF),
	}

	// Parse flags based on version
	if a.version >= 27.2 {
		t.NumMods = uint8((bits >> 24) & 0x1F)
		t.Byref = (bits>>29)&1 == 1
		t.Pinned = (bits>>30)&1 == 1
		t.ValueType = (bits >> 31) == 1
	} else {
		t.NumMods = uint8((bits >> 24) & 0x3F)
		t.Byref = (bits>>30)&1 == 1
		t.Pinned = (bits >> 31) == 1
	}

	return t, nil
}

// readUInt32At reads a uint32 from a file offset
func (a *IL2CPPStaticAnalyzer) readUInt32At(off uint64) (uint32, error) {
	if off+4 > uint64(len(a.data)) {
		return 0, fmt.Errorf("read past end of file")
	}
	return binary.LittleEndian.Uint32(a.data[off:]), nil
}

// ReadFieldOffsets reads the fieldOffsets array from MetadataRegistration
func (a *IL2CPPStaticAnalyzer) ReadFieldOffsets(metaRegVA uint64) ([]uint64, error) {
	metaRegOff, err := a.mapVATR(metaRegVA)
	if err != nil {
		return nil, fmt.Errorf("map MetadataRegistration: %w", err)
	}

	// Il2CppMetadataRegistration layout:
	//   +64: fieldOffsetsCount
	//   +72: fieldOffsets (pointer to array)

	count, err := a.readInt64At(metaRegOff + 64)
	if err != nil {
		return nil, fmt.Errorf("read fieldOffsetsCount: %w", err)
	}
	ptr, err := a.readUInt64At(metaRegOff + 72)
	if err != nil {
		return nil, fmt.Errorf("read fieldOffsets ptr: %w", err)
	}

	a.log("[il2cpp static] fieldOffsetsCount=%d, fieldOffsets=0x%x\n", count, ptr)

	if count <= 0 || count > 1000000 {
		return nil, fmt.Errorf("invalid fieldOffsetsCount: %d", count)
	}

	// For v22+, fieldOffsets are pointers to arrays of offsets
	// For v21 and below, they are direct offsets
	arrayOff, err := a.mapVATR(ptr)
	if err != nil {
		return nil, fmt.Errorf("map fieldOffsets array: %w", err)
	}

	offsets := make([]uint64, count)
	for i := int64(0); i < count; i++ {
		offsets[i], _ = a.readUInt64At(arrayOff + uint64(i)*8)
	}

	return offsets, nil
}

// GetIl2CppType reads an Il2CppType from a pointer (used for nested types)
func (a *IL2CPPStaticAnalyzer) GetIl2CppType(ptr uint64) (*Il2CppType, error) {
	return a.readIl2CppType(ptr)
}

// ReadGenericClass reads an Il2CppGenericClass structure
func (a *IL2CPPStaticAnalyzer) ReadGenericClass(ptr uint64) (*Il2CppGenericClass, error) {
	off, err := a.mapVATR(ptr)
	if err != nil {
		return nil, err
	}

	gc := &Il2CppGenericClass{}

	if a.version < 27 {
		// v24.5 and below: has typeDefinitionIndex (int64)
		gc.TypeDefinitionIndex, _ = a.readInt64At(off)
		off += 8
	} else {
		// v27+: has type pointer
		gc.Type, _ = a.readUInt64At(off)
		off += 8
	}

	// Read context (class_inst, method_inst)
	gc.ClassInst, _ = a.readUInt64At(off)
	gc.MethodInst, _ = a.readUInt64At(off + 8)

	return gc, nil
}

// ReadGenericInst reads an Il2CppGenericInst structure
func (a *IL2CPPStaticAnalyzer) ReadGenericInst(ptr uint64) (*Il2CppGenericInst, error) {
	off, err := a.mapVATR(ptr)
	if err != nil {
		return nil, err
	}

	gi := &Il2CppGenericInst{}
	gi.TypeArgc, _ = a.readInt64At(off)

	typeArgvPtr, _ := a.readUInt64At(off + 8)
	if typeArgvPtr != 0 && gi.TypeArgc > 0 && gi.TypeArgc <= 32 {
		argvOff, err := a.mapVATR(typeArgvPtr)
		if err == nil {
			gi.TypeArgv = make([]uint64, gi.TypeArgc)
			for i := int64(0); i < gi.TypeArgc; i++ {
				gi.TypeArgv[i], _ = a.readUInt64At(argvOff + uint64(i)*8)
			}
		}
	}

	return gi, nil
}

// ReadArrayType reads an Il2CppArrayType structure
func (a *IL2CPPStaticAnalyzer) ReadArrayType(ptr uint64) (*Il2CppArrayType, error) {
	off, err := a.mapVATR(ptr)
	if err != nil {
		return nil, err
	}

	at := &Il2CppArrayType{}
	at.EType, _ = a.readUInt64At(off)
	at.Rank = a.data[off+8]
	at.NumSizes = a.data[off+9]
	at.NumLoBounds = a.data[off+10]

	return at, nil
}

// RGCTXDataType represents the type of RGCTX data entry
type RGCTXDataType int32

const (
	RGCTXDataInvalid     RGCTXDataType = 0
	RGCTXDataType_       RGCTXDataType = 1 // Il2CppType*
	RGCTXDataClass       RGCTXDataType = 2 // Il2CppClass*
	RGCTXDataMethod      RGCTXDataType = 3 // MethodInfo*
	RGCTXDataField       RGCTXDataType = 4 // FieldInfo* (rare)
	RGCTXDataArray       RGCTXDataType = 5 // Il2CppClass* (array class)
	RGCTXDataConstrained RGCTXDataType = 6 // Constrained call
)

// RGCTXDefinition represents a single RGCTX entry
type RGCTXDefinition struct {
	Type RGCTXDataType
	Data int32 // Token or index depending on type
}

// RGCTXRange maps a token to a range in the rgctxs array
type RGCTXRange struct {
	Token  uint32
	Start  int32
	Length int32
}

// RGCTXStaticData holds parsed RGCTX information for the entire binary
type RGCTXStaticData struct {
	// TypeRGCTXs maps type definition index to its RGCTX definitions
	TypeRGCTXs map[int][]RGCTXDefinition

	// MethodRGCTXs maps method definition index to its RGCTX definitions
	MethodRGCTXs map[int][]RGCTXDefinition
}

// ReadRGCTXData reads all RGCTX data from CodeGenModules
func (a *IL2CPPStaticAnalyzer) ReadRGCTXData(codeRegVA uint64) (*RGCTXStaticData, error) {
	// Map CodeRegistration VA to file offset
	codeRegOff, err := a.mapVATR(codeRegVA)
	if err != nil {
		return nil, fmt.Errorf("map CodeRegistration: %w", err)
	}

	// Get offset to codeGenModulesCount based on version
	modulesFieldOffset := a.getCodeGenModulesOffset()

	modulesCountOff := codeRegOff + modulesFieldOffset
	modulesCount, err := a.readInt64At(modulesCountOff)
	if err != nil {
		return nil, fmt.Errorf("read modules count: %w", err)
	}

	modulesPtrOff := codeRegOff + modulesFieldOffset + 8
	modulesPtr, err := a.readUInt64At(modulesPtrOff)
	if err != nil {
		return nil, fmt.Errorf("read modules pointer: %w", err)
	}

	if modulesCount <= 0 || modulesCount > 10000 {
		return nil, fmt.Errorf("invalid modules count: %d", modulesCount)
	}

	// Map modules array pointer to file offset
	modulesArrayOff, err := a.mapVATR(modulesPtr)
	if err != nil {
		return nil, fmt.Errorf("map modules array: %w", err)
	}

	result := &RGCTXStaticData{
		TypeRGCTXs:   make(map[int][]RGCTXDefinition),
		MethodRGCTXs: make(map[int][]RGCTXDefinition),
	}

	// Read each module's RGCTX data
	for i := int64(0); i < modulesCount; i++ {
		ptrOff := modulesArrayOff + uint64(i)*8
		modPtr, err := a.readUInt64At(ptrOff)
		if err != nil || modPtr == 0 {
			continue
		}

		a.readModuleRGCTX(modPtr, result)
	}

	a.log("[il2cpp static] Parsed RGCTX for %d types, %d methods\n",
		len(result.TypeRGCTXs), len(result.MethodRGCTXs))
	return result, nil
}

// readModuleRGCTX reads RGCTX data from a single CodeGenModule
func (a *IL2CPPStaticAnalyzer) readModuleRGCTX(modVA uint64, result *RGCTXStaticData) {
	off, err := a.mapVATR(modVA)
	if err != nil {
		return
	}

	// CodeGenModule layout (v27+):
	//   +0x00: moduleName (pointer)
	//   +0x08: methodPointerCount (int64)
	//   +0x10: methodPointers (pointer)
	//   +0x18: adjustorThunkCount (int64) - optional
	//   +0x20: adjustorThunks (pointer) - optional
	//   +0x28: invokerIndices (pointer)
	//   +0x30: reversePInvokeWrapperCount (int64)
	//   +0x38: reversePInvokeWrapperIndices (pointer)
	//   +0x40: rgctxRangesCount (int64)
	//   +0x48: rgctxRanges (pointer)
	//   +0x50: rgctxsCount (int64)
	//   +0x58: rgctxs (pointer)

	// Try different offsets for rgctxRanges/rgctxs based on version
	// For v27+, typically at 0x40/0x48 or 0x30/0x38
	offsets := []uint64{0x40, 0x30, 0x48, 0x50}

	for _, baseOff := range offsets {
		rangesCount, err := a.readInt64At(off + baseOff)
		if err != nil || rangesCount <= 0 || rangesCount > 100000 {
			continue
		}

		rangesPtr, err := a.readUInt64At(off + baseOff + 8)
		if err != nil || rangesPtr == 0 {
			continue
		}

		rgctxsCount, err := a.readInt64At(off + baseOff + 16)
		if err != nil || rgctxsCount <= 0 || rgctxsCount > 1000000 {
			continue
		}

		rgctxsPtr, err := a.readUInt64At(off + baseOff + 24)
		if err != nil || rgctxsPtr == 0 {
			continue
		}

		// Validate by trying to read
		rangesOff, err := a.mapVATR(rangesPtr)
		if err != nil {
			continue
		}

		rgctxsOff, err := a.mapVATR(rgctxsPtr)
		if err != nil {
			continue
		}

		// Read ranges: Il2CppTokenRangePair { token (4), range.start (4), range.length (4) }
		for i := int64(0); i < rangesCount; i++ {
			rOff := rangesOff + uint64(i)*12
			token, _ := a.readUInt32At(rOff)
			start, _ := a.readInt32At(rOff + 4)
			length, _ := a.readInt32At(rOff + 8)

			if start < 0 || length <= 0 || int64(start)+int64(length) > rgctxsCount {
				continue
			}

			// Read RGCTX definitions for this range
			defs := make([]RGCTXDefinition, length)
			for j := int32(0); j < length; j++ {
				defOff := rgctxsOff + uint64(start+j)*8
				typ, _ := a.readInt32At(defOff)
				data, _ := a.readInt32At(defOff + 4)
				defs[j] = RGCTXDefinition{
					Type: RGCTXDataType(typ),
					Data: data,
				}
			}

			// Map token to type/method definition
			tableType := (token >> 24) & 0xFF
			index := int(token & 0x00FFFFFF)

			switch tableType {
			case 0x02: // TypeDef
				result.TypeRGCTXs[index] = defs
			case 0x06: // MethodDef
				result.MethodRGCTXs[index] = defs
			}
		}

		// Found valid RGCTX data, no need to try other offsets
		break
	}
}
