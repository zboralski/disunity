// Package output provides IL2CPP RGCTX (Runtime Generic Context) parsing.
// RGCTX data is stored in the binary (libil2cpp.so), not global-metadata.dat.
//
// For v27+, RGCTX definitions are accessed via:
// - s_Il2CppCodeGenModules -> Il2CppCodeGenModule[] -> rgctxs/rgctxRanges
//
// Each Il2CppRGCTXDefinition contains:
// - type: IL2CPP_RGCTX_DATA_TYPE, IL2CPP_RGCTX_DATA_CLASS, IL2CPP_RGCTX_DATA_METHOD
// - data: Token/index to resolve
package output

import (
	"fmt"

	"disunity/internal/binary"
	"disunity/internal/metadata"
)

// RGCTXData wraps binary.RGCTXStaticData for use in metadata package.
// This provides name resolution using GlobalMetadata.
type RGCTXData struct {
	data *binary.RGCTXStaticData
}

// RGCTXEntry represents a resolved RGCTX entry for code generation
type RGCTXEntry struct {
	Index    int    // Slot index (0-based)
	TypeName string // C type (Il2CppClass*, MethodInfo*, Il2CppType*)
	Name     string // Name for the entry
}

// NewRGCTXData creates an RGCTXData from binary.RGCTXStaticData
func NewRGCTXData(data *binary.RGCTXStaticData) *RGCTXData {
	if data == nil {
		return nil
	}
	return &RGCTXData{data: data}
}

// GetRGCTXForBinary extracts RGCTX data from a binary using the static analyzer.
// This is the preferred method for obtaining RGCTX data.
func GetRGCTXForBinary(binaryPath string, version float64, imageCount, typeDefsCount int) (*RGCTXData, error) {
	analyzer, err := binary.NewIL2CPPStaticAnalyzer(binaryPath, version, imageCount, typeDefsCount, 0)
	if err != nil {
		return nil, fmt.Errorf("create static analyzer: %w", err)
	}
	defer analyzer.Close()

	// Find CodeRegistration
	codeRegVA, err := analyzer.FindCodeRegistration()
	if err != nil {
		return nil, fmt.Errorf("find CodeRegistration: %w", err)
	}

	// Read RGCTX data
	rgctxData, err := analyzer.ReadRGCTXData(codeRegVA)
	if err != nil {
		return nil, fmt.Errorf("read RGCTX data: %w", err)
	}

	return NewRGCTXData(rgctxData), nil
}

// GetRGCTXEntries returns resolved RGCTX entries for a type definition
func (r *RGCTXData) GetRGCTXEntries(typeDefIndex int, meta *metadata.GlobalMetadata) []RGCTXEntry {
	if r == nil || r.data == nil {
		return nil
	}

	defs, ok := r.data.TypeRGCTXs[typeDefIndex]
	if !ok || len(defs) == 0 {
		return nil
	}

	entries := make([]RGCTXEntry, len(defs))
	for i, def := range defs {
		entry := RGCTXEntry{
			Index: i,
		}

		switch def.Type {
		case binary.RGCTXDataType_:
			entry.TypeName = "const Il2CppType*"
			entry.Name = resolveTypeName(meta, def.Data)
		case binary.RGCTXDataClass, binary.RGCTXDataArray:
			entry.TypeName = "Il2CppClass*"
			entry.Name = resolveClassName(meta, def.Data)
		case binary.RGCTXDataMethod:
			entry.TypeName = "const MethodInfo*"
			entry.Name = resolveMethodName(meta, def.Data)
		default:
			entry.TypeName = "void*"
			entry.Name = fmt.Sprintf("unknown_%d", i)
		}

		entries[i] = entry
	}

	return entries
}

// GetMethodRGCTXEntries returns resolved RGCTX entries for a method definition
func (r *RGCTXData) GetMethodRGCTXEntries(methodDefIndex int, meta *metadata.GlobalMetadata) []RGCTXEntry {
	if r == nil || r.data == nil {
		return nil
	}

	defs, ok := r.data.MethodRGCTXs[methodDefIndex]
	if !ok || len(defs) == 0 {
		return nil
	}

	entries := make([]RGCTXEntry, len(defs))
	for i, def := range defs {
		entry := RGCTXEntry{
			Index: i,
		}

		switch def.Type {
		case binary.RGCTXDataType_:
			entry.TypeName = "const Il2CppType*"
			entry.Name = resolveTypeName(meta, def.Data)
		case binary.RGCTXDataClass, binary.RGCTXDataArray:
			entry.TypeName = "Il2CppClass*"
			entry.Name = resolveClassName(meta, def.Data)
		case binary.RGCTXDataMethod:
			entry.TypeName = "const MethodInfo*"
			entry.Name = resolveMethodName(meta, def.Data)
		default:
			entry.TypeName = "void*"
			entry.Name = fmt.Sprintf("unknown_%d", i)
		}

		entries[i] = entry
	}

	return entries
}

// TypeCount returns the number of types with RGCTX data
func (r *RGCTXData) TypeCount() int {
	if r == nil || r.data == nil {
		return 0
	}
	return len(r.data.TypeRGCTXs)
}

// MethodCount returns the number of methods with RGCTX data
func (r *RGCTXData) MethodCount() int {
	if r == nil || r.data == nil {
		return 0
	}
	return len(r.data.MethodRGCTXs)
}

// resolveTypeName resolves a type index to a name
func resolveTypeName(meta *metadata.GlobalMetadata, typeIndex int32) string {
	if typeIndex < 0 || int(typeIndex) >= len(meta.TypeDefinitions) {
		return fmt.Sprintf("Type_%d", typeIndex)
	}
	return sanitizeName(meta.GetTypeName(int(typeIndex)))
}

// resolveClassName resolves a class index to a name
func resolveClassName(meta *metadata.GlobalMetadata, classIndex int32) string {
	if classIndex < 0 || int(classIndex) >= len(meta.TypeDefinitions) {
		return fmt.Sprintf("Class_%d", classIndex)
	}
	return sanitizeName(meta.GetTypeName(int(classIndex)))
}

// resolveMethodName resolves a method index to a name
func resolveMethodName(meta *metadata.GlobalMetadata, methodIndex int32) string {
	if methodIndex < 0 || int(methodIndex) >= len(meta.MethodDefinitions) {
		return fmt.Sprintf("Method_%d", methodIndex)
	}
	return sanitizeName(meta.GetMethodName(int(methodIndex)))
}

// sanitizeName converts a name to a valid C identifier
func sanitizeName(name string) string {
	if name == "" {
		return "unnamed"
	}
	// Replace invalid characters
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			result = append(result, c)
		} else if c == '.' || c == '<' || c == '>' || c == ',' || c == ' ' || c == '/' || c == '`' {
			result = append(result, '_')
		}
	}
	return string(result)
}
