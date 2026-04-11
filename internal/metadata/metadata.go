// Package metadata provides parsing for Unity IL2CPP global-metadata.dat files.
// This file contains method/type names that map to native code addresses.
package metadata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// ErrMetadataEncrypted is returned when the metadata file is encrypted.
// Some protection systems like FairGuard encrypt global-metadata.dat.
// The EncryptedMagic field contains the actual (encrypted) magic bytes.
var ErrMetadataEncrypted = errors.New("metadata is encrypted")

// EncryptedMetadataError provides details about encrypted metadata.
type EncryptedMetadataError struct {
	EncryptedMagic uint32
	Path           string
}

func (e *EncryptedMetadataError) Error() string {
	return fmt.Sprintf("metadata is encrypted: magic=0x%08X (expected 0x%08X), path=%s",
		e.EncryptedMagic, MetadataMagic, e.Path)
}

func (e *EncryptedMetadataError) Is(target error) bool {
	return target == ErrMetadataEncrypted
}

// IsEncrypted checks if a metadata file is encrypted.
// Returns true if the magic bytes don't match the expected value.
func IsEncrypted(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	return magic != MetadataMagic
}

// IsEncryptedFile checks if a metadata file on disk is encrypted.
func IsEncryptedFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false, err
	}

	m := binary.LittleEndian.Uint32(magic[:])
	return m != MetadataMagic, nil
}

// GlobalMetadata represents a parsed global-metadata.dat file
type GlobalMetadata struct {
	Header *Header

	// String tables
	Strings        []byte // Metadata strings (type/method names)
	StringLiterals []byte // String literals used in code

	// Definition arrays
	TypeDefinitions      []*TypeDefinition
	MethodDefinitions    []*MethodDefinition
	ImageDefinitions     []*ImageDefinition
	FieldDefinitions     []*FieldDefinition
	ParameterDefinitions []*ParameterDefinition
	PropertyDefinitions  []*PropertyDefinition
	EventDefinitions     []*EventDefinition
	GenericContainers    []*GenericContainer
	GenericParameters    []*GenericParameter

	// VTable method indices (encoded method references)
	VTableMethodIndices []uint32

	// Cached lookup: type definition index -> image index
	typeToImage []int

	// Raw data for future parsing
	rawData []byte
}

// Header represents the Il2CppGlobalMetadataHeader
// Field order varies by version - this struct contains all possible fields
// and parseHeader populates them based on detected version
type Header struct {
	Magic   uint32 // 0xFAB11BAF
	Version int32

	// String tables
	StringLiteralOffset     uint32
	StringLiteralSize       uint32
	StringLiteralDataOffset uint32
	StringLiteralDataSize   uint32
	StringOffset            uint32
	StringSize              uint32

	// Events
	EventsOffset uint32
	EventsSize   uint32

	// Properties
	PropertiesOffset uint32
	PropertiesSize   uint32

	// Methods
	MethodsOffset uint32
	MethodsSize   uint32

	// Parameter default values (v24.2+)
	ParameterDefaultValuesOffset uint32
	ParameterDefaultValuesSize   uint32

	// Field default values (v24.2+)
	FieldDefaultValuesOffset uint32
	FieldDefaultValuesSize   uint32

	// Field and parameter default value data (v24.2+)
	FieldAndParameterDefaultValueDataOffset uint32
	FieldAndParameterDefaultValueDataSize   uint32

	// Field marshaled sizes (v24.2+)
	FieldMarshaledSizesOffset uint32
	FieldMarshaledSizesSize   uint32

	// Parameters
	ParametersOffset uint32
	ParametersSize   uint32

	// Fields
	FieldsOffset uint32
	FieldsSize   uint32

	// Generic parameters
	GenericParametersOffset uint32
	GenericParametersSize   uint32

	// Generic constraints
	GenericParameterConstraintsOffset uint32
	GenericParameterConstraintsSize   uint32

	// Generic containers
	GenericContainersOffset uint32
	GenericContainersSize   uint32

	// Nested types
	NestedTypesOffset uint32
	NestedTypesSize   uint32

	// Interfaces
	InterfacesOffset uint32
	InterfacesSize   uint32

	// Vtable methods
	VTableMethodsOffset uint32
	VTableMethodsSize   uint32

	// Interface offsets (pair of type/interface indices)
	InterfaceOffsetsOffset uint32
	InterfaceOffsetsSize   uint32

	// Type definitions - the main array we need
	TypeDefinitionsOffset uint32
	TypeDefinitionsSize   uint32

	// RGCTX entries (v24.1 and earlier only)
	RGCTXEntriesOffset uint32
	RGCTXEntriesCount  uint32

	// Images (assemblies)
	ImagesOffset uint32
	ImagesSize   uint32

	// Assemblies
	AssembliesOffset uint32
	AssembliesSize   uint32

	// Metadata usage lists (v19-v24.5)
	MetadataUsageListsOffset uint32
	MetadataUsageListsCount  uint32

	// Metadata usage pairs (v19-v24.5)
	MetadataUsagePairsOffset uint32
	MetadataUsagePairsCount  uint32

	// Field refs
	FieldRefsOffset uint32
	FieldRefsSize   uint32

	// Referenced assemblies
	ReferencedAssembliesOffset uint32
	ReferencedAssembliesSize   uint32

	// Attribute info (v21-v27.2)
	AttributesInfoOffset uint32
	AttributesInfoCount  uint32

	// Attribute types (v21-v27.2)
	AttributeTypesOffset uint32
	AttributeTypesCount  uint32

	// Attribute data (v29+)
	AttributeDataOffset uint32
	AttributeDataSize   uint32

	// Attribute data ranges (v29+)
	AttributeDataRangeOffset uint32
	AttributeDataRangeSize   uint32

	// Unresolved virtual call parameters (v22+)
	UnresolvedVirtualCallParameterTypesOffset  uint32
	UnresolvedVirtualCallParameterTypesSize    uint32
	UnresolvedVirtualCallParameterRangesOffset uint32
	UnresolvedVirtualCallParameterRangesSize   uint32

	// Windows runtime type names (v23+)
	WindowsRuntimeTypeNamesOffset uint32
	WindowsRuntimeTypeNamesSize   uint32

	// Windows runtime strings (v27+)
	WindowsRuntimeStringsOffset uint32
	WindowsRuntimeStringsSize   uint32

	// Exported type definitions (v24+)
	ExportedTypeDefinitionsOffset uint32
	ExportedTypeDefinitionsSize   uint32

	// Detected version for parsing (may differ from Version field)
	// e.g., v24.2 when Version=24 but stringLiteralOffset==264
	DetectedVersion float64
}

// TypeDefinition represents Il2CppTypeDefinition
type TypeDefinition struct {
	NameIndex      int32 // Index into string table
	NamespaceIndex int32 // Index into string table
	ByvalTypeIndex int32
	DeclaringTypeIndex int32
	ParentIndex    int32
	ElementTypeIndex int32
	GenericContainerIndex int32

	Flags     uint32
	FieldStart int32
	MethodStart int32
	EventStart int32
	PropertyStart int32
	NestedTypesStart int32
	InterfacesStart int32
	VtableStart int32
	InterfaceOffsetsStart int32

	MethodCount      uint16
	PropertyCount    uint16
	FieldCount       uint16
	EventCount       uint16
	NestedTypesCount uint16
	VtableCount      uint16
	InterfacesCount  uint16
	InterfaceOffsetsCount uint16

	BitField uint32
	Token    uint32
}

// MethodDefinition represents Il2CppMethodDefinition
type MethodDefinition struct {
	NameIndex             int32 // Index into string table
	DeclaringTypeIndex    int32 // Index into TypeDefinitions
	ReturnTypeIndex       int32
	ParameterStart        int32
	GenericContainerIndex int32
	Token                 uint32 // Method token (low 24 bits = index into method pointers)
	Flags                 uint16
	IFlags                uint16
	Slot                  uint16
	ParameterCount        uint16
}

// ImageDefinition represents Il2CppImageDefinition
type ImageDefinition struct {
	NameIndex              int32  // Index into string table (assembly name)
	AssemblyIndex          int32
	TypeStart              int32  // First type index in this assembly
	TypeCount              uint32 // Number of types in this assembly
	ExportedTypeStart      int32
	ExportedTypeCount      uint32
	EntryPointIndex        int32
	Token                  uint32
	CustomAttributeStart   int32
	CustomAttributeCount   uint32
}

// FieldDefinition represents Il2CppFieldDefinition
type FieldDefinition struct {
	NameIndex int32  // Index into string table
	TypeIndex int32  // Index into Il2CppType array (in binary)
	Token     uint32 // Field token (v19+)
}

// ParameterDefinition represents Il2CppParameterDefinition
type ParameterDefinition struct {
	NameIndex int32  // Index into string table
	Token     uint32 // Parameter token
	TypeIndex int32  // Index into Il2CppType array (in binary)
}

// PropertyDefinition represents Il2CppPropertyDefinition
type PropertyDefinition struct {
	NameIndex int32  // Index into string table
	Get       int32  // Getter method index (-1 if none)
	Set       int32  // Setter method index (-1 if none)
	Attrs     uint32 // Property attributes
	Token     uint32 // Property token (v19+)
}

// EventDefinition represents Il2CppEventDefinition
type EventDefinition struct {
	NameIndex int32  // Index into string table
	TypeIndex int32  // Event handler type
	Add       int32  // Add method index
	Remove    int32  // Remove method index
	Raise     int32  // Raise method index
	Token     uint32 // Event token (v19+)
}

// GenericContainer represents Il2CppGenericContainer
type GenericContainer struct {
	OwnerIndex            int32 // Type or method index
	TypeArgc              int32 // Number of type parameters
	IsMethod              int32 // 1 if generic method, 0 if type
	GenericParameterStart int32 // Start index in genericParameters
}

// GenericParameter represents Il2CppGenericParameter
type GenericParameter struct {
	OwnerIndex       int32  // Type or method index
	NameIndex        uint32 // Index into string table (e.g., "T")
	ConstraintsStart int16
	ConstraintsCount int16
	Num              uint16 // Parameter index (0 for T, 1 for U, etc.)
	Flags            uint16
}

// Magic value for global-metadata.dat
const MetadataMagic = 0xFAB11BAF

// ParseFile parses a global-metadata.dat file from disk
func ParseFile(path string) (*GlobalMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	meta, err := Parse(data)
	if err != nil {
		// Wrap encrypted error with path info
		var encErr *EncryptedMetadataError
		if errors.As(err, &encErr) {
			encErr.Path = path
		}
		return nil, err
	}
	return meta, nil
}

// Parse parses global-metadata.dat from a byte slice
func Parse(data []byte) (*GlobalMetadata, error) {
	if len(data) < 264 { // Minimum header size
		return nil, fmt.Errorf("file too small: %d bytes", len(data))
	}

	// Check magic
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != MetadataMagic {
		// Return specific error for encrypted metadata
		return nil, &EncryptedMetadataError{EncryptedMagic: magic}
	}

	version := int32(binary.LittleEndian.Uint32(data[4:8]))
	if version < 24 || version > 31 {
		return nil, fmt.Errorf("unsupported metadata version: %d (supported: 24-31)", version)
	}

	meta := &GlobalMetadata{
		Header:  parseHeader(data, version),
		rawData: data,
	}

	// Extract string tables
	if err := meta.parseStrings(); err != nil {
		return nil, fmt.Errorf("parse strings: %w", err)
	}

	// Parse type definitions
	if err := meta.parseTypeDefinitions(); err != nil {
		return nil, fmt.Errorf("parse type definitions: %w", err)
	}

	// Parse method definitions
	if err := meta.parseMethodDefinitions(); err != nil {
		return nil, fmt.Errorf("parse method definitions: %w", err)
	}

	// Parse image definitions
	if err := meta.parseImageDefinitions(); err != nil {
		return nil, fmt.Errorf("parse image definitions: %w", err)
	}

	// Parse field definitions
	if err := meta.parseFieldDefinitions(); err != nil {
		return nil, fmt.Errorf("parse field definitions: %w", err)
	}

	// Parse parameter definitions
	if err := meta.parseParameterDefinitions(); err != nil {
		return nil, fmt.Errorf("parse parameter definitions: %w", err)
	}

	// Parse property definitions
	if err := meta.parsePropertyDefinitions(); err != nil {
		return nil, fmt.Errorf("parse property definitions: %w", err)
	}

	// Parse event definitions
	if err := meta.parseEventDefinitions(); err != nil {
		return nil, fmt.Errorf("parse event definitions: %w", err)
	}

	// Parse generic containers
	if err := meta.parseGenericContainers(); err != nil {
		return nil, fmt.Errorf("parse generic containers: %w", err)
	}

	// Parse generic parameters
	if err := meta.parseGenericParameters(); err != nil {
		return nil, fmt.Errorf("parse generic parameters: %w", err)
	}

	// Parse vtable method indices
	if err := meta.parseVTableMethods(); err != nil {
		return nil, fmt.Errorf("parse vtable methods: %w", err)
	}

	return meta, nil
}

// parseHeader reads the metadata header
// Header layout varies significantly by version - see IL2CppDumper's MetadataClass.cs
func parseHeader(data []byte, version int32) *Header {
	h := &Header{
		Magic:           binary.LittleEndian.Uint32(data[0:4]),
		Version:         version,
		DetectedVersion: float64(version),
	}

	// Read initial fields to detect v24 subversions
	h.StringLiteralOffset = binary.LittleEndian.Uint32(data[8:12])
	h.StringLiteralSize = binary.LittleEndian.Uint32(data[12:16])
	h.StringLiteralDataOffset = binary.LittleEndian.Uint32(data[16:20])
	h.StringLiteralDataSize = binary.LittleEndian.Uint32(data[20:24])
	h.StringOffset = binary.LittleEndian.Uint32(data[24:28])
	h.StringSize = binary.LittleEndian.Uint32(data[28:32])
	h.EventsOffset = binary.LittleEndian.Uint32(data[32:36])
	h.EventsSize = binary.LittleEndian.Uint32(data[36:40])
	h.PropertiesOffset = binary.LittleEndian.Uint32(data[40:44])
	h.PropertiesSize = binary.LittleEndian.Uint32(data[44:48])
	h.MethodsOffset = binary.LittleEndian.Uint32(data[48:52])
	h.MethodsSize = binary.LittleEndian.Uint32(data[52:56])

	// Version 24 detection: v24.2+ has a larger header (264+ bytes before
	// string data). The stringLiteralOffset tells us the header size.
	if version == 24 {
		if h.StringLiteralOffset >= 264 {
			h.DetectedVersion = 24.2
		}
	}

	// Parse remaining fields based on detected version
	if h.DetectedVersion >= 24.2 {
		// v24.2+ has additional fields after methods
		h.ParameterDefaultValuesOffset = binary.LittleEndian.Uint32(data[56:60])
		h.ParameterDefaultValuesSize = binary.LittleEndian.Uint32(data[60:64])
		h.FieldDefaultValuesOffset = binary.LittleEndian.Uint32(data[64:68])
		h.FieldDefaultValuesSize = binary.LittleEndian.Uint32(data[68:72])
		h.FieldAndParameterDefaultValueDataOffset = binary.LittleEndian.Uint32(data[72:76])
		h.FieldAndParameterDefaultValueDataSize = binary.LittleEndian.Uint32(data[76:80])
		h.FieldMarshaledSizesOffset = binary.LittleEndian.Uint32(data[80:84])
		h.FieldMarshaledSizesSize = binary.LittleEndian.Uint32(data[84:88])
		h.ParametersOffset = binary.LittleEndian.Uint32(data[88:92])
		h.ParametersSize = binary.LittleEndian.Uint32(data[92:96])
		h.FieldsOffset = binary.LittleEndian.Uint32(data[96:100])
		h.FieldsSize = binary.LittleEndian.Uint32(data[100:104])
		h.GenericParametersOffset = binary.LittleEndian.Uint32(data[104:108])
		h.GenericParametersSize = binary.LittleEndian.Uint32(data[108:112])
		h.GenericParameterConstraintsOffset = binary.LittleEndian.Uint32(data[112:116])
		h.GenericParameterConstraintsSize = binary.LittleEndian.Uint32(data[116:120])
		h.GenericContainersOffset = binary.LittleEndian.Uint32(data[120:124])
		h.GenericContainersSize = binary.LittleEndian.Uint32(data[124:128])
		h.NestedTypesOffset = binary.LittleEndian.Uint32(data[128:132])
		h.NestedTypesSize = binary.LittleEndian.Uint32(data[132:136])
		h.InterfacesOffset = binary.LittleEndian.Uint32(data[136:140])
		h.InterfacesSize = binary.LittleEndian.Uint32(data[140:144])
		h.VTableMethodsOffset = binary.LittleEndian.Uint32(data[144:148])
		h.VTableMethodsSize = binary.LittleEndian.Uint32(data[148:152])
		h.InterfaceOffsetsOffset = binary.LittleEndian.Uint32(data[152:156])
		h.InterfaceOffsetsSize = binary.LittleEndian.Uint32(data[156:160])
		h.TypeDefinitionsOffset = binary.LittleEndian.Uint32(data[160:164])
		h.TypeDefinitionsSize = binary.LittleEndian.Uint32(data[164:168])

		// v24.x has RGCTX entries before images
		pos := 168
		if version == 24 {
			h.RGCTXEntriesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
			h.RGCTXEntriesCount = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			pos += 8
		}

		h.ImagesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
		h.ImagesSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
		pos += 8
		h.AssembliesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
		h.AssembliesSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
		pos += 8

		// v24-v26 has metadata usage lists/pairs and other tables
		if h.DetectedVersion < 27 {
			h.MetadataUsageListsOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
			h.MetadataUsageListsCount = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			pos += 8
			h.MetadataUsagePairsOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
			h.MetadataUsagePairsCount = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			pos += 8
			h.FieldRefsOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
			h.FieldRefsSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			pos += 8
			h.ReferencedAssembliesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
			h.ReferencedAssembliesSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			pos += 8
			h.AttributesInfoOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
			h.AttributesInfoCount = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			pos += 8
			h.AttributeTypesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
			h.AttributeTypesCount = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			pos += 8

			if len(data) >= pos+16 {
				h.UnresolvedVirtualCallParameterTypesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
				h.UnresolvedVirtualCallParameterTypesSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
				pos += 8
				h.UnresolvedVirtualCallParameterRangesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
				h.UnresolvedVirtualCallParameterRangesSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
				pos += 8
			}
			if len(data) >= pos+8 {
				h.WindowsRuntimeTypeNamesOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
				h.WindowsRuntimeTypeNamesSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
				pos += 8
			}
			if len(data) >= pos+8 {
				h.ExportedTypeDefinitionsOffset = binary.LittleEndian.Uint32(data[pos : pos+4])
				h.ExportedTypeDefinitionsSize = binary.LittleEndian.Uint32(data[pos+4 : pos+8])
			}
		}
	} else {
		// Pre-v24.2 layout (v24.0, v24.1)
		// Parameters come right after methods (no default value fields)
		h.ParametersOffset = binary.LittleEndian.Uint32(data[56:60])
		h.ParametersSize = binary.LittleEndian.Uint32(data[60:64])
		h.FieldsOffset = binary.LittleEndian.Uint32(data[64:68])
		h.FieldsSize = binary.LittleEndian.Uint32(data[68:72])
		h.GenericParametersOffset = binary.LittleEndian.Uint32(data[72:76])
		h.GenericParametersSize = binary.LittleEndian.Uint32(data[76:80])
		h.GenericParameterConstraintsOffset = binary.LittleEndian.Uint32(data[80:84])
		h.GenericParameterConstraintsSize = binary.LittleEndian.Uint32(data[84:88])
		h.GenericContainersOffset = binary.LittleEndian.Uint32(data[88:92])
		h.GenericContainersSize = binary.LittleEndian.Uint32(data[92:96])
		h.NestedTypesOffset = binary.LittleEndian.Uint32(data[96:100])
		h.NestedTypesSize = binary.LittleEndian.Uint32(data[100:104])
		h.InterfacesOffset = binary.LittleEndian.Uint32(data[104:108])
		h.InterfacesSize = binary.LittleEndian.Uint32(data[108:112])
		h.VTableMethodsOffset = binary.LittleEndian.Uint32(data[112:116])
		h.VTableMethodsSize = binary.LittleEndian.Uint32(data[116:120])
		h.InterfaceOffsetsOffset = binary.LittleEndian.Uint32(data[120:124])
		h.InterfaceOffsetsSize = binary.LittleEndian.Uint32(data[124:128])
		h.TypeDefinitionsOffset = binary.LittleEndian.Uint32(data[128:132])
		h.TypeDefinitionsSize = binary.LittleEndian.Uint32(data[132:136])

		// v24.0 has no RGCTX entries; v24.1 inserts RGCTX before images.
		// Auto-detect: try v24.0 layout (images@136) first. If the first
		// image entry has a valid nameIdx, use v24.0. Otherwise try v24.1.
		imgOff0 := binary.LittleEndian.Uint32(data[136:140])
		if imgOff0 > 0 && imgOff0+4 <= uint32(len(data)) {
			nameIdx := int32(binary.LittleEndian.Uint32(data[imgOff0 : imgOff0+4]))
			if nameIdx >= 0 && int(nameIdx) < int(h.StringSize) {
				// v24.0: no RGCTX, images at offset 136
				h.ImagesOffset = imgOff0
				h.ImagesSize = binary.LittleEndian.Uint32(data[140:144])
				h.AssembliesOffset = binary.LittleEndian.Uint32(data[144:148])
				h.AssembliesSize = binary.LittleEndian.Uint32(data[148:152])
			} else {
				// v24.1: RGCTX entries at 136, images at 144
				h.DetectedVersion = 24.1
				h.RGCTXEntriesOffset = binary.LittleEndian.Uint32(data[136:140])
				h.RGCTXEntriesCount = binary.LittleEndian.Uint32(data[140:144])
				h.ImagesOffset = binary.LittleEndian.Uint32(data[144:148])
				h.ImagesSize = binary.LittleEndian.Uint32(data[148:152])
				h.AssembliesOffset = binary.LittleEndian.Uint32(data[152:156])
				h.AssembliesSize = binary.LittleEndian.Uint32(data[156:160])
			}
		}
	}

	return h
}

// parseStrings extracts the string tables
func (m *GlobalMetadata) parseStrings() error {
	h := m.Header
	fsize := uint32(len(m.rawData))

	// Metadata strings (type/method names)
	if h.StringOffset > 0 && h.StringSize > 0 {
		if h.StringOffset >= fsize {
			return fmt.Errorf("strings table offset beyond file (%d >= %d)", h.StringOffset, fsize)
		}
		end := h.StringOffset + h.StringSize
		if end > fsize {
			end = fsize // clamp to available data
		}
		m.Strings = m.rawData[h.StringOffset:end]
	}

	// String literals
	if h.StringLiteralDataOffset > 0 && h.StringLiteralDataSize > 0 {
		if h.StringLiteralDataOffset >= fsize {
			return fmt.Errorf("string literal table offset beyond file (%d >= %d)", h.StringLiteralDataOffset, fsize)
		}
		end := h.StringLiteralDataOffset + h.StringLiteralDataSize
		if end > fsize {
			end = fsize // clamp to available data
		}
		m.StringLiterals = m.rawData[h.StringLiteralDataOffset:end]
	}

	return nil
}

// GetString reads a null-terminated string from the string table
func (m *GlobalMetadata) GetString(index int32) string {
	if index < 0 || int(index) >= len(m.Strings) {
		return ""
	}

	// Find null terminator
	start := int(index)
	end := start
	for end < len(m.Strings) && m.Strings[end] != 0 {
		end++
		// Reasonable max length
		if end-start > 512 {
			break
		}
	}

	return string(m.Strings[start:end])
}

// detectTypeDefSize detects the size of Il2CppTypeDefinition based on version
func (m *GlobalMetadata) detectTypeDefSize() int {
	// TypeDefinition sizes vary by version:
	// v24.0-24.1: ~100+ bytes (has customAttributeIndex, byrefTypeIndex, rgctx fields)
	// v24.2-24.5: 92 bytes (has byrefTypeIndex but no customAttribute/rgctx)
	// v25-30: 76-88 bytes
	// v31+: varies
	//
	// Test sizes from largest to smallest since larger structs are more common in earlier versions
	sizes := []int{92, 88, 84, 80, 76}

	h := m.Header
	if h.TypeDefinitionsSize == 0 {
		return 92 // Default for v24.2
	}

	data := m.rawData[h.TypeDefinitionsOffset:]
	totalSize := h.TypeDefinitionsSize

	for _, size := range sizes {
		if totalSize%uint32(size) != 0 {
			continue
		}

		count := int(totalSize) / size
		if count < 1 || count > 200000 {
			continue
		}

		// Validate first few entries have reasonable string indices
		valid := true
		for i := 0; i < min(10, count); i++ {
			offset := i * size
			if offset+8 > len(data) {
				valid = false
				break
			}
			nameIdx := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
			nsIdx := int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))

			// Check if indices are within string table bounds
			if nameIdx < 0 || int(nameIdx) >= len(m.Strings) {
				valid = false
				break
			}
			if nsIdx < 0 || int(nsIdx) >= len(m.Strings) {
				valid = false
				break
			}
		}

		if valid {
			return size
		}
	}

	return 92 // Default for v24.2
}

// parseTypeDefinitions parses the type definition array
func (m *GlobalMetadata) parseTypeDefinitions() error {
	h := m.Header
	if h.TypeDefinitionsSize == 0 {
		return nil
	}

	structSize := m.detectTypeDefSize()
	count := int(h.TypeDefinitionsSize) / structSize
	if count <= 0 || count > 200000 {
		return fmt.Errorf("invalid type definition count: %d (size=%d)", count, structSize)
	}

	data := m.rawData[h.TypeDefinitionsOffset:]
	m.TypeDefinitions = make([]*TypeDefinition, count)

	// TypeDefinition layout varies by version:
	//
	// v24.2-24.5 (92 bytes with byrefTypeIndex):
	// 0-3: nameIndex, 4-7: namespaceIndex, 8-11: byvalTypeIndex, 12-15: byrefTypeIndex
	// 16-19: declaringTypeIndex, 20-23: parentIndex, 24-27: elementTypeIndex
	// 28-31: genericContainerIndex, 32-35: flags
	// 36-39: fieldStart, 40-43: methodStart, 44-47: eventStart, 48-51: propertyStart
	// 52-55: nestedTypesStart, 56-59: interfacesStart, 60-63: vtableStart, 64-67: interfaceOffsetsStart
	// 68-75: counts (method, property, field, event)
	// 76-83: counts (nested, vtable, interfaces, interfaceOffsets)
	// 84-87: bitfield, 88-91: token
	//
	// v27+ (88 bytes, NO byrefTypeIndex):
	// 0-3: nameIndex, 4-7: namespaceIndex, 8-11: byvalTypeIndex
	// 12-15: declaringTypeIndex, 16-19: parentIndex, 20-23: elementTypeIndex
	// 24-27: genericContainerIndex, 28-31: flags
	// 32-35: fieldStart, 36-39: methodStart, 40-43: eventStart, 44-47: propertyStart
	// 48-51: nestedTypesStart, 52-55: interfacesStart, 56-59: vtableStart, 60-63: interfaceOffsetsStart
	// 64-71: counts (method, property, field, event)
	// 72-79: counts (nested, vtable, interfaces, interfaceOffsets)
	// 80-83: bitfield, 84-87: token

	// Determine if byrefTypeIndex exists (v24.5 and below)
	hasByrefTypeIndex := h.Version <= 24 || (h.Version == 24 && h.DetectedVersion <= 24.5)

	for i := 0; i < count; i++ {
		off := i * structSize
		if off+structSize > len(data) {
			break
		}

		td := &TypeDefinition{
			NameIndex:      int32(binary.LittleEndian.Uint32(data[off : off+4])),
			NamespaceIndex: int32(binary.LittleEndian.Uint32(data[off+4 : off+8])),
		}

		// Parse fields with version-aware offsets
		if structSize >= 12 {
			td.ByvalTypeIndex = int32(binary.LittleEndian.Uint32(data[off+8 : off+12]))
		}

		// Calculate base offset for fields after byvalTypeIndex
		// v24.5 and below: byrefTypeIndex at 12, declaringTypeIndex at 16
		// v27+: no byrefTypeIndex, declaringTypeIndex at 12
		baseOff := 12
		if hasByrefTypeIndex {
			baseOff = 16 // Skip byrefTypeIndex
		}

		if structSize >= baseOff+8 {
			td.DeclaringTypeIndex = int32(binary.LittleEndian.Uint32(data[off+baseOff : off+baseOff+4]))
			td.ParentIndex = int32(binary.LittleEndian.Uint32(data[off+baseOff+4 : off+baseOff+8]))
		}
		if structSize >= baseOff+16 {
			td.ElementTypeIndex = int32(binary.LittleEndian.Uint32(data[off+baseOff+8 : off+baseOff+12]))
			td.GenericContainerIndex = int32(binary.LittleEndian.Uint32(data[off+baseOff+12 : off+baseOff+16]))
		}
		if structSize >= baseOff+20 {
			td.Flags = binary.LittleEndian.Uint32(data[off+baseOff+16 : off+baseOff+20])
		}
		if structSize >= baseOff+40 {
			td.FieldStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+20 : off+baseOff+24]))
			td.MethodStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+24 : off+baseOff+28]))
			td.EventStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+28 : off+baseOff+32]))
			td.PropertyStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+32 : off+baseOff+36]))
			td.NestedTypesStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+36 : off+baseOff+40]))
		}
		if structSize >= baseOff+52 {
			td.InterfacesStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+40 : off+baseOff+44]))
			td.VtableStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+44 : off+baseOff+48]))
			td.InterfaceOffsetsStart = int32(binary.LittleEndian.Uint32(data[off+baseOff+48 : off+baseOff+52]))
		}
		if structSize >= baseOff+60 {
			td.MethodCount = binary.LittleEndian.Uint16(data[off+baseOff+52 : off+baseOff+54])
			td.PropertyCount = binary.LittleEndian.Uint16(data[off+baseOff+54 : off+baseOff+56])
			td.FieldCount = binary.LittleEndian.Uint16(data[off+baseOff+56 : off+baseOff+58])
			td.EventCount = binary.LittleEndian.Uint16(data[off+baseOff+58 : off+baseOff+60])
		}
		if structSize >= baseOff+68 {
			td.NestedTypesCount = binary.LittleEndian.Uint16(data[off+baseOff+60 : off+baseOff+62])
			td.VtableCount = binary.LittleEndian.Uint16(data[off+baseOff+62 : off+baseOff+64])
			td.InterfacesCount = binary.LittleEndian.Uint16(data[off+baseOff+64 : off+baseOff+66])
			td.InterfaceOffsetsCount = binary.LittleEndian.Uint16(data[off+baseOff+66 : off+baseOff+68])
		}
		if structSize >= baseOff+72 {
			td.BitField = binary.LittleEndian.Uint32(data[off+baseOff+68 : off+baseOff+72])
		}
		if structSize >= baseOff+76 {
			td.Token = binary.LittleEndian.Uint32(data[off+baseOff+72 : off+baseOff+76])
		}

		m.TypeDefinitions[i] = td
	}

	return nil
}

// detectMethodDefSize detects the size of Il2CppMethodDefinition
func (m *GlobalMetadata) detectMethodDefSize() int {
	// v24.1: 44 bytes (with methodIndex, invokerIndex, etc.)
	// v24.2-30: 32 bytes
	// v31+: 36 bytes (with returnParameterToken)
	sizes := []int{32, 36, 44}

	h := m.Header
	if h.MethodsSize == 0 {
		return 32 // Default
	}

	data := m.rawData[h.MethodsOffset:]
	totalSize := h.MethodsSize

	for _, size := range sizes {
		if totalSize%uint32(size) != 0 {
			continue
		}

		count := int(totalSize) / size
		if count < 1 || count > 500000 {
			continue
		}

		// Validate first few entries
		valid := true
		for i := 0; i < min(10, count); i++ {
			offset := i * size
			if offset+8 > len(data) {
				valid = false
				break
			}
			nameIdx := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
			declTypeIdx := int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))

			// Name index must be valid
			if nameIdx < 0 || int(nameIdx) >= len(m.Strings) {
				valid = false
				break
			}
			// Declaring type must be valid (can be -1 for global functions)
			if declTypeIdx < -1 || int(declTypeIdx) >= len(m.TypeDefinitions) {
				valid = false
				break
			}
		}

		if valid {
			return size
		}
	}

	return 32 // Default
}

// parseMethodDefinitions parses the method definition array
func (m *GlobalMetadata) parseMethodDefinitions() error {
	h := m.Header
	if h.MethodsSize == 0 {
		return nil
	}

	structSize := m.detectMethodDefSize()
	count := int(h.MethodsSize) / structSize
	if count <= 0 || count > 500000 {
		return fmt.Errorf("invalid method definition count: %d (size=%d)", count, structSize)
	}

	data := m.rawData[h.MethodsOffset:]
	m.MethodDefinitions = make([]*MethodDefinition, count)

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		// v31+ inserts returnParameterToken (4 bytes) after returnType,
		// shifting parameterStart..parameterCount forward by 4 bytes.
		extra := 0
		if structSize == 36 {
			extra = 4
		}

		md := &MethodDefinition{
			NameIndex:             int32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			DeclaringTypeIndex:    int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			ReturnTypeIndex:       int32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			ParameterStart:        int32(binary.LittleEndian.Uint32(data[offset+12+extra : offset+16+extra])),
			GenericContainerIndex: int32(binary.LittleEndian.Uint32(data[offset+16+extra : offset+20+extra])),
			Token:                 binary.LittleEndian.Uint32(data[offset+20+extra : offset+24+extra]),
			Flags:                 binary.LittleEndian.Uint16(data[offset+24+extra : offset+26+extra]),
			IFlags:                binary.LittleEndian.Uint16(data[offset+26+extra : offset+28+extra]),
			Slot:                  binary.LittleEndian.Uint16(data[offset+28+extra : offset+30+extra]),
			ParameterCount:        binary.LittleEndian.Uint16(data[offset+30+extra : offset+32+extra]),
		}

		m.MethodDefinitions[i] = md
	}

	return nil
}

// parseImageDefinitions parses the image (assembly) definitions
func (m *GlobalMetadata) parseImageDefinitions() error {
	h := m.Header
	if h.ImagesSize == 0 {
		return nil
	}

	// Image definition size varies by version:
	// v24.0: 28 bytes (no customAttributeStart/Count)
	// v24.1+: 40 bytes (with customAttributeStart/Count)
	// Try common sizes
	sizes := []int{40, 32, 28, 24}
	structSize := 40

	for _, sz := range sizes {
		if int(h.ImagesSize)%sz == 0 {
			count := int(h.ImagesSize) / sz
			if count >= 1 && count <= 1000 {
				// Validate first entry
				if h.ImagesOffset+uint32(sz) <= uint32(len(m.rawData)) {
					data := m.rawData[h.ImagesOffset:]
					nameIdx := int32(binary.LittleEndian.Uint32(data[0:4]))
					if nameIdx >= 0 && int(nameIdx) < len(m.Strings) {
						structSize = sz
						break
					}
				}
			}
		}
	}

	count := int(h.ImagesSize) / structSize
	if count <= 0 {
		return fmt.Errorf("invalid image count: %d (size=%d, total=%d)", count, structSize, h.ImagesSize)
	}

	data := m.rawData[h.ImagesOffset:]

	// Parse entries and keep only valid ones (nameIdx within string table).
	// Some binaries have oversized imagesSize fields; the actual images are
	// a prefix of the table and the rest is padding or unrelated data.
	images := make([]*ImageDefinition, 0, min(count, 256))

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		nameIdx := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if nameIdx < 0 || int(nameIdx) >= len(m.Strings) {
			break // past valid image entries
		}

		img := &ImageDefinition{
			NameIndex:     nameIdx,
			AssemblyIndex: int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			TypeStart:     int32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			TypeCount:     binary.LittleEndian.Uint32(data[offset+12 : offset+16]),
		}

		if structSize >= 24 {
			img.ExportedTypeStart = int32(binary.LittleEndian.Uint32(data[offset+16 : offset+20]))
			img.ExportedTypeCount = binary.LittleEndian.Uint32(data[offset+20 : offset+24])
		}
		if structSize >= 32 {
			img.EntryPointIndex = int32(binary.LittleEndian.Uint32(data[offset+24 : offset+28]))
			img.Token = binary.LittleEndian.Uint32(data[offset+28 : offset+32])
		}
		if structSize >= 40 {
			img.CustomAttributeStart = int32(binary.LittleEndian.Uint32(data[offset+32 : offset+36]))
			img.CustomAttributeCount = binary.LittleEndian.Uint32(data[offset+36 : offset+40])
		}

		images = append(images, img)
	}

	if len(images) == 0 {
		return fmt.Errorf("no valid image definitions found (raw count=%d, size=%d, total=%d)", count, structSize, h.ImagesSize)
	}

	m.ImageDefinitions = images
	return nil
}

// GetTypeName returns the full name of a type (Namespace.TypeName)
func (m *GlobalMetadata) GetTypeName(typeIdx int) string {
	if typeIdx < 0 || typeIdx >= len(m.TypeDefinitions) {
		return ""
	}

	td := m.TypeDefinitions[typeIdx]
	name := m.GetString(td.NameIndex)
	ns := m.GetString(td.NamespaceIndex)

	if ns == "" {
		return name
	}
	return ns + "." + name
}

// GetMethodName returns the name of a method
func (m *GlobalMetadata) GetMethodName(methodIdx int) string {
	if methodIdx < 0 || methodIdx >= len(m.MethodDefinitions) {
		return ""
	}

	md := m.MethodDefinitions[methodIdx]
	return m.GetString(md.NameIndex)
}

// GetMethodFullName returns Namespace.TypeName$$MethodName
func (m *GlobalMetadata) GetMethodFullName(methodIdx int) string {
	if methodIdx < 0 || methodIdx >= len(m.MethodDefinitions) {
		return ""
	}

	md := m.MethodDefinitions[methodIdx]
	methodName := m.GetString(md.NameIndex)
	typeName := m.GetTypeName(int(md.DeclaringTypeIndex))

	if typeName == "" {
		return methodName
	}
	return typeName + "$$" + methodName
}

// GetImageName returns the name of an image (assembly)
func (m *GlobalMetadata) GetImageName(imageIdx int) string {
	if imageIdx < 0 || imageIdx >= len(m.ImageDefinitions) {
		return ""
	}

	img := m.ImageDefinitions[imageIdx]
	return m.GetString(img.NameIndex)
}

// BuildTypeToImageMap creates a mapping from type index to image index.
// Deprecated: use getTypeToImage() which caches the result.
func (m *GlobalMetadata) BuildTypeToImageMap() map[int]int {
	typeToImage := make(map[int]int, len(m.TypeDefinitions))
	for imgIdx, img := range m.ImageDefinitions {
		if img == nil {
			continue
		}
		for i := 0; i < int(img.TypeCount); i++ {
			typeIdx := int(img.TypeStart) + i
			typeToImage[typeIdx] = imgIdx
		}
	}
	return typeToImage
}

// getTypeToImage returns a cached slice mapping type index -> image index.
// Uses a flat slice instead of a map (type indices are dense integers).
func (m *GlobalMetadata) getTypeToImage() []int {
	if m.typeToImage != nil {
		return m.typeToImage
	}
	n := len(m.TypeDefinitions)
	m.typeToImage = make([]int, n)
	for i := range m.typeToImage {
		m.typeToImage[i] = -1
	}
	for imgIdx, img := range m.ImageDefinitions {
		if img == nil {
			continue
		}
		for i := 0; i < int(img.TypeCount); i++ {
			typeIdx := int(img.TypeStart) + i
			if typeIdx >= 0 && typeIdx < n {
				m.typeToImage[typeIdx] = imgIdx
			}
		}
	}
	return m.typeToImage
}

// MethodInfo contains resolved method information for script.json generation
type MethodInfo struct {
	Index      int    // Method index in metadata
	Name       string // Full method name (Namespace.Type$$Method)
	Token      uint32 // Method token
	TokenIndex int    // Token & 0x00FFFFFF (1-based index into method pointers)
	ImageName  string // Assembly name (e.g., "Assembly-CSharp.dll")
	ImageIndex int    // Image index
}

// GetAllMethods returns resolved information for all methods
func (m *GlobalMetadata) GetAllMethods() []*MethodInfo {
	t2i := m.getTypeToImage()

	methods := make([]*MethodInfo, 0, len(m.MethodDefinitions))

	for i, md := range m.MethodDefinitions {
		if md == nil {
			continue
		}

		info := &MethodInfo{
			Index:      i,
			Name:       m.GetMethodFullName(i),
			Token:      md.Token,
			TokenIndex: int(md.Token & 0x00FFFFFF), // Low 24 bits
		}

		// Find image from declaring type
		if idx := int(md.DeclaringTypeIndex); idx >= 0 && idx < len(t2i) {
			if imgIdx := t2i[idx]; imgIdx >= 0 {
				info.ImageIndex = imgIdx
				info.ImageName = m.GetImageName(imgIdx)
			}
		}

		methods = append(methods, info)
	}

	return methods
}

// GetMethodInfo returns resolved information for a single method by index
func (m *GlobalMetadata) GetMethodInfo(methodIdx int) *MethodInfo {
	if methodIdx < 0 || methodIdx >= len(m.MethodDefinitions) {
		return nil
	}

	md := m.MethodDefinitions[methodIdx]
	if md == nil {
		return nil
	}

	t2i := m.getTypeToImage()

	info := &MethodInfo{
		Index:      methodIdx,
		Name:       m.GetMethodFullName(methodIdx),
		Token:      md.Token,
		TokenIndex: int(md.Token & 0x00FFFFFF),
	}

	// Find image from declaring type
	if idx := int(md.DeclaringTypeIndex); idx >= 0 && idx < len(t2i) {
		if imgIdx := t2i[idx]; imgIdx >= 0 {
			info.ImageIndex = imgIdx
			info.ImageName = m.GetImageName(imgIdx)
		}
	}

	return info
}

// parseFieldDefinitions parses the field definition array
func (m *GlobalMetadata) parseFieldDefinitions() error {
	h := m.Header
	if h.FieldsSize == 0 {
		return nil
	}

	// Field definition size varies by version:
	// v24 and below: 12 bytes (with customAttributeIndex)
	// v24.2+: 12 bytes (nameIndex, typeIndex, token)
	// Size detection: try 12 bytes first
	structSize := 12
	count := int(h.FieldsSize) / structSize
	if count <= 0 || count > 1000000 {
		return nil // No fields or invalid
	}

	data := m.rawData[h.FieldsOffset:]
	m.FieldDefinitions = make([]*FieldDefinition, count)

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		fd := &FieldDefinition{
			NameIndex: int32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			TypeIndex: int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			Token:     binary.LittleEndian.Uint32(data[offset+8 : offset+12]),
		}
		m.FieldDefinitions[i] = fd
	}

	return nil
}

// parseParameterDefinitions parses the parameter definition array
func (m *GlobalMetadata) parseParameterDefinitions() error {
	h := m.Header
	if h.ParametersSize == 0 {
		return nil
	}

	// Parameter definition size: 12 bytes (nameIndex, token, typeIndex)
	structSize := 12
	count := int(h.ParametersSize) / structSize
	if count <= 0 || count > 1000000 {
		return nil
	}

	data := m.rawData[h.ParametersOffset:]
	m.ParameterDefinitions = make([]*ParameterDefinition, count)

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		pd := &ParameterDefinition{
			NameIndex: int32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			Token:     binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
			TypeIndex: int32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
		}
		m.ParameterDefinitions[i] = pd
	}

	return nil
}

// parsePropertyDefinitions parses the property definition array
func (m *GlobalMetadata) parsePropertyDefinitions() error {
	h := m.Header
	if h.PropertiesSize == 0 {
		return nil
	}

	// Property definition size: 20 bytes for v24.2+
	structSize := 20
	count := int(h.PropertiesSize) / structSize
	if count <= 0 || count > 500000 {
		return nil
	}

	data := m.rawData[h.PropertiesOffset:]
	m.PropertyDefinitions = make([]*PropertyDefinition, count)

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		pd := &PropertyDefinition{
			NameIndex: int32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			Get:       int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			Set:       int32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			Attrs:     binary.LittleEndian.Uint32(data[offset+12 : offset+16]),
			Token:     binary.LittleEndian.Uint32(data[offset+16 : offset+20]),
		}
		m.PropertyDefinitions[i] = pd
	}

	return nil
}

// parseEventDefinitions parses the event definition array
func (m *GlobalMetadata) parseEventDefinitions() error {
	h := m.Header
	if h.EventsSize == 0 {
		return nil
	}

	// Event definition size: 24 bytes for v24.2+
	structSize := 24
	count := int(h.EventsSize) / structSize
	if count <= 0 || count > 100000 {
		return nil
	}

	data := m.rawData[h.EventsOffset:]
	m.EventDefinitions = make([]*EventDefinition, count)

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		ed := &EventDefinition{
			NameIndex: int32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			TypeIndex: int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			Add:       int32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			Remove:    int32(binary.LittleEndian.Uint32(data[offset+12 : offset+16])),
			Raise:     int32(binary.LittleEndian.Uint32(data[offset+16 : offset+20])),
			Token:     binary.LittleEndian.Uint32(data[offset+20 : offset+24]),
		}
		m.EventDefinitions[i] = ed
	}

	return nil
}

// parseGenericContainers parses the generic container array
func (m *GlobalMetadata) parseGenericContainers() error {
	h := m.Header
	if h.GenericContainersSize == 0 {
		return nil
	}

	// Generic container size: 16 bytes
	structSize := 16
	count := int(h.GenericContainersSize) / structSize
	if count <= 0 || count > 100000 {
		return nil
	}

	data := m.rawData[h.GenericContainersOffset:]
	m.GenericContainers = make([]*GenericContainer, count)

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		gc := &GenericContainer{
			OwnerIndex:            int32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			TypeArgc:              int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			IsMethod:              int32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			GenericParameterStart: int32(binary.LittleEndian.Uint32(data[offset+12 : offset+16])),
		}
		m.GenericContainers[i] = gc
	}

	return nil
}

// parseGenericParameters parses the generic parameter array
func (m *GlobalMetadata) parseGenericParameters() error {
	h := m.Header
	if h.GenericParametersSize == 0 {
		return nil
	}

	// Generic parameter size: 16 bytes
	structSize := 16
	count := int(h.GenericParametersSize) / structSize
	if count <= 0 || count > 100000 {
		return nil
	}

	data := m.rawData[h.GenericParametersOffset:]
	m.GenericParameters = make([]*GenericParameter, count)

	for i := 0; i < count; i++ {
		offset := i * structSize
		if offset+structSize > len(data) {
			break
		}

		gp := &GenericParameter{
			OwnerIndex:       int32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			NameIndex:        binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
			ConstraintsStart: int16(binary.LittleEndian.Uint16(data[offset+8 : offset+10])),
			ConstraintsCount: int16(binary.LittleEndian.Uint16(data[offset+10 : offset+12])),
			Num:              binary.LittleEndian.Uint16(data[offset+12 : offset+14]),
			Flags:            binary.LittleEndian.Uint16(data[offset+14 : offset+16]),
		}
		m.GenericParameters[i] = gp
	}

	return nil
}

// GetFieldName returns the name of a field
func (m *GlobalMetadata) GetFieldName(fieldIdx int) string {
	if fieldIdx < 0 || fieldIdx >= len(m.FieldDefinitions) {
		return ""
	}
	fd := m.FieldDefinitions[fieldIdx]
	if fd == nil {
		return ""
	}
	return m.GetString(fd.NameIndex)
}

// GetParameterName returns the name of a parameter
func (m *GlobalMetadata) GetParameterName(paramIdx int) string {
	if paramIdx < 0 || paramIdx >= len(m.ParameterDefinitions) {
		return ""
	}
	pd := m.ParameterDefinitions[paramIdx]
	if pd == nil {
		return ""
	}
	return m.GetString(pd.NameIndex)
}

// GetPropertyName returns the name of a property
func (m *GlobalMetadata) GetPropertyName(propIdx int) string {
	if propIdx < 0 || propIdx >= len(m.PropertyDefinitions) {
		return ""
	}
	pd := m.PropertyDefinitions[propIdx]
	if pd == nil {
		return ""
	}
	return m.GetString(pd.NameIndex)
}

// GetGenericParameterName returns the name of a generic parameter (e.g., "T")
func (m *GlobalMetadata) GetGenericParameterName(gpIdx int) string {
	if gpIdx < 0 || gpIdx >= len(m.GenericParameters) {
		return ""
	}
	gp := m.GenericParameters[gpIdx]
	if gp == nil {
		return ""
	}
	return m.GetString(int32(gp.NameIndex))
}

// parseVTableMethods parses the vtable method indices array
func (m *GlobalMetadata) parseVTableMethods() error {
	h := m.Header
	if h.VTableMethodsSize == 0 {
		return nil
	}

	// VTable entries are uint32 encoded method indices
	// Size is 4 bytes per entry
	count := int(h.VTableMethodsSize) / 4
	if count <= 0 || count > 10000000 {
		return nil
	}

	data := m.rawData[h.VTableMethodsOffset:]
	m.VTableMethodIndices = make([]uint32, count)

	for i := 0; i < count; i++ {
		offset := i * 4
		if offset+4 > len(data) {
			break
		}
		m.VTableMethodIndices[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	return nil
}

// GetEncodedIndexType returns the usage type from an encoded index (high 3 bits)
// Types: 0=TypeInfo, 1=Type, 2=MethodDef, 3=FieldInfo, 4=StringLiteral, 5=MethodRef, 6=MethodRef
func GetEncodedIndexType(encoded uint32) uint32 {
	return (encoded & 0xE0000000) >> 29
}

// DecodeVTableMethodIndex decodes an encoded vtable method index
// For v27+: bits 1-28 contain the index (shifted right by 1)
// For older versions: bits 0-28 contain the index
// Returns the decoded index and the usage type
func DecodeVTableMethodIndex(encoded uint32) (methodIdx int, isGeneric bool) {
	usageType := GetEncodedIndexType(encoded)
	// Usage type 6 = kIl2CppMetadataUsageMethodRef (generic method)
	isGeneric = usageType == 6

	// For v27+, the index is in bits 1-28 (shifted)
	// We assume v27+ here since that's the common case
	methodIdx = int((encoded & 0x1FFFFFFE) >> 1)
	return
}

// DecodeVTableMethodIndexV24 decodes for v24 and below
func DecodeVTableMethodIndexV24(encoded uint32) (methodIdx int, isGeneric bool) {
	usageType := GetEncodedIndexType(encoded)
	isGeneric = usageType == 6
	methodIdx = int(encoded & 0x1FFFFFFF)
	return
}

// GetVTableMethodName returns the method name for a vtable slot
// typeDefIndex: the type definition index
// slotIndex: the vtable slot index (0-based)
func (m *GlobalMetadata) GetVTableMethodName(typeDefIndex, slotIndex int) string {
	if typeDefIndex < 0 || typeDefIndex >= len(m.TypeDefinitions) {
		return ""
	}

	typeDef := m.TypeDefinitions[typeDefIndex]
	if typeDef == nil || slotIndex < 0 || slotIndex >= int(typeDef.VtableCount) {
		return ""
	}

	vtableIdx := int(typeDef.VtableStart) + slotIndex
	if vtableIdx < 0 || vtableIdx >= len(m.VTableMethodIndices) {
		return ""
	}

	encoded := m.VTableMethodIndices[vtableIdx]
	methodIdx, _ := DecodeVTableMethodIndex(encoded)

	if methodIdx < 0 || methodIdx >= len(m.MethodDefinitions) {
		return ""
	}

	return m.GetMethodName(methodIdx)
}

// StringLiteralEntry represents a single Il2CppStringLiteral entry.
type StringLiteralEntry struct {
	Length    uint32 // String length in bytes (UTF-16LE)
	DataIndex uint32 // Offset into StringLiteralData
}

// GetAllStringLiterals extracts all string literals from metadata.
// IL2CPP stores string literals as UTF-16LE in the StringLiteralData table,
// indexed by entries at StringLiteralOffset (each {uint32 length, uint32 dataIndex}).
func (m *GlobalMetadata) GetAllStringLiterals() []string {
	h := m.Header
	if h.StringLiteralOffset == 0 || h.StringLiteralSize == 0 {
		return nil
	}
	if h.StringLiteralDataOffset == 0 || h.StringLiteralDataSize == 0 {
		return nil
	}

	// Each entry is 8 bytes: {uint32 length, uint32 dataIndex}
	entrySize := 8
	entryCount := int(h.StringLiteralSize) / entrySize
	if entryCount <= 0 {
		return nil
	}

	entryData := m.rawData[h.StringLiteralOffset:]
	litData := m.rawData[h.StringLiteralDataOffset:]

	var result []string
	for i := 0; i < entryCount; i++ {
		off := i * entrySize
		if off+entrySize > len(entryData) {
			break
		}

		length := binary.LittleEndian.Uint32(entryData[off : off+4])
		dataIdx := binary.LittleEndian.Uint32(entryData[off+4 : off+8])

		if length == 0 || length > 65536 {
			continue
		}
		if int(dataIdx+length) > len(litData) {
			continue
		}

		raw := litData[dataIdx : dataIdx+length]

		// Decode UTF-16LE to Go string
		if length%2 != 0 {
			// Odd byte count - treat as raw UTF-8
			s := string(raw)
			if s != "" {
				result = append(result, s)
			}
			continue
		}

		runes := make([]rune, 0, length/2)
		for j := 0; j+1 < len(raw); j += 2 {
			r := rune(binary.LittleEndian.Uint16(raw[j : j+2]))
			if r == 0 {
				break
			}
			runes = append(runes, r)
		}
		if len(runes) > 0 {
			result = append(result, string(runes))
		}
	}

	return result
}
