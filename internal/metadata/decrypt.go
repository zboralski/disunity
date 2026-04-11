// Package metadata provides IL2CPP global-metadata.dat parsing.
package metadata

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
)

// XORKey represents an extracted XOR decryption key.
type XORKey struct {
	Key       [8]byte
	KeyVA     uint64
	FuncVA    uint64
	KeyString string
}

// FindXORKeyWithValidation searches the binary for XOR decryption patterns,
// extracts candidate keys, and validates them against the metadata.
// This handles IL2CPP metadata obfuscation that uses simple 8-byte XOR.
//
// The pattern we look for:
//  1. ADRP Xn, #key@PAGE - loads page address
//  2. ADD Xn, Xn, #key@PAGEOFF - adds page offset
//  3. EOR loop - XORs data with key
func FindXORKeyWithValidation(binaryPath string, metaData []byte) (*XORKey, []byte, error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read binary: %w", err)
	}

	// Parse ELF
	f, err := elf.Open(binaryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ELF: %w", err)
	}
	defer f.Close()

	// Find .text section
	var textSection *elf.Section
	for _, sec := range f.Sections {
		if sec.Name == ".text" {
			textSection = sec
			break
		}
	}
	if textSection == nil {
		return nil, nil, fmt.Errorf("no .text section found")
	}

	// Scan for XOR decryption patterns
	candidates := findXORCandidates(data, textSection)
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("no XOR patterns found")
	}

	// Try each candidate and validate decryption result
	for _, cand := range candidates {
		// Convert VA to file offset
		keyOffset := vaToOffset(cand.keyVA, f)
		if keyOffset == 0 || keyOffset+8 > uint64(len(data)) {
			continue
		}

		// Read key
		var key [8]byte
		copy(key[:], data[keyOffset:keyOffset+8])

		// Validate key looks like ASCII
		if !isValidKey(key[:]) {
			continue
		}

		// Try decrypting with this key
		decrypted := DecryptMetadata(metaData, key)

		// Validate decryption result
		if len(decrypted) < 32 {
			continue
		}

		magic := binary.LittleEndian.Uint32(decrypted[0:4])
		version := binary.LittleEndian.Uint32(decrypted[4:8])
		stringOffset := binary.LittleEndian.Uint32(decrypted[24:28])
		stringSize := binary.LittleEndian.Uint32(decrypted[28:32])

		// Check if decryption produced valid metadata
		if magic != MetadataMagic {
			continue
		}
		if version < 24 || version > 31 {
			continue
		}
		if stringOffset == 0 || uint64(stringOffset)+uint64(stringSize) > uint64(len(decrypted)) {
			continue
		}

		keyStr := string(bytes.TrimRight(key[:], "\x00"))

		return &XORKey{
			Key:       key,
			KeyVA:     cand.keyVA,
			FuncVA:    cand.funcVA,
			KeyString: keyStr,
		}, decrypted, nil
	}

	return nil, nil, fmt.Errorf("no valid XOR key found (tried %d candidates)", len(candidates))
}

// FindXORKey searches the binary for XOR decryption patterns and extracts the key.
// NOTE: This function doesn't validate the key. Use FindXORKeyWithValidation for
// validated key extraction.
func FindXORKey(binaryPath string) (*XORKey, error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}

	// Parse ELF
	f, err := elf.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	defer f.Close()

	// Find .text section
	var textSection *elf.Section
	for _, sec := range f.Sections {
		if sec.Name == ".text" {
			textSection = sec
			break
		}
	}
	if textSection == nil {
		return nil, fmt.Errorf("no .text section found")
	}

	// Scan for XOR decryption patterns
	candidates := findXORCandidates(data, textSection)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no XOR patterns found")
	}

	// Return first valid-looking candidate
	for _, cand := range candidates {
		// Convert VA to file offset
		keyOffset := vaToOffset(cand.keyVA, f)
		if keyOffset == 0 || keyOffset+8 > uint64(len(data)) {
			continue
		}

		// Read key
		var key [8]byte
		copy(key[:], data[keyOffset:keyOffset+8])

		// Validate key looks like ASCII
		if !isValidKey(key[:]) {
			continue
		}

		keyStr := string(bytes.TrimRight(key[:], "\x00"))

		return &XORKey{
			Key:       key,
			KeyVA:     cand.keyVA,
			FuncVA:    cand.funcVA,
			KeyString: keyStr,
		}, nil
	}

	return nil, fmt.Errorf("no valid XOR key found")
}

// DecryptMetadata decrypts obfuscated metadata using XOR key.
// The obfuscation preserves bytes 0-6 (magic + partial version)
// and XORs everything from byte 7 onwards.
func DecryptMetadata(data []byte, key [8]byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		if i >= 7 {
			result[i] = key[i%8] ^ data[i]
		} else {
			result[i] = data[i]
		}
	}
	return result
}

// TryAutoDecrypt attempts to detect and decrypt obfuscated metadata.
// It first checks if metadata is obfuscated, then tries to find
// the XOR key in the binary and decrypt.
func TryAutoDecrypt(binaryPath, metadataPath string) ([]byte, *XORKey, error) {
	// Read metadata
	metaData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read metadata: %w", err)
	}

	// Try Kasiski/known-plaintext attack first (works without binary patterns)
	key, decrypted, kasErr := FindXORKeyKasiski(metaData)
	if kasErr == nil {
		// Try to find key location in binary for better reporting
		if binKey, _, binErr := FindXORKeyWithValidation(binaryPath, metaData); binErr == nil {
			// Use binary key info (has VA location) but kasiski-decrypted data
			return decrypted, binKey, nil
		}
		return decrypted, key, nil
	}

	// Fallback: Try binary pattern matching
	key, decrypted, binErr := FindXORKeyWithValidation(binaryPath, metaData)
	if binErr == nil {
		return decrypted, key, nil
	}

	return nil, nil, fmt.Errorf("find XOR key: kasiski failed (%v), binary pattern failed (%v)", kasErr, binErr)
}

// FindXORKeyKasiski uses Kasiski examination and known-plaintext attack to recover XOR key.
// Handles two encryption modes:
// - Partial encryption (standard): XOR from byte 7, magic preserved
// - Full encryption: XOR from byte 0, magic also encrypted
func FindXORKeyKasiski(metaData []byte) (*XORKey, []byte, error) {
	if len(metaData) < 264 {
		return nil, nil, fmt.Errorf("metadata too small")
	}

	// Check if magic is valid (partial encryption mode)
	magic := binary.LittleEndian.Uint32(metaData[0:4])
	fullEncryption := magic != MetadataMagic

	// Step 1: Detect key length using Kasiski examination
	detectedLen := kasiskiFindKeyLength(metaData)
	if detectedLen == 0 {
		detectedLen = frequencyKeyLength(metaData, 32)
	}

	// Try detected length first, then common lengths
	tryLengths := []int{detectedLen}
	for _, l := range []int{8, 16, 4, 32, 12, 24} {
		if l != detectedLen {
			tryLengths = append(tryLengths, l)
		}
	}

	for _, keyLen := range tryLengths {
		if keyLen < 4 || keyLen > 32 {
			continue
		}

		var key *XORKey
		var decrypted []byte
		var err error

		if fullEncryption {
			key, decrypted, err = tryKeyLengthFull(metaData, keyLen)
		} else {
			key, decrypted, err = tryKeyLength(metaData, keyLen)
		}

		if err == nil {
			return key, decrypted, nil
		}
	}

	return nil, nil, fmt.Errorf("kasiski: no valid key found (tried lengths: %v, fullEncryption=%v)", tryLengths, fullEncryption)
}

// tryKeyLength attempts to recover key of specified length using known-plaintext attack
// and partial string matching to complete unknown key positions.
func tryKeyLength(metaData []byte, keyLen int) (*XORKey, []byte, error) {
	// IL2CPP metadata has predictable header structure:
	// - byte 7:  version high byte = 0x00 (for versions 24-31)
	// - byte 8:  stringLiteralOffset[0] = 0x00 or 0x08
	// - byte 9:  stringLiteralOffset[1] = 0x01 (= 256, header size)
	// - byte 10: stringLiteralOffset[2] = 0x00
	// - byte 11: stringLiteralOffset[3] = 0x00
	// - byte 15: stringLiteralSize[3] = 0x00 (for sizes < 16MB)

	key := make([]byte, keyLen)
	known := make([]bool, keyLen) // Track which positions are derived

	// Derive key bytes from known plaintext positions
	// key[i % keyLen] = ciphertext[i] XOR plaintext[i]
	key[7%keyLen] = metaData[7] ^ 0x00 // version high byte = 0
	known[7%keyLen] = true
	key[9%keyLen] = metaData[9] ^ 0x01 // stringLiteralOffset[1] = 1
	known[9%keyLen] = true
	key[10%keyLen] = metaData[10] ^ 0x00 // stringLiteralOffset[2] = 0
	known[10%keyLen] = true
	key[11%keyLen] = metaData[11] ^ 0x00 // stringLiteralOffset[3] = 0
	known[11%keyLen] = true
	key[15%keyLen] = metaData[15] ^ 0x00 // stringLiteralSize[3] = 0
	known[15%keyLen] = true

	// Use frequency analysis for initial estimate of unknown positions
	for pos := 0; pos < keyLen; pos++ {
		if !known[pos] {
			key[pos] = findKeyByteFrequency(metaData, keyLen, pos)
		}
	}

	// Try partial decryption and look for known strings to complete key
	// This is more reliable than brute-forcing
	key, known = completeKeyFromStrings(metaData, key, known, keyLen)

	// For any remaining unknown positions, try variations
	unknownPositions := []int{}
	for pos := 0; pos < keyLen; pos++ {
		if !known[pos] {
			unknownPositions = append(unknownPositions, pos)
		}
	}

	// If we have too many unknown positions, brute force isn't practical
	if len(unknownPositions) > 3 {
		// Try with frequency-derived values first
		decrypted := decryptMetadataVariable(metaData, key)
		if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
			return makeXORKeyResult(key, keyLen, decrypted)
		}
		return nil, nil, fmt.Errorf("too many unknown key positions (%d) for length %d", len(unknownPositions), keyLen)
	}

	// Try all combinations for remaining unknown positions
	if len(unknownPositions) == 0 {
		decrypted := decryptMetadataVariable(metaData, key)
		if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
			return makeXORKeyResult(key, keyLen, decrypted)
		}
		return nil, nil, fmt.Errorf("no valid key found for length %d", keyLen)
	}

	// Build search order: letters, digits, then other printable
	tryOrder := buildTryOrder()

	// For 1-3 unknown positions, try combinations
	if result, decrypted, err := tryUnknownPositions(metaData, key, unknownPositions, tryOrder, keyLen); err == nil {
		return result, decrypted, nil
	}

	return nil, nil, fmt.Errorf("no valid key found for length %d", keyLen)
}

// completeKeyFromStrings looks for partial matches of known strings
// and derives missing key bytes from them.
func completeKeyFromStrings(metaData []byte, key []byte, known []bool, keyLen int) ([]byte, []bool) {
	// Known IL2CPP strings that appear in virtually all metadata
	knownStrings := []string{
		"<Module>",
		".ctor",
		".cctor",
		"System",
		"System.Object",
		"System.String",
		"System.Int32",
		"System.Boolean",
		"System.Void",
		"mscorlib",
		"UnityEngine",
		"Assembly-CSharp",
		"get_",
		"set_",
		"Awake",
		"Start",
		"Update",
		"OnDestroy",
		"GameObject",
		"Transform",
		"MonoBehaviour",
	}

	// Do partial decrypt with current key
	decrypted := decryptMetadataVariable(metaData, key)

	// Parse header to find string table
	if len(decrypted) < 32 {
		return key, known
	}

	magic := binary.LittleEndian.Uint32(decrypted[0:4])
	if magic != MetadataMagic {
		return key, known
	}

	stringOffset := binary.LittleEndian.Uint32(decrypted[24:28])
	stringSize := binary.LittleEndian.Uint32(decrypted[28:32])

	if stringOffset == 0 || stringOffset >= uint32(len(decrypted)) {
		return key, known
	}

	// Limit search area
	searchEnd := int(stringOffset) + int(stringSize)
	if searchEnd > len(decrypted) {
		searchEnd = len(decrypted)
	}
	if searchEnd > int(stringOffset)+500*1024 {
		searchEnd = int(stringOffset) + 500*1024
	}

	// For each known string, try to find partial matches
	for _, target := range knownStrings {
		if len(target) < 3 {
			continue
		}

		// Search for positions where most of the string matches
		for pos := int(stringOffset); pos < searchEnd-len(target); pos++ {
			matchCount := 0
			mismatchPositions := []int{}

			for i := 0; i < len(target); i++ {
				if decrypted[pos+i] == target[i] {
					matchCount++
				} else {
					mismatchPositions = append(mismatchPositions, i)
				}
			}

			// If we have a good partial match (>70% matching)
			if matchCount >= len(target)*7/10 && matchCount > 0 && len(mismatchPositions) <= len(target)*3/10 {
				// Use mismatches to derive missing key bytes
				for _, mi := range mismatchPositions {
					dataPos := pos + mi
					keyPos := dataPos % keyLen

					// Calculate what key byte should be
					// plaintext XOR key = ciphertext
					// So: key = ciphertext XOR plaintext
					expectedKey := metaData[dataPos] ^ target[mi]

					// If this position wasn't known, or confirms our guess
					if !known[keyPos] || key[keyPos] == expectedKey {
						key[keyPos] = expectedKey
						known[keyPos] = true
					}
				}

				// Re-decrypt to update our view with new key bytes
				decrypted = decryptMetadataVariable(metaData, key)
			}
		}
	}

	return key, known
}

// tryUnknownPositions brute-forces remaining unknown key positions.
func tryUnknownPositions(metaData, key []byte, unknownPos []int, tryOrder []byte, keyLen int) (*XORKey, []byte, error) {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	switch len(unknownPos) {
	case 1:
		for _, b0 := range tryOrder {
			keyCopy[unknownPos[0]] = b0
			decrypted := decryptMetadataVariable(metaData, keyCopy)
			if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
				return makeXORKeyResult(keyCopy, keyLen, decrypted)
			}
		}
	case 2:
		for _, b0 := range tryOrder {
			keyCopy[unknownPos[0]] = b0
			for _, b1 := range tryOrder {
				keyCopy[unknownPos[1]] = b1
				decrypted := decryptMetadataVariable(metaData, keyCopy)
				if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
					return makeXORKeyResult(keyCopy, keyLen, decrypted)
				}
			}
		}
	case 3:
		for _, b0 := range tryOrder {
			keyCopy[unknownPos[0]] = b0
			for _, b1 := range tryOrder {
				keyCopy[unknownPos[1]] = b1
				for _, b2 := range tryOrder {
					keyCopy[unknownPos[2]] = b2
					decrypted := decryptMetadataVariable(metaData, keyCopy)
					if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
						return makeXORKeyResult(keyCopy, keyLen, decrypted)
					}
				}
			}
		}
	}

	return nil, nil, fmt.Errorf("no valid combination found")
}

// tryKeyLengthFull attempts to recover key for full encryption (XOR from byte 0).
// Uses known magic bytes and header structure for known-plaintext attack.
func tryKeyLengthFull(metaData []byte, keyLen int) (*XORKey, []byte, error) {
	// IL2CPP metadata has known values at specific offsets:
	// - bytes 0-3: magic 0xFAB11BAF (af 1b b1 fa in little-endian)
	// - byte 7: version high byte = 0x00 (for versions 24-31)
	// Other header fields are less predictable but we can use frequency analysis

	key := make([]byte, keyLen)
	known := make([]bool, keyLen)

	// Derive key bytes from known magic (bytes 0-3)
	magicBytes := []byte{0xaf, 0x1b, 0xb1, 0xfa}
	for i := 0; i < 4; i++ {
		pos := i % keyLen
		key[pos] = metaData[i] ^ magicBytes[i]
		known[pos] = true
	}

	// Version high byte at position 7 is 0x00 for versions < 256
	key[7%keyLen] = metaData[7] ^ 0x00
	known[7%keyLen] = true

	// Quick sanity check: if key bytes from magic are non-printable and don't look
	// like a repeating pattern, this might not be simple XOR encryption
	// Check if the derived key produces a valid version number
	testDecrypt := decryptMetadataFull(metaData[:32], key[:min(keyLen, 8)])
	version := binary.LittleEndian.Uint32(testDecrypt[4:8])
	if version < 20 || version > 35 {
		// Version is out of range - likely not simple XOR or wrong key length
		return nil, nil, fmt.Errorf("derived key produces invalid version %d (expected 20-35)", version)
	}

	// Use frequency analysis for remaining positions
	for pos := 0; pos < keyLen; pos++ {
		if !known[pos] {
			key[pos] = findKeyByteFrequencyFull(metaData, keyLen, pos)
		}
	}

	// Try to complete key using partial string matches
	key, known = completeKeyFromStringsFull(metaData, key, known, keyLen)

	// Count unknown positions
	unknownPositions := []int{}
	for pos := 0; pos < keyLen; pos++ {
		if !known[pos] {
			unknownPositions = append(unknownPositions, pos)
		}
	}

	// If we have too many unknown positions, try with frequency values first
	if len(unknownPositions) > 3 {
		decrypted := decryptMetadataFull(metaData, key)
		if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
			return makeXORKeyResult(key, keyLen, decrypted)
		}
		return nil, nil, fmt.Errorf("too many unknown key positions (%d) for length %d", len(unknownPositions), keyLen)
	}

	// Try all combinations for remaining unknown positions
	if len(unknownPositions) == 0 {
		decrypted := decryptMetadataFull(metaData, key)
		if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
			return makeXORKeyResult(key, keyLen, decrypted)
		}
		return nil, nil, fmt.Errorf("no valid key found for length %d", keyLen)
	}

	// Build search order and try combinations
	tryOrder := buildTryOrder()
	if result, decrypted, err := tryUnknownPositionsFull(metaData, key, unknownPositions, tryOrder, keyLen); err == nil {
		return result, decrypted, nil
	}

	return nil, nil, fmt.Errorf("no valid key found for length %d (full encryption)", keyLen)
}

// findKeyByteFrequencyFull finds key byte using frequency analysis for full encryption.
func findKeyByteFrequencyFull(data []byte, keyLen, pos int) byte {
	freq := make([]int, 256)

	// Count frequency of bytes at this key position (from byte 0)
	for i := 0; i < len(data); i++ {
		if i%keyLen == pos {
			freq[data[i]]++
		}
	}

	// Find most frequent byte (likely XORed with 0x00)
	maxFreq := 0
	maxByte := byte(0)
	for b, f := range freq {
		if f > maxFreq {
			maxFreq = f
			maxByte = byte(b)
		}
	}

	return maxByte
}

// completeKeyFromStringsFull looks for partial matches in fully encrypted data.
func completeKeyFromStringsFull(metaData []byte, key []byte, known []bool, keyLen int) ([]byte, []bool) {
	// Do partial decrypt with current key
	decrypted := decryptMetadataFull(metaData, key)

	// Parse header to find string table
	if len(decrypted) < 32 {
		return key, known
	}

	magic := binary.LittleEndian.Uint32(decrypted[0:4])
	if magic != MetadataMagic {
		return key, known
	}

	stringOffset := binary.LittleEndian.Uint32(decrypted[24:28])
	stringSize := binary.LittleEndian.Uint32(decrypted[28:32])

	if stringOffset == 0 || stringOffset >= uint32(len(decrypted)) {
		return key, known
	}

	// Known IL2CPP strings
	knownStrings := []string{
		"<Module>", ".ctor", ".cctor", "System", "System.Object",
		"System.String", "System.Int32", "System.Boolean", "System.Void",
		"mscorlib", "UnityEngine", "Assembly-CSharp",
		"get_", "set_", "Awake", "Start", "Update", "OnDestroy",
		"GameObject", "Transform", "MonoBehaviour",
	}

	// Limit search area
	searchEnd := int(stringOffset) + int(stringSize)
	if searchEnd > len(decrypted) {
		searchEnd = len(decrypted)
	}
	if searchEnd > int(stringOffset)+500*1024 {
		searchEnd = int(stringOffset) + 500*1024
	}

	// Look for partial matches
	for _, target := range knownStrings {
		if len(target) < 3 {
			continue
		}

		for pos := int(stringOffset); pos < searchEnd-len(target); pos++ {
			matchCount := 0
			mismatchPositions := []int{}

			for i := 0; i < len(target); i++ {
				if decrypted[pos+i] == target[i] {
					matchCount++
				} else {
					mismatchPositions = append(mismatchPositions, i)
				}
			}

			// Good partial match (>70%)
			if matchCount >= len(target)*7/10 && matchCount > 0 && len(mismatchPositions) <= len(target)*3/10 {
				for _, mi := range mismatchPositions {
					dataPos := pos + mi
					keyPos := dataPos % keyLen
					expectedKey := metaData[dataPos] ^ target[mi]

					if !known[keyPos] || key[keyPos] == expectedKey {
						key[keyPos] = expectedKey
						known[keyPos] = true
					}
				}
				decrypted = decryptMetadataFull(metaData, key)
			}
		}
	}

	return key, known
}

// tryUnknownPositionsFull brute-forces remaining positions for full encryption.
func tryUnknownPositionsFull(metaData, key []byte, unknownPos []int, tryOrder []byte, keyLen int) (*XORKey, []byte, error) {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	switch len(unknownPos) {
	case 1:
		for _, b0 := range tryOrder {
			keyCopy[unknownPos[0]] = b0
			decrypted := decryptMetadataFull(metaData, keyCopy)
			if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
				return makeXORKeyResult(keyCopy, keyLen, decrypted)
			}
		}
	case 2:
		for _, b0 := range tryOrder {
			keyCopy[unknownPos[0]] = b0
			for _, b1 := range tryOrder {
				keyCopy[unknownPos[1]] = b1
				decrypted := decryptMetadataFull(metaData, keyCopy)
				if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
					return makeXORKeyResult(keyCopy, keyLen, decrypted)
				}
			}
		}
	case 3:
		for _, b0 := range tryOrder {
			keyCopy[unknownPos[0]] = b0
			for _, b1 := range tryOrder {
				keyCopy[unknownPos[1]] = b1
				for _, b2 := range tryOrder {
					keyCopy[unknownPos[2]] = b2
					decrypted := decryptMetadataFull(metaData, keyCopy)
					if quickValidateHeader(decrypted[:min(1024, len(decrypted))]) && validateDecrypted(decrypted) {
						return makeXORKeyResult(keyCopy, keyLen, decrypted)
					}
				}
			}
		}
	}

	return nil, nil, fmt.Errorf("no valid combination found")
}

// decryptMetadataFull decrypts with XOR from byte 0 (full encryption).
func decryptMetadataFull(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	keyLen := len(key)
	for i := range data {
		result[i] = key[i%keyLen] ^ data[i]
	}
	return result
}

// makeXORKeyResult creates the XORKey result from a successful key.
func makeXORKeyResult(key []byte, keyLen int, decrypted []byte) (*XORKey, []byte, error) {
	var keyArr [8]byte
	if keyLen <= 8 {
		copy(keyArr[:], key)
	} else {
		copy(keyArr[:], key[:8])
	}
	keyStr := string(bytes.TrimRight(key, "\x00"))
	return &XORKey{
		Key:       keyArr,
		KeyVA:     0,
		FuncVA:    0,
		KeyString: keyStr,
	}, decrypted, nil
}

// decryptMetadataVariable decrypts with variable-length key (XOR from byte 7).
func decryptMetadataVariable(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	keyLen := len(key)
	for i := range data {
		if i >= 7 {
			result[i] = key[i%keyLen] ^ data[i]
		} else {
			result[i] = data[i]
		}
	}
	return result
}

// buildTryOrder returns byte values to try in priority order.
func buildTryOrder() []byte {
	tryOrder := make([]byte, 0, 96)
	for b := byte('a'); b <= 'z'; b++ {
		tryOrder = append(tryOrder, b)
	}
	for b := byte('A'); b <= 'Z'; b++ {
		tryOrder = append(tryOrder, b)
	}
	for b := byte('0'); b <= '9'; b++ {
		tryOrder = append(tryOrder, b)
	}
	for b := byte(0x20); b <= 0x7E; b++ {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}
		tryOrder = append(tryOrder, b)
	}
	tryOrder = append(tryOrder, 0)
	return tryOrder
}

// quickValidateHeader performs fast header-only validation.
func quickValidateHeader(data []byte) bool {
	if len(data) < 32 {
		return false
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	version := binary.LittleEndian.Uint32(data[4:8])
	stringOffset := binary.LittleEndian.Uint32(data[24:28])

	if magic != MetadataMagic {
		return false
	}
	if version < 24 || version > 31 {
		return false
	}
	// String offset should be reasonable (header size to ~10MB)
	if stringOffset < 256 || stringOffset > 50*1024*1024 {
		return false
	}

	return true
}

// findKeyByteFrequency finds the most likely key byte for a position using frequency.
// In IL2CPP metadata, null bytes are common, so the most frequent ciphertext byte
// at each position likely corresponds to key XOR 0x00 = key.
func findKeyByteFrequency(data []byte, keyLen, pos int) byte {
	freq := make([]int, 256)

	// Count frequency of bytes at this key position (starting from byte 7 where XOR begins)
	for i := 7; i < len(data); i++ {
		if i%keyLen == pos {
			freq[data[i]]++
		}
	}

	// Find most frequent byte
	maxFreq := 0
	maxByte := byte(0)
	for b, f := range freq {
		if f > maxFreq {
			maxFreq = f
			maxByte = byte(b)
		}
	}

	return maxByte
}

// kasiskiFindKeyLength uses Kasiski examination to estimate key length.
// It finds repeated byte sequences and calculates GCD of their distances.
func kasiskiFindKeyLength(data []byte) int {
	if len(data) < 100 {
		return 0
	}

	// Find repeated sequences of length 6-16 bytes
	distances := make(map[int]int)
	minSeqLen := 6
	maxSeqLen := 16

	// Limit search to first 100KB for performance
	searchLen := len(data)
	if searchLen > 100*1024 {
		searchLen = 100 * 1024
	}

	for seqLen := minSeqLen; seqLen <= maxSeqLen; seqLen++ {
		seen := make(map[string][]int)

		for i := 0; i <= searchLen-seqLen; i++ {
			seq := string(data[i : i+seqLen])
			seen[seq] = append(seen[seq], i)
		}

		for _, positions := range seen {
			if len(positions) < 2 {
				continue
			}
			for i := 1; i < len(positions); i++ {
				dist := positions[i] - positions[i-1]
				if dist > 0 && dist < 10000 {
					distances[dist]++
				}
			}
		}
	}

	if len(distances) == 0 {
		return 0
	}

	// Find GCD of most common distances
	type distCount struct {
		dist  int
		count int
	}
	var dcs []distCount
	for d, c := range distances {
		dcs = append(dcs, distCount{d, c})
	}

	// Sort by count descending
	for i := 0; i < len(dcs)-1; i++ {
		for j := i + 1; j < len(dcs); j++ {
			if dcs[j].count > dcs[i].count {
				dcs[i], dcs[j] = dcs[j], dcs[i]
			}
		}
	}

	// Take top distances and find their GCD
	topN := 20
	if len(dcs) < topN {
		topN = len(dcs)
	}
	result := dcs[0].dist
	for i := 1; i < topN; i++ {
		result = gcd(result, dcs[i].dist)
	}

	// Prefer common key lengths
	validLengths := []int{4, 8, 12, 16, 20, 24, 32}
	for _, vl := range validLengths {
		if result%vl == 0 || vl%result == 0 {
			if result >= vl {
				return vl
			}
		}
	}

	if result >= 4 && result <= 64 {
		return result
	}

	return 8 // Default for IL2CPP
}

// frequencyKeyLength uses index of coincidence to estimate key length.
func frequencyKeyLength(data []byte, maxLen int) int {
	// Limit data for performance
	if len(data) > 100*1024 {
		data = data[:100*1024]
	}

	bestLen := 8
	bestIC := 0.0

	for keyLen := 4; keyLen <= maxLen; keyLen++ {
		var totalIC float64
		for offset := 0; offset < keyLen; offset++ {
			// Extract every keyLen-th byte starting at offset
			var slice []byte
			for i := offset; i < len(data); i += keyLen {
				slice = append(slice, data[i])
			}
			totalIC += indexOfCoincidence(slice)
		}
		avgIC := totalIC / float64(keyLen)

		// Higher IC suggests correct key length
		if avgIC > bestIC {
			bestIC = avgIC
			bestLen = keyLen
		}
	}

	return bestLen
}

// indexOfCoincidence calculates IC for a byte slice.
func indexOfCoincidence(data []byte) float64 {
	if len(data) < 2 {
		return 0
	}

	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	var sum float64
	n := float64(len(data))
	for _, f := range freq {
		sum += float64(f) * float64(f-1)
	}

	return sum / (n * (n - 1))
}

// validateDecrypted checks if decrypted data looks like valid metadata.
func validateDecrypted(data []byte) bool {
	if len(data) < 264 {
		return false
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	version := binary.LittleEndian.Uint32(data[4:8])
	stringOffset := binary.LittleEndian.Uint32(data[24:28])
	stringSize := binary.LittleEndian.Uint32(data[28:32])

	if magic != MetadataMagic {
		return false
	}
	if version < 24 || version > 31 {
		return false
	}
	if stringOffset == 0 || uint64(stringOffset)+uint64(stringSize) > uint64(len(data)) {
		return false
	}

	// Stronger validation: look for known IL2CPP/Unity strings in the string table
	// These strings appear in virtually all IL2CPP apps
	if stringOffset < uint32(len(data)) && stringSize > 0 {
		// Search for known patterns that appear in all IL2CPP metadata
		knownStrings := []string{
			"<Module>",
			".ctor",
			"System",
			"mscorlib",
			"UnityEngine",
			"Void",
			"Object",
			"String",
			"Int32",
			"Boolean",
		}

		// Extract first 50KB of string table to search
		searchEnd := stringOffset + 50*1024
		if searchEnd > uint32(len(data)) {
			searchEnd = uint32(len(data))
		}
		if searchEnd > stringOffset+stringSize {
			searchEnd = stringOffset + stringSize
		}
		searchData := string(data[stringOffset:searchEnd])

		// Must find at least 3 known patterns
		foundCount := 0
		for _, known := range knownStrings {
			for i := 0; i <= len(searchData)-len(known); i++ {
				if searchData[i:i+len(known)] == known {
					foundCount++
					break
				}
			}
		}

		if foundCount < 4 {
			return false
		}
	}

	return true
}

// isValidString checks if bytes look like valid C# identifier or text.
func isValidString(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for valid printable characters
	// IL2CPP strings are typically C# identifiers, type names, or method names
	for _, b := range data {
		// Allow printable ASCII
		if b >= 0x20 && b <= 0x7E {
			continue
		}
		// Allow UTF-8 continuation bytes (for international strings)
		if b >= 0x80 && b <= 0xBF {
			continue
		}
		// Allow UTF-8 start bytes
		if b >= 0xC0 && b <= 0xF7 {
			continue
		}
		return false
	}
	return true
}

// isValidCSharpString checks if string looks like a valid C# identifier/name.
// Uses strict validation - no unusual characters allowed.
func isValidCSharpString(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Count character types
	for _, b := range data {
		// Only allow: a-z, A-Z, 0-9, _, ., <, >, [, ], `, ,, space
		switch {
		case b >= 'a' && b <= 'z':
		case b >= 'A' && b <= 'Z':
		case b >= '0' && b <= '9':
		case b == '_', b == '.', b == '<', b == '>', b == '[', b == ']', b == '`', b == ',', b == ' ', b == '-':
		case b >= 0x80 && b <= 0xBF: // UTF-8 continuation
		case b >= 0xC0 && b <= 0xF7: // UTF-8 start
		default:
			return false // Invalid character
		}
	}
	return true
}

// gcd calculates greatest common divisor.
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// xorCandidate represents a potential XOR decryption location.
type xorCandidate struct {
	funcVA uint64
	keyVA  uint64
}

// findXORCandidates scans the text section for XOR patterns.
func findXORCandidates(data []byte, textSection *elf.Section) []xorCandidate {
	var candidates []xorCandidate

	textStart := textSection.Offset
	textSize := textSection.Size
	textVA := textSection.Addr

	// Scan for EOR instructions with ADRP/ADD patterns nearby
	for i := uint64(0); i < textSize-32; i += 4 {
		off := textStart + i

		if off+4 > uint64(len(data)) {
			break
		}

		instr := binary.LittleEndian.Uint32(data[off : off+4])

		// EOR (shifted register) 32-bit: 0x4A??????
		if (instr & 0xFF000000) != 0x4A000000 {
			continue
		}

		// Found EOR, look backwards for ADRP
		for j := uint64(1); j < 20; j++ {
			if i < j*4 {
				break
			}

			prevOff := textStart + i - j*4
			if prevOff+4 > uint64(len(data)) {
				continue
			}

			prevInstr := binary.LittleEndian.Uint32(data[prevOff : prevOff+4])

			// ADRP: 1 immlo(2) 10000 immhi(19) Rd(5)
			// Mask: 0x9F000000, expect: 0x90000000
			if (prevInstr & 0x9F000000) != 0x90000000 {
				continue
			}

			// Found ADRP, decode it
			rd := prevInstr & 0x1F
			pc := textVA + (i - j*4)
			page := decodeADRP(prevInstr, pc)

			// Look for ADD after ADRP
			for k := uint64(1); k < 10; k++ {
				addOff := prevOff + k*4
				if addOff+4 > uint64(len(data)) {
					break
				}

				addInstr := binary.LittleEndian.Uint32(data[addOff : addOff+4])

				// ADD immediate 64-bit: 0x91??????
				if (addInstr & 0xFF000000) != 0x91000000 {
					continue
				}

				addRd := addInstr & 0x1F
				addRn := (addInstr >> 5) & 0x1F

				if addRd == rd && addRn == rd {
					imm12 := decodeADDImm(addInstr)
					keyVA := page + uint64(imm12)
					funcVA := textVA + i - j*4

					candidates = append(candidates, xorCandidate{
						funcVA: funcVA,
						keyVA:  keyVA,
					})
					break
				}
			}
			break
		}
	}

	return candidates
}

// decodeADRP decodes an ADRP instruction to get the target page address.
func decodeADRP(instr uint32, pc uint64) uint64 {
	immlo := (instr >> 29) & 0x3
	immhi := (instr >> 5) & 0x7FFFF
	imm := int64((immhi << 2) | immlo)

	// Sign extend from 21 bits
	if imm&0x100000 != 0 {
		imm -= 0x200000
	}

	pageOffset := imm << 12
	return (pc &^ 0xFFF) + uint64(pageOffset)
}

// decodeADDImm decodes an ADD immediate instruction to get the offset.
func decodeADDImm(instr uint32) uint32 {
	return (instr >> 10) & 0xFFF
}

// vaToOffset converts a virtual address to file offset.
func vaToOffset(va uint64, f *elf.File) uint64 {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if va >= prog.Vaddr && va < prog.Vaddr+prog.Memsz {
			return prog.Off + (va - prog.Vaddr)
		}
	}
	return 0
}

// isValidKey checks if the key looks like a valid ASCII string.
func isValidKey(key []byte) bool {
	hasContent := false
	for _, b := range key {
		if b == 0 {
			continue
		}
		if b < 0x20 || b > 0x7e {
			return false
		}
		hasContent = true
	}
	return hasContent
}
