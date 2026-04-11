package output

import (
	"disunity/internal/metadata"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// CodeGenModuleInfo represents captured CodeGenModule data from emulation
type CodeGenModuleInfo struct {
	Name           string   // Assembly name (e.g., "Assembly-CSharp.dll")
	MethodPointers []uint64 // Native method addresses
}

// ScriptEntry represents a single entry in script.json
type ScriptEntry struct {
	Address  uint64 `json:"address"`
	Name     string `json:"name"`
	FullName string `json:"fullName,omitempty"`
	Image    string `json:"image,omitempty"`
}

// ScriptJSON maps hex addresses to method info
type ScriptJSON struct {
	Methods map[string]*ScriptEntry `json:"methods"` // key: "0x<addr>"
	Count   int                     `json:"count"`
	Version int32                   `json:"metadataVersion"`
}

// GenerateScriptJSON creates a script.json mapping from metadata and captured modules
//
// For IL2CPP v24.2+:
//  1. Get method.image_name (assembly name from type_to_image mapping)
//  2. Get method.token_index = token & 0x00FFFFFF (low 24 bits, 1-based)
//  3. Look up CodeGenModule by image_name
//  4. method_idx = token_index - 1 (convert to 0-based)
//  5. Get native_address = modules[image_name].methodPointers[method_idx]
//
// For pre-v24.2 (when modules is nil/empty):
//  1. Use global methodPointers array directly
//  2. Method RID (1-based) indexes into the array
//  3. Get native_address = globalMethodPointers[methodRid - 1]
func GenerateScriptJSON(meta *metadata.GlobalMetadata, modules []*CodeGenModuleInfo) (*ScriptJSON, error) {
	if meta == nil {
		return nil, fmt.Errorf("metadata is nil")
	}

	result := &ScriptJSON{
		Methods: make(map[string]*ScriptEntry),
		Version: meta.Header.Version,
	}

	// Get all methods with resolved info
	allMethods := meta.GetAllMethods()

	// Check if we have CodeGenModules
	hasModules := false
	moduleMap := make(map[string]*CodeGenModuleInfo)
	for _, mod := range modules {
		if mod != nil && mod.Name != "" && len(mod.MethodPointers) > 0 {
			hasModules = true
			// Normalize module name (some have .dll suffix, some don't)
			name := mod.Name
			moduleMap[name] = mod
			// Also store without .dll suffix
			if strings.HasSuffix(name, ".dll") {
				moduleMap[strings.TrimSuffix(name, ".dll")] = mod
			}
		}
	}

	resolved := 0
	if hasModules {
		// v24.2+ path: use per-module method pointers
		for _, mi := range allMethods {
			if mi.ImageName == "" {
				continue
			}

			// Find module
			mod, ok := moduleMap[mi.ImageName]
			if !ok {
				// Try without .dll suffix
				mod, ok = moduleMap[strings.TrimSuffix(mi.ImageName, ".dll")]
			}
			if !ok || mod == nil {
				continue
			}

			// Token index is 1-based
			tokenIdx := mi.TokenIndex
			if tokenIdx <= 0 {
				continue
			}

			// Convert to 0-based array index
			arrayIdx := tokenIdx - 1
			if arrayIdx < 0 || arrayIdx >= len(mod.MethodPointers) {
				continue
			}

			addr := mod.MethodPointers[arrayIdx]
			if addr == 0 {
				continue
			}

			// Build entry
			entry := &ScriptEntry{
				Address:  addr,
				Name:     meta.GetMethodName(mi.Index),
				FullName: mi.Name,
				Image:    mi.ImageName,
			}

			// Key is hex address
			key := fmt.Sprintf("0x%X", addr)
			result.Methods[key] = entry
			resolved++
		}
	}

	result.Count = resolved

	return result, nil
}

// GenericMethodEntry represents a generic method instantiation from static analysis
type GenericMethodEntry struct {
	MethodDefinitionIndex int32
	ClassIndexIndex       int32  // Index into genericInsts for class type args (-1 if none)
	MethodIndexIndex      int32  // Index into genericInsts for method type args (-1 if none)
	Address               uint64
}

// GenerateScriptJSONWithGenerics creates script.json with both regular and generic methods.
// The genericMethods slice contains all generic method instantiations with their addresses.
func GenerateScriptJSONWithGenerics(meta *metadata.GlobalMetadata, modules []*CodeGenModuleInfo, genericMethods []GenericMethodEntry) (*ScriptJSON, error) {
	if meta == nil {
		return nil, fmt.Errorf("metadata is nil")
	}

	result := &ScriptJSON{
		Methods: make(map[string]*ScriptEntry),
		Version: meta.Header.Version,
	}

	// Get all methods with resolved info
	allMethods := meta.GetAllMethods()

	// Build module map
	moduleMap := make(map[string]*CodeGenModuleInfo)
	for _, mod := range modules {
		if mod != nil && mod.Name != "" && len(mod.MethodPointers) > 0 {
			name := mod.Name
			moduleMap[name] = mod
			// Also store without .dll suffix
			if strings.HasSuffix(name, ".dll") {
				moduleMap[strings.TrimSuffix(name, ".dll")] = mod
			}
		}
	}

	// Build map from methodDefinitionIndex to list of generic method entries
	// This is used to look up generic instantiations for methods that have no direct pointer
	genericMethodsByDef := make(map[int32][]GenericMethodEntry)
	for _, gm := range genericMethods {
		genericMethodsByDef[gm.MethodDefinitionIndex] = append(genericMethodsByDef[gm.MethodDefinitionIndex], gm)
	}

	resolved := 0
	genericResolved := 0

	// First pass: resolve regular methods from CodeGenModules
	for _, mi := range allMethods {
		if mi.ImageName == "" {
			continue
		}

		// Find module
		mod, ok := moduleMap[mi.ImageName]
		if !ok {
			mod, ok = moduleMap[strings.TrimSuffix(mi.ImageName, ".dll")]
		}
		if !ok || mod == nil {
			continue
		}

		// Token index is 1-based
		tokenIdx := mi.TokenIndex
		if tokenIdx <= 0 {
			continue
		}

		// Convert to 0-based array index
		arrayIdx := tokenIdx - 1
		if arrayIdx < 0 || arrayIdx >= len(mod.MethodPointers) {
			continue
		}

		addr := mod.MethodPointers[arrayIdx]
		if addr != 0 {
			// Build entry for regular method
			entry := &ScriptEntry{
				Address:  addr,
				Name:     meta.GetMethodName(mi.Index),
				FullName: mi.Name,
				Image:    mi.ImageName,
			}

			key := fmt.Sprintf("0x%X", addr)
			result.Methods[key] = entry
			resolved++
		}
	}

	// Second pass: add ALL generic method instantiations
	// Each genericMethod entry represents one specific instantiation
	for _, gm := range genericMethods {
		if gm.Address == 0 {
			continue
		}

		// Get method info
		if int(gm.MethodDefinitionIndex) < 0 || int(gm.MethodDefinitionIndex) >= len(meta.MethodDefinitions) {
			continue
		}

		mi := meta.GetMethodInfo(int(gm.MethodDefinitionIndex))
		if mi == nil {
			continue
		}

		// Build entry
		// For now, use the base method name. Later we could add type argument info.
		entry := &ScriptEntry{
			Address:  gm.Address,
			Name:     meta.GetMethodName(int(gm.MethodDefinitionIndex)),
			FullName: mi.Name, // Could be enhanced with type args
			Image:    mi.ImageName,
		}

		key := fmt.Sprintf("0x%X", gm.Address)
		// Only add if not already present (some regular methods may share addresses with generic versions)
		if _, exists := result.Methods[key]; !exists {
			result.Methods[key] = entry
			resolved++
			genericResolved++
		}
	}

	result.Count = resolved

	return result, nil
}

// GenerateScriptJSONFromGlobal creates script.json using the global method pointers array.
// This is used for pre-v24.2 IL2CPP binaries that don't have CodeGenModules.
//
// Resolution formula:
//  1. Get method RID (token & 0x00FFFFFF) - this is the method definition row ID (1-based)
//  2. native_address = globalMethodPointers[rid - 1]
func GenerateScriptJSONFromGlobal(meta *metadata.GlobalMetadata, globalMethodPointers []uint64) (*ScriptJSON, error) {
	if meta == nil {
		return nil, fmt.Errorf("metadata is nil")
	}
	if len(globalMethodPointers) == 0 {
		return nil, fmt.Errorf("no global method pointers")
	}

	result := &ScriptJSON{
		Methods: make(map[string]*ScriptEntry),
		Version: meta.Header.Version,
	}

	// Get all methods
	allMethods := meta.GetAllMethods()

	resolved := 0
	for _, mi := range allMethods {
		// For pre-v24.2, we use the method definition index directly
		// The Index field should already be the 0-based index into methodDefs
		methodIdx := mi.Index

		if methodIdx < 0 || methodIdx >= len(globalMethodPointers) {
			continue
		}

		addr := globalMethodPointers[methodIdx]
		if addr == 0 {
			continue
		}

		// Build entry
		entry := &ScriptEntry{
			Address:  addr,
			Name:     meta.GetMethodName(mi.Index),
			FullName: mi.Name,
			Image:    mi.ImageName,
		}

		// Key is hex address
		key := fmt.Sprintf("0x%X", addr)
		result.Methods[key] = entry
		resolved++
	}

	result.Count = resolved

	return result, nil
}

// WriteScriptJSON writes script.json to a file
func WriteScriptJSON(sj *ScriptJSON, path string) error {
	data, err := json.MarshalIndent(sj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// WriteIDAScript writes a Python script for IDA Pro to import names
func WriteIDAScript(sj *ScriptJSON, path string) error {
	var sb strings.Builder

	sb.WriteString("# Auto-generated IL2CPP symbol import script\n")
	sb.WriteString("# Usage: Run in IDA: File -> Script file...\n\n")
	sb.WriteString("import idaapi\n")
	sb.WriteString("import idc\n\n")
	sb.WriteString("def import_il2cpp_symbols():\n")
	sb.WriteString("    count = 0\n")

	// Sort addresses for consistent output
	addrs := make([]uint64, 0, len(sj.Methods))
	for _, entry := range sj.Methods {
		addrs = append(addrs, entry.Address)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	for _, addr := range addrs {
		key := fmt.Sprintf("0x%X", addr)
		entry := sj.Methods[key]

		// Sanitize name for IDA (replace $$ with _, remove special chars)
		name := entry.FullName
		name = strings.ReplaceAll(name, "$$", "_")
		name = strings.ReplaceAll(name, ".", "_")
		name = strings.ReplaceAll(name, "<", "_")
		name = strings.ReplaceAll(name, ">", "_")
		name = strings.ReplaceAll(name, ",", "_")
		name = strings.ReplaceAll(name, " ", "_")

		sb.WriteString(fmt.Sprintf("    if idc.set_name(0x%X, '%s', idaapi.SN_NOWARN | idaapi.SN_FORCE):\n", addr, name))
		sb.WriteString("        count += 1\n")
	}

	sb.WriteString(fmt.Sprintf("    print('Imported %%d / %d IL2CPP symbols' %% count)\n\n", len(sj.Methods)))
	sb.WriteString("import_il2cpp_symbols()\n")

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// WriteGhidraScript writes a Python script for Ghidra to import names
func WriteGhidraScript(sj *ScriptJSON, path string) error {
	var sb strings.Builder

	sb.WriteString("# Auto-generated IL2CPP symbol import script for Ghidra\n")
	sb.WriteString("# Usage: Run in Ghidra: Script Manager -> Run\n\n")
	sb.WriteString("#@category IL2CPP\n\n")

	sb.WriteString("from ghidra.program.model.symbol import SourceType\n\n")
	sb.WriteString("def import_il2cpp_symbols():\n")
	sb.WriteString("    count = 0\n")
	sb.WriteString("    fm = currentProgram.getFunctionManager()\n")
	sb.WriteString("    st = currentProgram.getSymbolTable()\n")

	// Sort for consistent output
	addrs := make([]uint64, 0, len(sj.Methods))
	for _, entry := range sj.Methods {
		addrs = append(addrs, entry.Address)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	for _, addr := range addrs {
		key := fmt.Sprintf("0x%X", addr)
		entry := sj.Methods[key]

		name := entry.FullName
		name = strings.ReplaceAll(name, "$$", "_")
		name = strings.ReplaceAll(name, ".", "_")
		name = strings.ReplaceAll(name, "<", "_")
		name = strings.ReplaceAll(name, ">", "_")

		sb.WriteString(fmt.Sprintf("    addr = toAddr(0x%X)\n", addr))
		sb.WriteString("    try:\n")
		sb.WriteString("        f = fm.getFunctionAt(addr)\n")
		sb.WriteString("        if f:\n")
		sb.WriteString(fmt.Sprintf("            f.setName('%s', SourceType.USER_DEFINED)\n", name))
		sb.WriteString("            count += 1\n")
		sb.WriteString("        else:\n")
		sb.WriteString(fmt.Sprintf("            st.createLabel(addr, '%s', SourceType.USER_DEFINED)\n", name))
		sb.WriteString("            count += 1\n")
		sb.WriteString("    except: pass\n")
	}

	sb.WriteString(fmt.Sprintf("    print('Imported %%d / %d IL2CPP symbols' %% count)\n\n", len(sj.Methods)))
	sb.WriteString("import_il2cpp_symbols()\n")

	return os.WriteFile(path, []byte(sb.String()), 0644)
}
