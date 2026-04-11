# disunity metadata import script for Ghidra
# Reads unity_meta.json and applies function names, types, and comments.
#
# Usage:
#   analyzeHeadless ... -postScript disunity_apply.py <path/to/unity_meta.json>
#   Or run manually: Script Manager -> disunity_apply.py
#
#@category IL2CPP
#@author disunity

import json
import os

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit, ParameterImpl
from ghidra.program.model.data import (
    VoidDataType, BooleanDataType,
    SignedByteDataType, ByteDataType,
    ShortDataType, UnsignedShortDataType,
    IntegerDataType, UnsignedIntegerDataType,
    LongLongDataType, UnsignedLongLongDataType,
    FloatDataType, DoubleDataType,
    PointerDataType, Undefined8DataType,
)
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.decompiler import DecompInterface, DecompileOptions

# Map C type strings to Ghidra DataType instances
_PRIMITIVE_TYPES = {
    "void":       VoidDataType.dataType,
    "bool":       BooleanDataType.dataType,
    "int8_t":     SignedByteDataType.dataType,
    "uint8_t":    ByteDataType.dataType,
    "int16_t":    ShortDataType.dataType,
    "uint16_t":   UnsignedShortDataType.dataType,
    "int32_t":    IntegerDataType.dataType,
    "uint32_t":   UnsignedIntegerDataType.dataType,
    "int64_t":    LongLongDataType.dataType,
    "uint64_t":   UnsignedLongLongDataType.dataType,
    "float":      FloatDataType.dataType,
    "double":     DoubleDataType.dataType,
    "intptr_t":   LongLongDataType.dataType,
    "uintptr_t":  UnsignedLongLongDataType.dataType,
}

# Pointer-sized void* (8 bytes on ARM64)
_VOID_PTR = PointerDataType(VoidDataType.dataType)


def resolve_c_type(type_str, dtm):
    """Convert a C type string from unity_meta.json to a Ghidra DataType.

    Handles: primitives, pointers, struct types. Falls back to void* for
    unknown types (structs not imported, generic placeholders, etc.).
    """
    if not type_str:
        return _VOID_PTR

    s = type_str.strip()

    # Direct primitive match
    if s in _PRIMITIVE_TYPES:
        return _PRIMITIVE_TYPES[s]

    # Pointer types (e.g., "void*", "System_String_o*", "struct Foo_o*")
    if s.endswith("*"):
        base = s[:-1].strip()

        # "const MethodInfo*" -> void*
        if base.startswith("const "):
            base = base[6:].strip()

        # Strip "struct " prefix
        if base.startswith("struct "):
            base = base[7:].strip()

        # Check for primitive pointer
        if base in _PRIMITIVE_TYPES:
            return PointerDataType(_PRIMITIVE_TYPES[base])

        # Try to find the struct in the data type manager (if il2cpp.h was imported)
        if dtm is not None and base:
            found = dtm.getDataType("/" + base)
            if found is not None:
                return PointerDataType(found)

        # Fall back to void*
        return _VOID_PTR

    # "struct Foo_o" without pointer (value type in param)
    if s.startswith("struct "):
        base = s[7:].strip()
        if dtm is not None and base:
            found = dtm.getDataType("/" + base)
            if found is not None:
                return found
        return Undefined8DataType.dataType

    # Unknown type -> void*
    return _VOID_PTR


def sanitize_filename(name):
    """Sanitize for filenames (allows dots and hyphens)."""
    out = []
    for ch in name:
        if ch.isalnum() or ch in ('_', '-', '.'):
            out.append(ch)
        else:
            out.append('_')
    s = ''.join(out)
    return s[:120] if len(s) > 120 else s


def owner_to_path(owner):
    """Convert dotted C# owner to hierarchical path.

    'System.Net.Http.HttpClient' -> 'System/Net/Http/HttpClient'
    Generic backtick suffixes are stripped: 'List`1' -> 'List'
    """
    if not owner:
        return "global"
    parts = []
    for p in owner.split('.'):
        # Strip generic arity: List`1 -> List
        idx = p.find('`')
        if idx > 0:
            p = p[:idx]
        s = sanitize_filename(p)
        if s:
            parts.append(s)
    return os.path.join(*parts) if parts else "global"


def apply_metadata(meta_path=None, decompile_dir=None):
    """Apply unity_meta.json to the current Ghidra program.

    This function is importable by external tools (e.g. ida-headless-mcp).

    Args:
        meta_path: Path to unity_meta.json. If None, uses script argument.
        decompile_dir: Directory for decompiled .c files. If None, uses args[1].
    """
    if meta_path is None:
        args = getScriptArgs()
        if not args:
            # Try to find unity_meta.json next to the binary
            prog_path = currentProgram.getExecutablePath()
            if prog_path:
                candidate = os.path.join(os.path.dirname(prog_path), "unity_meta.json")
                if os.path.exists(candidate):
                    meta_path = candidate
            if meta_path is None:
                print("[disunity] ERROR: No unity_meta.json path provided")
                print("[disunity] Usage: -postScript disunity_apply.py <path/to/unity_meta.json>")
                return
        else:
            meta_path = args[0]
            if decompile_dir is None and len(args) > 1:
                decompile_dir = args[1]

    print("[disunity] Loading %s" % meta_path)
    with open(meta_path, 'r') as f:
        meta = json.load(f)

    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    af = currentProgram.getAddressFactory()
    space = af.getDefaultAddressSpace()
    dtm = currentProgram.getDataTypeManager()

    il2cpp_version = meta.get("il2cpp_version", 0)
    ptr_size = meta.get("pointer_size", 8)
    print("[disunity] IL2CPP v%d, pointer size %d" % (il2cpp_version, ptr_size))

    # Phase 1: Create/rename functions
    functions = meta.get("functions", [])
    func_count = 0
    for entry in functions:
        addr_str = entry.get("addr", "")
        name = entry.get("name", "")
        if not addr_str or not name:
            continue

        addr_val = int(addr_str, 16)
        addr = space.getAddress(addr_val)

        # Sanitize name for Ghidra
        safe_name = sanitize_name(name)

        # Disassemble at address if needed
        if listing.getInstructionAt(addr) is None:
            cmd = DisassembleCommand(addr, None, True)
            cmd.applyTo(currentProgram)

        # Create or rename function
        func = fm.getFunctionAt(addr)
        if func is None:
            try:
                func = createFunction(addr, safe_name)
            except:
                pass
        if func:
            try:
                func.setName(safe_name, SourceType.USER_DEFINED)
                func_count += 1
            except:
                pass
        else:
            try:
                st.createLabel(addr, safe_name, SourceType.USER_DEFINED)
                func_count += 1
            except:
                pass

    print("[disunity] Applied %d / %d function names" % (func_count, len(functions)))

    # Phase 2: Apply comments
    comments = meta.get("comments", [])
    comment_count = 0
    for entry in comments:
        addr_str = entry.get("addr", "")
        text = entry.get("text", "")
        if not addr_str or not text:
            continue

        addr_val = int(addr_str, 16)
        addr = space.getAddress(addr_val)

        cu = listing.getCodeUnitAt(addr)
        if cu:
            existing = cu.getComment(CodeUnit.EOL_COMMENT)
            if existing:
                text = existing + " | " + text
            cu.setComment(CodeUnit.EOL_COMMENT, text)
            comment_count += 1

    print("[disunity] Applied %d / %d comments" % (comment_count, len(comments)))

    # Phase 3: Apply function signatures
    sig_count = 0
    for entry in functions:
        params = entry.get("params")
        ret_type = entry.get("return_type")
        if not params:
            continue

        addr_str = entry.get("addr", "")
        if not addr_str:
            continue

        addr_val = int(addr_str, 16)
        addr = space.getAddress(addr_val)

        func = fm.getFunctionAt(addr)
        if not func:
            continue

        try:
            # Set return type
            ret_dt = resolve_c_type(ret_type, dtm)
            func.setReturnType(ret_dt, SourceType.USER_DEFINED)

            # Build parameter list
            param_list = []
            for p in params:
                p_name = sanitize_name(p.get("name", "arg"))
                p_type = resolve_c_type(p.get("type", ""), dtm)
                param = ParameterImpl(p_name, p_type, currentProgram)
                param_list.append(param)

            func.replaceParameters(param_list,
                ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,  # force
                SourceType.USER_DEFINED)
            sig_count += 1
        except:
            pass

    print("[disunity] Applied %d / %d function signatures" % (sig_count, len(functions)))

    # Phase 4: Decompile focus functions
    focus = meta.get("focus_functions", [])
    decompiled = 0
    decompile_failed = 0

    if decompile_dir and focus:
        print("[disunity] Phase 4: decompiling %d focus functions..." % len(focus))
        if not os.path.exists(decompile_dir):
            os.makedirs(decompile_dir)

        # Build lookup maps.
        name_by_addr = {}
        owner_by_addr = {}
        for entry in functions:
            a = entry.get("addr", "")
            if a:
                name_by_addr[a] = entry.get("name", "")
                if entry.get("owner"):
                    owner_by_addr[a] = entry["owner"]

        # Set up decompiler.
        decomp = DecompInterface()
        opts = DecompileOptions()
        decomp.setOptions(opts)
        decomp.openProgram(currentProgram)

        index = []
        total = len(focus)
        for i, addr_str in enumerate(focus):
            if (i + 1) % 500 == 0:
                print("[disunity]   progress: %d / %d (%d ok, %d failed)" %
                      (i + 1, total, decompiled, decompile_failed))

            addr_val = int(addr_str, 16)
            addr = space.getAddress(addr_val)

            func = fm.getFunctionAt(addr)
            if func is None:
                index.append({
                    "addr": addr_str,
                    "name": name_by_addr.get(addr_str, "unknown"),
                    "file": None,
                    "decompile_ok": False,
                    "reason": "no_function",
                })
                decompile_failed += 1
                continue

            fn_name = func.getName()
            try:
                result = decomp.decompileFunction(func, 10, monitor)
                if result is None or not result.decompileCompleted():
                    msg = "timeout"
                    if result is not None:
                        msg = result.getErrorMessage() or "unknown error"
                    raise Exception(msg)

                c_code = result.getDecompiledFunction().getC()
                if not c_code:
                    raise Exception("empty decompilation")

                safe_name = addr_str.replace("0x", "") + "_" + sanitize_filename(fn_name)
                owner = owner_by_addr.get(addr_str, "")
                sub = owner_to_path(owner)
                sub_dir = os.path.join(decompile_dir, sub)
                if not os.path.exists(sub_dir):
                    os.makedirs(sub_dir)
                out_file = os.path.join(sub, safe_name + ".c")

                with open(os.path.join(decompile_dir, out_file), 'w') as cf:
                    cf.write(c_code)

                index.append({
                    "addr": addr_str,
                    "name": fn_name,
                    "file": out_file,
                    "decompile_ok": True,
                })
                decompiled += 1
            except Exception as e:
                index.append({
                    "addr": addr_str,
                    "name": fn_name,
                    "file": None,
                    "decompile_ok": False,
                    "reason": str(e)[:100],
                })
                decompile_failed += 1

        decomp.dispose()

        with open(os.path.join(decompile_dir, "index.json"), 'w') as idx:
            json.dump(index, idx, indent=2)

        print("[disunity] Decompiled %d / %d focus functions (%d failed)" %
              (decompiled, len(focus), decompile_failed))
    elif not decompile_dir:
        if focus:
            print("[disunity] Phase 4: skipped (no output dir)")
    else:
        print("[disunity] Phase 4: skipped (no focus functions)")

    print("[disunity] Done.")

    # Kill the JVM to skip Ghidra's automatic post-script re-analysis.
    # All .c files and index.json are already on disk. The Ghidra project
    # state is not needed - we'd delete it anyway on the next run (-overwrite).
    # Without this, Ghidra re-analyzes all 123K+ created functions (~4 min).
    import java.lang
    java.lang.System.exit(0)


def sanitize_name(name):
    """Convert IL2CPP method name to valid Ghidra symbol."""
    result = []
    for c in name:
        if c.isalnum() or c == '_':
            result.append(c)
        elif c in '.$$<>,/ `':
            result.append('_')
    return ''.join(result) or 'unnamed'


# Entry point for Ghidra script runner
apply_metadata()
