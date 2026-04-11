# disunity prescript for Ghidra headless analysis
# Run BEFORE analysis to disable analyzers that are unnecessary for IL2CPP.
# We supply all function addresses, names, and string refs from metadata,
# so discovery/search passes are redundant. This saves ~2 minutes.
#
# Usage: analyzeHeadless ... -preScript disunity_prescript.py
#
#@category IL2CPP
#@author disunity

def run():
    options = currentProgram.getOptions("Analyzers")

    # Analyzers to disable (IL2CPP-specific rationale):
    disabled = [
        # We supply all function starts from IL2CPP CodeRegistration
        "Aggressive Instruction Finder",
        "Function Start Search",
        "Function Start Search After Code",
        "Function Start Search After Data",

        # IL2CPP uses its own exception model, not GCC unwinding
        "GCC Exception Handlers",

        # We supply all function names from metadata
        "Demangler GNU",
        "Function ID",

        # We supply string refs from global-metadata.dat
        "ASCII Strings",

        # IL2CPP code doesn't use standard jump tables
        "Create Address Tables",

        # Not useful for stripped IL2CPP binaries
        "Embedded Media",
        "Apply Data Archives",
        "DWARF",
    ]

    count = 0
    for name in disabled:
        try:
            options.setBoolean(name, False)
            count += 1
        except Exception:
            pass  # analyzer name may vary across Ghidra versions

    print("[disunity] Disabled %d/%d unnecessary analyzers" % (count, len(disabled)))

run()
