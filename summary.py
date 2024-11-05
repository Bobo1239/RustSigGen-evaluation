#!/usr/bin/env python3

from pathlib import Path
import json
import rustc_demangle_py

TARGET_PATH = Path("target")
EVALUATION_PATH = TARGET_PATH / "evaluation"

# `real_name``: `matched_name``
ALLOWED_ALIASES = {
    "_start": "start",
    "mainCRTStartup": "start",
    # These are just thunks which aren't in the signature library (too small) but get auto-named by
    # IDA. We recognize the actual jump target so these should count too.
    ## Linux
    "__rust_alloc": "j___rdl_alloc",
    "__rust_dealloc": "j___rdl_dealloc",
    "__rust_realloc": "j___rdl_realloc",
    "__rust_alloc_zeroed": "j___rdl_alloc_zeroed",
    "__rust_alloc_error_handler": "j___rg_oom",
    "_alloca_probe": "__alloca_probe",
    "rust_alloc_zeroed": "j___rdl_alloc_zeroed",
    ## MSVC
    "rust_alloc": "j___rdl_alloc",
    "rust_dealloc": "j___rdl_dealloc",
    "rust_realloc": "j___rdl_realloc",
    "rust_alloc_error_handler": "j___rg_oom",
    # Language items which are special in regards to linkage
    "std::alloc::__default_lib_allocator::__rdl_alloc": "__rdl_alloc",
    "std::alloc::__default_lib_allocator::__rdl_dealloc": "__rdl_dealloc",
    "std::alloc::__default_lib_allocator::__rdl_realloc": "__rdl_realloc",
    "std::alloc::__default_lib_allocator::__rdl_alloc_zeroed": "__rdl_alloc_zeroed",
    "std::panicking::rust_panic": "rust_panic",
    "std::sys::personality::gcc::rust_eh_personality": "rust_eh_personality",
    "std::alloc::_::__rg_oom": "__rg_oom",
    "panic_unwind::__rust_panic_cleanup": "__rust_panic_cleanup",
    "panic_unwind::__rust_start_panic": "__rust_start_panic",
}

with open(TARGET_PATH / "binaries.json") as f:
    binaries = json.loads(f.read())

for unstripped, stripped in binaries.items():
    # TODO: Make this filterable via CLI arg (supply regex?)
    # if "empty" not in unstripped:
    #     continue
    # if (
    #     unstripped != "target/1.79.0/x86_64-unknown-linux-gnu/debug/empty"
    #     and unstripped
    #     != "target/nightly-2024-06-11/x86_64-unknown-linux-gnu/debug/empty"
    # ):
    #     continue
    # if (
    #     unstripped
    #     != "target/nightly-2024-06-11/x86_64-pc-windows-msvc/release/hello_world.exe"
    # ):
    #     continue
    # if unstripped != "target/nightly-2024-06-11/x86_64-unknown-linux-gnu/release/empty":
    #     continue
    # if "rg.exe" not in unstripped or ("real_msvc" not in unstripped and "1.80.0" not in unstripped) or "gnu" in unstripped:
    #     continue
    # if "spica" not in unstripped:
    #     continue
    # if unstripped != "target/nightly/x86_64-pc-windows-gnu/release/empty.exe":
    #     continue
    # if unstripped != "target/1.80.0/x86_64-pc-windows-gnu/release/empty.exe":
    #     continue
    # if unstripped != "target/nightly/x86_64-unknown-linux-gnu/debug/empty":
    #     continue
    print(unstripped)
    is_msvc = True if stripped.endswith(".pdb") else False

    rel_path = Path(unstripped).relative_to(TARGET_PATH)
    out_path = EVALUATION_PATH / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if unstripped != stripped:
        with open(f"{out_path}.reference") as f:
            reference = json.load(f)
        with open(f"{out_path}.matched") as f:
            matched = json.load(f)

        ok = 0
        different_hash = 0
        sig_collision = 0
        wrong = 0
        missed = 0
        total = 0
        for addr, real_name in reference.items():
            total += 1
            if addr in matched:
                real_name = real_name.strip("_0")
                matched_name = matched[addr].strip("_0")

                real_demangled = rustc_demangle_py.demangle(real_name)
                matched_demangled = rustc_demangle_py.demangle(matched_name)

                if matched_name.startswith("?"):
                    real_demangled = rustc_demangle_py.demangle_msvc(real_name)
                    matched_demangled = rustc_demangle_py.demangle_msvc(matched_name)

                real_demangled_no_hash = rustc_demangle_py.demangle_no_hash(real_name)
                matched_demangled_no_hash = rustc_demangle_py.demangle_no_hash(
                    matched_name
                )

                # Sometimes symbols are missing even in the unstripped binary
                if (
                    real_demangled == matched_demangled
                    or "__" + real_demangled == matched_demangled
                    or (
                        real_name.startswith("sub_")
                        and not matched_name.startswith("sub_")
                    )
                    or (real_name, matched_name) in ALLOWED_ALIASES.items()
                ):
                    ok += 1
                elif real_demangled_no_hash == matched_demangled_no_hash:
                    # print(real_name)
                    # print(matched_name)
                    different_hash += 1
                elif matched_name.startswith("unknown_libname_"):
                    # print(rustc_demangle_py.demangle(real_name))
                    sig_collision += 1
                elif matched_name.startswith("sub_"):
                    # assert not real_demangled.startswith("sub_")
                    # print(real_demangled)
                    missed += 1
                else:
                    # print(real_demangled)
                    # print(matched_demangled)
                    # print("----")
                    wrong += 1
            else:
                # TODO
                # assert False
                pass

        print(
            f"  {ok + different_hash + sig_collision} / {total} (ok: {ok}, different_hash: {different_hash}, sig_collision: {sig_collision}, wrong: {wrong}, missed: {missed})"
        )
    else:
        with open(f"{out_path}.matched") as f:
            matched = json.load(f)

        total = 0
        missed = 0
        ok = 0
        for addr, matched in matched.items():
            total += 1
            if matched.startswith("sub_"):
                missed += 1
            else:
                ok += 1

        print(f"  {ok} / {total} (no reference symbols)")
