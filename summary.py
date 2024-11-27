#!/usr/bin/env python3

import argparse
import json
import re
from collections import ChainMap
from pathlib import Path

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

parser = argparse.ArgumentParser()
parser.add_argument(
    "mode", choices=["std", "crates"], help="mode, either std or crates"
)
parser.add_argument(
    "filter", nargs="?", help="optional regex to filter which binaries to consider"
)
args = parser.parse_args()

with open(TARGET_PATH / "binaries.json") as f:
    binaries = json.loads(f.read())

match args.mode:
    case "std":
        k_filter = [k for k in binaries.keys() if k != "uniqueness"]
        matched_extension = "matched"
    case "crates":
        k_filter = ["oss_projects", "malware_samples"]
        matched_extension = "matched_with_crates"
binaries = ChainMap(*[binaries[k] for k in binaries.keys() if k in k_filter])


def remove_number_suffix(symbol: str):
    if re.match(r"(sub|unknown_libname)_\d+$", symbol):
        return symbol
    else:
        return re.sub(r"_\d+$", "", symbol)


def remove_at_suffix(symbol: str):
    return re.sub(r"@\d+$", "", symbol)


for unstripped, stripped in binaries.items():
    if args.filter:
        if not re.search(args.filter, unstripped):
            continue

    print(unstripped)
    is_msvc = True if stripped.endswith(".pdb") else False

    rel_path = Path(unstripped).relative_to(TARGET_PATH)
    out_path = EVALUATION_PATH / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if unstripped != stripped:
        with open(f"{out_path}.reference") as f:
            reference = json.load(f)
        with open(f"{out_path}.{matched_extension}") as f:
            matched = json.load(f)

        ok = 0
        different_hash = 0
        sig_collision = 0
        wrong = 0
        missed = 0
        total = 0
        unknown = 0
        for addr, real_name in reference.items():
            total += 1
            if addr in matched:
                # Strip trailing _0, _1, ... which gets added by IDA (I believe since the same
                # signature is in multiple signature libraries?) We need this since it messes up the
                # demangler and it doesn't matter to our goal. Also strip out leading/trailing `_`
                # which don't matter and are sometimes different between real and matched name...
                real_name = remove_number_suffix(real_name).strip("_")
                matched_name = remove_number_suffix(matched[addr]).strip("_")

                # Demangle
                real_demangled = rustc_demangle_py.demangle(real_name)
                matched_demangled = rustc_demangle_py.demangle(matched_name)

                if matched_name.startswith("?"):
                    # MSVC symbol mangling
                    real_demangled = rustc_demangle_py.demangle_msvc(real_name)
                    matched_demangled = rustc_demangle_py.demangle_msvc(matched_name)

                # Remove trailing `@n` suffix which gets added by IDA for i686 binaries (ref:
                # https://stackoverflow.com/a/68767175)
                real_demangled = remove_at_suffix(real_demangled)
                matched_demangled = remove_at_suffix(matched_demangled)

                # Demangle without function hash suffix
                real_demangled_no_hash = rustc_demangle_py.demangle_no_hash(real_name)
                matched_demangled_no_hash = rustc_demangle_py.demangle_no_hash(
                    matched_name
                )

                # Sometimes symbols are missing even in the unstripped binary
                if real_name.startswith("sub_") and matched_name.startswith("sub_"):
                    unknown += 1
                elif (
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
            f"  {ok + different_hash + sig_collision} / {total} (ok: {ok}, different_hash: {different_hash}, sig_collision: {sig_collision}, wrong: {wrong}, missed: {missed}, unknown: {unknown})"
        )
    else:
        try:
            with open(f"{out_path}.{matched_extension}") as f:
                matched = json.load(f)
        except FileNotFoundError:
            continue

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
