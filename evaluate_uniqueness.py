#!/usr/bin/env python3

from pathlib import Path
import subprocess
import json

import idapro
import ida_undo
import ida_idp
import ida_funcs
import ida_auto

# NOTE: `signature_generator` needs to be available in $PATH

# TODO: Meh...
FLAIR_PATH = Path("~/master_thesis/ida/flair90/").expanduser()

TARGET_PATH = Path("target")
EVALUATION_PATH = TARGET_PATH / "evaluation"
SIGNATURES_OUT_PATH = TARGET_PATH / "uniqueness_sigs"


class sig_hooks_t(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.matched_funcs = set()

    def func_added(self, pfn):
        self.matched_funcs.add(pfn.start_ea)

    def func_updated(self, pfn):
        self.matched_funcs.add(pfn.start_ea)


# Adapted from idalib's idacli.py example
def apply_sig_file(sig_file_name):
    sig_hook = sig_hooks_t()
    sig_hook.hook()

    ida_funcs.plan_to_apply_idasgn(sig_file_name)
    ida_auto.auto_wait()

    match_count = 0
    for index in range(0, ida_funcs.get_idasgn_qty()):
        fname, _, fmatches = ida_funcs.get_idasgn_desc_with_matches(index)
        if fname in sig_file_name:
            match_count = fmatches
            break

    return match_count


with open(TARGET_PATH / "binaries_uniqueness.json") as f:
    binaries = json.loads(f.read())

if len(list(SIGNATURES_OUT_PATH.glob("*.sig"))) < len(binaries):
    for unstripped, stripped in binaries.items():
        print(unstripped, stripped)

        subprocess.check_output(
            [
                "signature_generator",
                "-f",
                str(FLAIR_PATH),
                stripped,
                str(SIGNATURES_OUT_PATH),
            ],
        )
sigs = sorted(list(SIGNATURES_OUT_PATH.glob("*.sig")))
bins_stripped = sorted(binaries.values())

versions = []
for i in range(len(bins_stripped)):
    bin_ver = Path(bins_stripped[i]).parts[1]
    sig_ver = (
        sigs[i].name.removeprefix("rust-std-").removesuffix(".sig").replace("-", ".")
    )
    assert bin_ver == sig_ver
    versions.append(bin_ver)

matrix = []
for binary in bins_stripped:
    print(binary)
    row = []

    # Open database and wait for auto-analysis
    idapro.open_database(binary, True)

    for sig in sigs:
        assert ida_undo.create_undo_point(b"pre_sig")
        match_count = apply_sig_file(str(sig.absolute()))
        row.append(match_count)
        print(sig, match_count)
        assert ida_undo.perform_undo()
    matrix.append(row)

    # Close database without saving
    idapro.close_database(False)

print(versions)
print(matrix)
