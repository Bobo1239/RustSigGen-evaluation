#!/usr/bin/env python3

import json
import os
import subprocess
from pathlib import Path

import idapro
import ida_auto
import ida_funcs
import ida_segment
import ida_undo
import idautils

from shared import FLAIR_PATH, TARGET_PATH, THESIS_DATA_PATH

# NOTE: `signature_generator` needs to be available in $PATH

EVALUATION_PATH = TARGET_PATH / "evaluation"
SIGNATURES_OUT_PATH = TARGET_PATH / "uniqueness_sigs"


# Adapted from idalib's idacli.py example
def apply_sig_file(sig_file_name):
    ida_funcs.plan_to_apply_idasgn(sig_file_name)
    ida_auto.auto_wait()

    match_count = 0
    for index in range(0, ida_funcs.get_idasgn_qty()):
        fname, _, fmatches = ida_funcs.get_idasgn_desc_with_matches(index)
        if fname in sig_file_name:
            match_count = fmatches
            break

    return match_count


with open(TARGET_PATH / "binaries.json") as f:
    binaries = json.loads(f.read())
    binaries = binaries["uniqueness"]

if len(list(SIGNATURES_OUT_PATH.glob("*.sig"))) < len(binaries):
    for unstripped, stripped in binaries.items():
        print(unstripped, stripped)

        subprocess.check_output(
            [
                "signature_generator",
                "-f",
                str(FLAIR_PATH),
                "-o",
                str(SIGNATURES_OUT_PATH),
                "std",
                stripped,
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
total_functions = []
for binary in bins_stripped:
    print(binary)
    row = []

    # Open database and wait for auto-analysis
    idapro.open_database(binary, True)

    # Get total number of functions
    total = 0
    for ea in idautils.Functions():
        # Ignore imports; only works properly for Linux which suffices here
        if ida_segment.get_segm_name(ida_segment.getseg(ea)) == "extern":
            continue
        total += 1
    total_functions.append(total)

    for sig in sigs:
        assert ida_undo.create_undo_point(b"pre_sig")
        match_count = apply_sig_file(str(sig.absolute()))
        row.append(match_count)
        print(sig, match_count)
        assert ida_undo.perform_undo()
    matrix.append(row)

    # Close database without saving
    idapro.close_database(False)

os.makedirs(THESIS_DATA_PATH, exist_ok=True)
with open(THESIS_DATA_PATH / "uniqueness.json", "w") as f:
    f.write(
        json.dumps(
            {
                "versions": versions,
                "total_functions": total_functions,
                "matrix": matrix,
            }
        )
    )
