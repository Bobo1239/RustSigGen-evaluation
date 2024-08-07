#!/usr/bin/env python3

from pathlib import Path
import subprocess
import json

# TODO: Filter out extern functions (they don't have a stable address)

TARGET_PATH = Path("target")
EVALUATION_PATH = TARGET_PATH / "evaluation"

with open(TARGET_PATH / "binaries.json") as f:
    binaries = json.loads(f.read())

for unstripped, stripped in binaries.items():
    print(unstripped)
    is_msvc = True if stripped.endswith(".pdb") else False

    rel_path = Path(unstripped).relative_to(TARGET_PATH)
    out_path = EVALUATION_PATH / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    out_path_ref = out_path.absolute().with_suffix(out_path.suffix + ".reference")
    out_path_matched = out_path.absolute().with_suffix(out_path.suffix + ".matched")

    if unstripped != stripped:
        # Ground truth symbols; for MSVC this will autoload the .pdb
        if not out_path_ref.exists():
            subprocess.check_output(
                [
                    "ida64",
                    "-c",  # Ignore old db
                    "-A",  # No dialog boxes
                    f"-S{Path(__file__).parent}/ida_evaluation.py {out_path_ref} nomatch",
                    unstripped,
                ]
            )

    # Symbols detected using signatures
    if not out_path_matched.exists():
        subprocess.check_output(
            [
                "ida64",
                "-c",
                "-A",
                "-Opdb:off",  # Disable .pdb loading so we have no symbols a priori
                f"-S{Path(__file__).parent}/ida_evaluation.py {out_path_matched} match",
                unstripped if is_msvc else stripped,
            ],
        )
