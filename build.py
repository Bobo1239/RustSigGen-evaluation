#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
from io import BytesIO
from pathlib import Path

import requests
from pyzipper import AESZipFile
from tomlkit.toml_file import TOMLFile

# NOTE: Need to use git version of cargo-xwin until there's a release with https://github.com/rust-cross/cargo-xwin/commit/13af95154fce77793001b29b8afc06b73dd0c879
#       (`cargo install --git https://github.com/rust-cross/cargo-xwin.git cargo-xwin`)

TARGET_PATH = Path("target")

# NOTE: The first target/version will be used for builds which don't cover the whole matrix
# NOTE: The beta release is the first one for Rust 1.80 (which was eventually released 2024-07-25)
#       (see https://releases.rs)
TARGETS = [
    "x86_64-unknown-linux-gnu",
    # NOTE: MUSL is currently always statically links the libc but this should change in the future: https://github.com/rust-lang/compiler-team/issues/422
    "x86_64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "x86_64-pc-windows-gnu",
    "i686-pc-windows-msvc",
    "i686-pc-windows-gnu",
]
VERSIONS = ["1.80.1", "1.79.0", "beta-2024-06-11", "nightly-2024-06-11"]

VERSIONS_UNIQUENESS = [
    "1.82.0",
    "1.81.0",
    "1.80.1",
    "1.80.0",
    "1.79.0",
    "1.78.0",
    "1.77.2",
    "1.77.1",
    "1.77.0",
]
BIN_UNIQUENESS = "hello_world"


def build_and_copy_to_target(crate_dir, version, target, mode, bins, binaries):
    bin_ext = ".exe" if "windows" in target else ""
    profile = "release" if mode == "release" else "dev"
    is_msvc = target.endswith("-msvc")
    cargo_command = [
        "cargo",
        f"+{version}",
        "xwin" if is_msvc else None,
        "build",
        "--profile",
        profile,
        "--target",
        target,
    ]
    # NOTE: If building fails with strange linker errors when targeting MSVC try removing
    #       cargo-xwin's cache: `rm -r ~/.cache/cargo-xwin/`
    subprocess.check_call(
        [x for x in cargo_command if x],
        cwd=crate_dir,
        env=dict(os.environ, XWIN_INCLUDE_DEBUG_SYMBOLS="true", XWIN_ARCH="x86,x86_64"),
    )

    for binary in bins:
        common = f"{target}/{mode}/{binary}{bin_ext}"
        in_path = crate_dir / "target" / common
        out_path = TARGET_PATH / version / common

        out_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(in_path, out_path)

        # Don't need to strip MSVC binaries since their debug info is external
        # anyways; MinGW binaries do use DWARF though!
        if is_msvc:
            # Instead copy the `.pdb` so we have ground-truth data. We can disable
            # loading of the debug info via `-Opdb:off` in the CLI.
            shutil.copy(in_path.with_suffix(".pdb"), out_path.with_suffix(".pdb"))
            binaries[out_path] = out_path.with_suffix(".pdb")
        else:
            out_path_stripped = out_path.with_suffix(out_path.suffix + ".stripped")
            subprocess.check_output(["strip", "-o", out_path_stripped, out_path])
            binaries[out_path] = out_path_stripped


def build_examples():
    binaries = {}
    examples_dir = Path("examples")
    metadata_json = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=examples_dir,
    )
    metadata = json.loads(metadata_json.decode())
    bins = [t["name"] for t in metadata["packages"][0]["targets"]]
    print("Example binaries:", bins)

    for version in VERSIONS:
        for target in TARGETS:
            for mode in ["debug", "release"]:
                build_and_copy_to_target(
                    examples_dir, version, target, mode, bins, binaries
                )
    return binaries


def build_examples_uniqueness():
    binaries = {}
    for version in VERSIONS_UNIQUENESS:
        build_and_copy_to_target(
            Path("examples"), version, TARGETS[0], "release", [BIN_UNIQUENESS], binaries
        )
    return binaries


def build_oss_projects():
    binaries = {}
    base_dir = Path("oss_projects")
    projects = [p.name for p in base_dir.glob("*")]
    print("OSS Projects:", projects)

    # If Cargo.toml is not in root directory
    special_toml_paths = {"resvg": "crates/resvg/Cargo.toml"}

    for proj in projects:
        for mode in ["debug", "release"]:
            version = VERSIONS[0]
            target = TARGETS[0]
            bins = ["rg" if proj == "ripgrep" else proj]
            proj_dir = base_dir / proj

            # Reset repo
            subprocess.check_call(["git", "reset", "--hard"], cwd=proj_dir)

            toml_path = proj_dir / "Cargo.toml"
            if proj in special_toml_paths:
                toml_path = proj_dir / special_toml_paths[proj]

            # Remove path dependencies (so crates.io versions get used)
            # NOTE: We do this since we want to evaluate how well we can recognize functions in
            #       dependencies and local path dependencies can't be recognized. On the other hand
            #       if the final crate is just a thin facade for a dependency which contains most of
            #       the actual implementation this will tell us nothing...
            f = TOMLFile(toml_path)
            cargo_toml = f.read()
            for k, v in cargo_toml["dependencies"].items():
                if "version" in v and "path" in v:
                    del v["path"]
                    print(f"Removed path dependency on crate {k}.")
            f.write(cargo_toml)

            build_and_copy_to_target(proj_dir, version, target, mode, bins, binaries)
    return binaries


# NOTE: Binaries built in a Windows VM
def copy_real_windows_binaries():
    binaries = {}
    metadata_json = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1"],
        cwd="examples",
    )
    metadata = json.loads(metadata_json.decode())
    bins = [t["name"] for t in metadata["packages"][0]["targets"]]

    for mode in ["debug", "release"]:
        for binary in bins:
            common = f"{mode}/{binary}.exe"
            in_path = Path("prebuilt_binaries") / "real_windows" / "examples" / common
            # TODO: Update Windows binaries to 1.80.1
            # NOTE: real_windows used Rust 1.80.0
            out_path = TARGET_PATH / "1.80.0" / "real_windows" / common

            out_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(in_path, out_path)
            shutil.copy(in_path.with_suffix(".pdb"), out_path.with_suffix(".pdb"))
            binaries[out_path] = out_path.with_suffix(".pdb")

        for oss in ["rg"]:
            common = f"{mode}/{oss}.exe"
            in_path = Path("prebuilt_binaries") / "real_windows" / "rg" / common
            # NOTE: `real_windows` used Rust 1.80.0 (msvc)
            out_path = TARGET_PATH / "1.80.0" / "real_windows" / common

            out_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(in_path, out_path)
            shutil.copy(in_path.with_suffix(".pdb"), out_path.with_suffix(".pdb"))
            binaries[out_path] = out_path.with_suffix(".pdb")
    return binaries


def get_malware_samples():
    # https://github.com/cxiao/rust-malware-gallery
    # NOTE: Sources to consider: https://bazaar.abuse.ch; https://malshare.com
    # TODO: Add comments about which target each sample uses
    MALWARE = [
        (
            "37c52481711631a5c73a6341bd8bea302ad57f02199db7624b580058547fb5a9",
            "spica.exe",
        ),
        (
            "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6",
            "blackcat.elf",
        ),
        (
            "7bb383b31d1b415bc067e612203cc6bda53e914f7ca5291299e92f59d47cabf8",
            "blackcat.exe",
        ),
        (
            "35d8eb3a18f55806333f187f295df747150048c5cdd011acba9e294fa57ad991",
            "rustystealer.exe",
        ),
        (
            "030eb56e155fb01d7b190866aaa8b3128f935afd0b7a7b2178dc8e2eb84228b0",
            "krustyloader.elf",
        ),
    ]
    ZIP_PASSWORD = b"infected"

    binaries = {}
    for hash, name in MALWARE:
        out_path = TARGET_PATH / "malware" / f"{name}.do_not_exec"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        binaries[out_path] = out_path
        if out_path.exists():
            continue

        data = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_file", "sha256_hash": hash},
        ).content

        data = BytesIO(data)
        with AESZipFile(data, "r") as zip_file:
            with open(out_path, "wb") as f:
                extraceted_bytes = zip_file.read(zip_file.filelist[0], pwd=ZIP_PASSWORD)
                f.write(extraceted_bytes)
    return binaries


def prepare_toolchains():
    print("Preparing toolchains...")

    installed_versions = (
        subprocess.check_output(["rustup", "toolchain", "list"])
        .decode()
        .strip()
        .split("\n")
    )
    installed_versions = [
        line.split(" ")[0].removesuffix("-x86_64-unknown-linux-gnu")
        for line in installed_versions
    ]

    # Install missing versions
    missing_versions = (set(VERSIONS) | set(VERSIONS_UNIQUENESS)).difference(
        installed_versions
    )
    for version in missing_versions:
        subprocess.check_output(
            ["rustup", "toolchain", "install", version, "--profile", "minimal"]
        )

    # Install targets (if missing)
    for version in VERSIONS:
        subprocess.check_output(
            ["rustup", f"+{version}", "target", "add"] + TARGETS,
            stderr=subprocess.DEVNULL,
        )


TARGET_PATH.mkdir(exist_ok=True)
prepare_toolchains()

# TODO: Other way around would be better since we don't always have an unstripped bin
# Map: unstripped bin -> stripped bin
categories = {
    "examples": build_examples(),
    # NOTE: Disabled since the binaries need updating and there's no good way to automate this
    #       process; The results are effectively the same as with cargo-xwin anyways...
    # "real_windows": copy_real_windows_binaries(),
    "oss_projects": build_oss_projects(),
    "malware_samples": get_malware_samples(),
    "uniqueness": build_examples_uniqueness(),
}

json_struct = {}
total = 0
for category, binaries in categories.items():
    json_struct[category] = {str(k): str(v) for k, v in binaries.items()}
    print(f"{category}: {len(binaries)} binaries")
    total += len(binaries)
print(f"Total: {total} binaries")

with open(TARGET_PATH / "binaries.json", "w") as f:
    f.write(json.dumps(json_struct))
