binaries := `cargo metadata --format-version 1 | jq ".packages[0].targets.[] | .name"`
default_rustc_version := "1.78"

build rustc_version=default_rustc_version: (build_release rustc_version) (build_debug rustc_version)

build_release rustc_version:
    cargo +{{rustc_version}} build --release
    rm -rf target/stripped_release
    mkdir target/stripped_release
    echo "{{binaries}}" | xargs -I = strip -o target/stripped_release/= target/release/=

build_debug rustc_version:
    cargo +{{rustc_version}} build
    rm -rf target/stripped_debug
    mkdir target/stripped_debug
    echo "{{binaries}}" | xargs -I = strip -o target/stripped_debug/= target/debug/=
