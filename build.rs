/// build.rs — compile the Go CGo wrapper that uses containerd's Docker
/// registry libraries and link the resulting static archive into the Rust binary.
///
/// The Go code lives in `go/` and produces a C-compatible static library
/// (`libdcopy_go.a`) that the Rust code calls via `src/ffi.rs`.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let go_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("go");
    let lib_path = out_dir.join("libdcopy_go.a");

    // ── Compile the Go c-archive ──────────────────────────────────────────────
    let status = Command::new("go")
        .env("CGO_ENABLED", "1")
        .env("GOTOOLCHAIN", "local")
        // Clear GOFLAGS so cargo's environment doesn't interfere
        .env("GOFLAGS", "")
        .args([
            "build",
            "-buildmode=c-archive",
            "-o",
            lib_path.to_str().unwrap(),
            ".",
        ])
        .current_dir(&go_dir)
        .status()
        .expect("failed to run `go build` — is Go installed?");

    assert!(
        status.success(),
        "go build -buildmode=c-archive failed (exit {status})"
    );

    // ── Tell cargo where the archive lives ────────────────────────────────────
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=dcopy_go");

    // ── Platform-specific link flags required by CGo ─────────────────────────
    //
    // CGo embeds the Go runtime, which depends on OS frameworks/libraries.
    // These mirror what `go tool cgo -ldflags` would emit.

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_os.as_str() {
        "macos" => {
            // macOS: CGo needs these frameworks for TLS, DNS resolution, etc.
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=SystemConfiguration");
            println!("cargo:rustc-link-lib=framework=Foundation");
            println!("cargo:rustc-link-lib=framework=CFNetwork");
            println!("cargo:rustc-link-lib=resolv");
        }
        "linux" => {
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=dl");
            println!("cargo:rustc-link-lib=m");
            println!("cargo:rustc-link-lib=resolv");
        }
        _ => {}
    }

    // ── Re-run triggers ───────────────────────────────────────────────────────
    println!("cargo:rerun-if-changed=go/libdcopy.go");
    println!("cargo:rerun-if-changed=go/go.mod");
    println!("cargo:rerun-if-changed=go/go.sum");
}
