/// Platform specification and matching.
///
/// Mirrors github.com/containerd/platforms — same normalisation rules,
/// same matching semantics.
use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// An OCI platform descriptor (os/arch/variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub variant: Option<String>,
    pub os_version: Option<String>,
}

impl Platform {
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
            variant: None,
            os_version: None,
        }
    }

    /// Returns the default platform for container image selection.
    ///
    /// Mirrors containerd's `platforms.Default()`:
    /// container images are always Linux, so on non-Linux hosts (e.g. macOS,
    /// Windows with Docker Desktop) we default to `linux/<host-arch>` — the
    /// same behaviour as `docker pull` on those platforms.
    pub fn host() -> Self {
        let arch = normalize_arch(std::env::consts::ARCH);
        let variant = host_variant(std::env::consts::ARCH);
        Self {
            os: "linux".to_string(),
            arch,
            variant,
            os_version: None,
        }
    }

    /// linux/amd64
    pub fn linux_amd64() -> Self {
        Self::new("linux", "amd64")
    }

    /// linux/arm64
    pub fn linux_arm64() -> Self {
        let mut p = Self::new("linux", "arm64");
        p.variant = Some("v8".to_string());
        p
    }
}

/// Normalise Rust arch strings to OCI/Go GOARCH names.
/// Mirrors containerd's platforms/cpuvariant_linux.go normalisation.
fn normalize_arch(rust_arch: &str) -> String {
    match rust_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "x86" => "386",
        "powerpc64" => "ppc64",
        "powerpc64le" => "ppc64le",
        "s390x" => "s390x",
        "mips" => "mips",
        "mips64" => "mips64",
        "riscv64" => "riscv64",
        other => other,
    }
    .to_string()
}

fn host_variant(rust_arch: &str) -> Option<String> {
    match rust_arch {
        "aarch64" => Some("v8".to_string()),
        _ => None,
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

impl FromStr for Platform {
    type Err = Error;

    /// Parse `os/arch` or `os/arch/variant` strings.
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, '/').collect();
        match parts.as_slice() {
            [os, arch] => Ok(Self::new(*os, normalize_arch(arch))),
            [os, arch, variant] => {
                let mut p = Self::new(*os, normalize_arch(arch));
                p.variant = Some(variant.to_string());
                Ok(p)
            }
            _ => Err(Error::Other(format!("invalid platform spec: {s}"))),
        }
    }
}

/// Returns true when `candidate` satisfies the `spec`.
///
/// An unset variant in `spec` matches any variant in `candidate`.
/// Mirrors containerd's `platforms.Match`.
pub fn matches(spec: &Platform, candidate: &Platform) -> bool {
    if spec.os != candidate.os || spec.arch != candidate.arch {
        return false;
    }
    if let Some(sv) = &spec.variant {
        if let Some(cv) = &candidate.variant {
            return sv == cv;
        }
        return false;
    }
    true
}

/// From a list of platform entries (from a manifest index) select the best
/// match for `spec`, using the same preference order as containerd's
/// `platforms.Only` / `platforms.Ordered` matchers.
pub fn best_match<'a, T, F>(spec: &Platform, items: &'a [T], platform_of: F) -> Option<&'a T>
where
    F: Fn(&T) -> Option<Platform>,
{
    // 1. Exact match (os + arch + variant)
    for item in items {
        if let Some(p) = platform_of(item) {
            if p.os == spec.os && p.arch == spec.arch && p.variant == spec.variant {
                return Some(item);
            }
        }
    }
    // 2. os + arch match (ignore variant)
    for item in items {
        if let Some(p) = platform_of(item) {
            if p.os == spec.os && p.arch == spec.arch {
                return Some(item);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(Platform::linux_amd64().to_string(), "linux/amd64");
        assert_eq!(Platform::linux_arm64().to_string(), "linux/arm64/v8");
    }

    #[test]
    fn parse_roundtrip() {
        let p: Platform = "linux/arm64/v8".parse().unwrap();
        assert_eq!(p.os, "linux");
        assert_eq!(p.arch, "arm64");
        assert_eq!(p.variant, Some("v8".to_string()));
    }
}
