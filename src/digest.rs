/// OCI content-addressable digest.
///
/// Mirrors github.com/opencontainers/go-digest — same format `algorithm:hex`,
/// same algorithm names (`sha256`, `sha512`), same validation rules.
use std::fmt;
use std::str::FromStr;

use sha2::{Digest as Sha2Digest, Sha256, Sha512};

use crate::error::{Error, Result};

/// A validated OCI digest in the form `algorithm:hex`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    algorithm: Algorithm,
    hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Sha256 => write!(f, "sha256"),
            Algorithm::Sha512 => write!(f, "sha512"),
        }
    }
}

impl Digest {
    /// Compute the SHA-256 digest of raw bytes.
    pub fn sha256_of(data: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(data);
        Self {
            algorithm: Algorithm::Sha256,
            hex: hex::encode(h.finalize()),
        }
    }

    /// Compute the SHA-512 digest of raw bytes.
    pub fn sha512_of(data: &[u8]) -> Self {
        let mut h = Sha512::new();
        h.update(data);
        Self {
            algorithm: Algorithm::Sha512,
            hex: hex::encode(h.finalize()),
        }
    }

    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Returns the short form used as a human-readable identifier (first 12 hex chars).
    pub fn short(&self) -> &str {
        &self.hex[..12.min(self.hex.len())]
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (algo_str, hex) = s
            .split_once(':')
            .ok_or_else(|| Error::InvalidDigest(s.to_string()))?;

        if hex.is_empty() {
            return Err(Error::InvalidDigest(s.to_string()));
        }

        let algorithm = match algo_str {
            "sha256" => Algorithm::Sha256,
            "sha512" => Algorithm::Sha512,
            other => return Err(Error::InvalidDigest(format!("unknown algorithm: {other}"))),
        };

        // Basic hex validation
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidDigest(format!("invalid hex in digest: {s}")));
        }

        Ok(Self {
            algorithm,
            hex: hex.to_string(),
        })
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let d = Digest::sha256_of(b"hello");
        let s = d.to_string();
        let d2: Digest = s.parse().unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn known_sha256() {
        // echo -n "" | sha256sum → e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let d = Digest::sha256_of(b"");
        assert_eq!(
            d.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
