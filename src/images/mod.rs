/// Image model — manifests, descriptors, and image walking.
///
/// Mirrors containerd's core/images/ package:
///   - `Descriptor` maps to `ocispec.Descriptor`
///   - `Manifest` and `Index` cover both OCI and Docker Schema 2 formats
///   - Media type constants are in crate::media_types
///
/// The `AnyManifest` enum provides unified handling of all wire formats
/// so callers don't need to branch on media type themselves.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::error::{Error, Result};
use crate::media_types;
use crate::platforms::Platform;

// ── Descriptor ───────────────────────────────────────────────────────────────

/// Content-addressable descriptor for a single blob.
///
/// Mirrors `ocispec.Descriptor` from github.com/opencontainers/image-spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,

    pub digest: Digest,

    pub size: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<PlatformSpec>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

impl Descriptor {
    pub fn new(media_type: impl Into<String>, digest: Digest, size: i64) -> Self {
        Self {
            media_type: media_type.into(),
            digest,
            size,
            platform: None,
            urls: None,
            annotations: None,
        }
    }
}

// ── Platform spec (as it appears inside manifests) ───────────────────────────

/// Platform as serialised inside a manifest index.
/// Mirrors `ocispec.Platform`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSpec {
    pub os: String,
    pub architecture: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

    #[serde(rename = "os.version", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    #[serde(rename = "os.features", skip_serializing_if = "Option::is_none")]
    pub os_features: Option<Vec<String>>,
}

impl PlatformSpec {
    pub fn to_platform(&self) -> Platform {
        Platform {
            os: self.os.clone(),
            arch: self.architecture.clone(),
            variant: self.variant.clone(),
            os_version: self.os_version.clone(),
        }
    }
}

impl From<&Platform> for PlatformSpec {
    fn from(p: &Platform) -> Self {
        Self {
            os: p.os.clone(),
            architecture: p.arch.clone(),
            variant: p.variant.clone(),
            os_version: p.os_version.clone(),
            os_features: None,
        }
    }
}

// ── Single-image manifest ─────────────────────────────────────────────────────

/// A single-image manifest (OCI or Docker Schema 2).
///
/// Mirrors both `ocispec.Manifest` and Docker's manifest v2 schema 2.
/// The `media_type` field disambiguates them at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    /// Present in Docker manifests; set to the OCI media type in OCI manifests.
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Config blob descriptor.
    pub config: Descriptor,

    /// Ordered list of layer blob descriptors (bottom → top).
    pub layers: Vec<Descriptor>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

impl Manifest {
    /// Returns the effective media type, falling back to OCI if not set.
    pub fn media_type(&self) -> &str {
        self.media_type
            .as_deref()
            .unwrap_or(media_types::OCI_MANIFEST_V1)
    }

    /// Collect all descriptors that need to be transferred (config + layers).
    pub fn blobs(&self) -> Vec<&Descriptor> {
        let mut v = vec![&self.config];
        v.extend(self.layers.iter());
        v
    }
}

// ── Multi-platform manifest index ─────────────────────────────────────────────

/// A manifest index / manifest list (OCI or Docker).
///
/// Mirrors both `ocispec.Index` and Docker's manifest list v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    pub manifests: Vec<Descriptor>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

impl Index {
    /// Returns the effective media type.
    pub fn media_type(&self) -> &str {
        self.media_type
            .as_deref()
            .unwrap_or(media_types::OCI_INDEX_V1)
    }

    /// Select the manifest descriptor that best matches `platform`.
    pub fn select_platform(&self, platform: &Platform) -> Option<&Descriptor> {
        crate::platforms::best_match(platform, &self.manifests, |d| {
            d.platform.as_ref().map(|p| p.to_platform())
        })
    }
}

// ── Unified manifest enum ─────────────────────────────────────────────────────

/// All manifest formats that dcopy can handle, as a single enum.
/// This is the return type of `resolve_manifest` so callers get one value
/// and can match on the variant rather than branching on media type strings.
#[derive(Debug, Clone)]
pub enum AnyManifest {
    Manifest(Manifest),
    Index(Index),
}

impl AnyManifest {
    /// Deserialise a manifest from raw JSON bytes, using the `content_type`
    /// header returned by the registry to choose the parser.
    pub fn from_bytes(bytes: &[u8], content_type: &str) -> Result<Self> {
        // Strip content-type parameters (e.g. `; charset=utf-8`)
        let ct = content_type.split(';').next().unwrap_or("").trim();

        if media_types::is_index(ct) {
            let idx: Index = serde_json::from_slice(bytes)?;
            Ok(AnyManifest::Index(idx))
        } else if media_types::is_manifest(ct) {
            let m: Manifest = serde_json::from_slice(bytes)?;
            Ok(AnyManifest::Manifest(m))
        } else {
            // Try to auto-detect from the JSON content
            let v: serde_json::Value = serde_json::from_slice(bytes)?;
            // An index has a `manifests` array; a manifest has a `layers` array
            if v.get("manifests").is_some() {
                let idx: Index = serde_json::from_value(v)?;
                Ok(AnyManifest::Index(idx))
            } else if v.get("layers").is_some() {
                let m: Manifest = serde_json::from_value(v)?;
                Ok(AnyManifest::Manifest(m))
            } else {
                Err(Error::UnsupportedMediaType(ct.to_string()))
            }
        }
    }

    pub fn media_type(&self) -> &str {
        match self {
            AnyManifest::Manifest(m) => m.media_type(),
            AnyManifest::Index(i) => i.media_type(),
        }
    }
}

// ── Image config ──────────────────────────────────────────────────────────────

/// Top-level image configuration JSON.
/// Mirrors `ocispec.Image` / Docker's container config v1.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    #[serde(rename = "Os.Version", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

    #[serde(rename = "config", skip_serializing_if = "Option::is_none")]
    pub config: Option<ContainerConfig>,

    #[serde(rename = "rootfs", skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<RootFS>,

    #[serde(rename = "history", skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<HistoryEntry>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerConfig {
    #[serde(rename = "Env", skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "Cmd", skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,

    #[serde(rename = "Entrypoint", skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,

    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "ExposedPorts", skip_serializing_if = "Option::is_none")]
    pub exposed_ports: Option<HashMap<String, serde_json::Value>>,

    #[serde(rename = "Volumes", skip_serializing_if = "Option::is_none")]
    pub volumes: Option<HashMap<String, serde_json::Value>>,

    #[serde(rename = "WorkingDir", skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootFS {
    #[serde(rename = "type")]
    pub fs_type: String,

    #[serde(rename = "diff_ids")]
    pub diff_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HistoryEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_layer: Option<bool>,
}
