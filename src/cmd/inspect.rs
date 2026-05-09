/// `dcopy inspect` — show image metadata.
///
/// Mirrors `skopeo inspect` — fetches the manifest and config from the registry
/// and prints image metadata as JSON without pulling the full image layers.
use serde::Serialize;
use tracing::debug;

use crate::error::{Error, Result};
use crate::images::{AnyManifest, Descriptor, ImageConfig};
use crate::platforms::Platform;
use crate::reference::{ImageRef, Transport};
use crate::remotes::docker::{auth::Credentials, DockerResolver};
use crate::remotes::{Fetcher, Resolver as _};

pub struct InspectOptions {
    pub creds: Option<Credentials>,
    /// Dump the raw manifest JSON instead of the formatted output.
    pub raw: bool,
    /// Dump the raw config JSON.
    pub config: bool,
    /// Override platform (for index images).
    pub platform: Option<Platform>,
}

impl Default for InspectOptions {
    fn default() -> Self {
        Self {
            creds: None,
            raw: false,
            config: false,
            platform: None,
        }
    }
}

/// The structured output of `dcopy inspect`.
/// Mirrors skopeo's `inspectOutput` struct.
#[derive(Debug, Serialize)]
pub struct InspectOutput {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Digest")]
    pub digest: String,
    #[serde(rename = "RepoTags")]
    pub repo_tags: Vec<String>,
    #[serde(rename = "Created")]
    pub created: Option<String>,
    #[serde(rename = "DockerVersion")]
    pub docker_version: String,
    #[serde(rename = "Labels")]
    pub labels: std::collections::HashMap<String, String>,
    #[serde(rename = "Architecture")]
    pub architecture: String,
    #[serde(rename = "Os")]
    pub os: String,
    #[serde(rename = "Layers")]
    pub layers: Vec<String>,
    #[serde(rename = "Env")]
    pub env: Vec<String>,
}

pub async fn run(reference: &str, mut opts: InspectOptions) -> Result<()> {
    let image_ref: ImageRef = reference.parse()?;

    match image_ref.transport {
        Transport::Docker => {
            let dr = image_ref.docker.as_ref().unwrap();
            let resolver = match opts.creds.take() {
                Some(c) => DockerResolver::with_credentials(&dr.registry, &dr.repository, c),
                None => DockerResolver::new(&dr.registry, &dr.repository),
            };
            inspect_docker(&resolver, &dr.reference(), &dr.name(), opts).await
        }
        t => Err(Error::UnsupportedTransport(t.to_string())),
    }
}

async fn inspect_docker(
    resolver: &DockerResolver,
    reference: &str,
    name: &str,
    opts: InspectOptions,
) -> Result<()> {
    let (raw, content_type, digest) = resolver.fetch_manifest_raw(reference).await?;

    if opts.raw {
        println!("{}", String::from_utf8_lossy(&raw));
        return Ok(());
    }

    let manifest = AnyManifest::from_bytes(&raw, &content_type)?;

    // Resolve to a single-image manifest (select platform from index if needed)
    let (single_manifest, manifest_digest) = match manifest {
        AnyManifest::Index(idx) => {
            let platform = opts.platform.clone().unwrap_or_else(Platform::host);
            let desc = idx
                .select_platform(&platform)
                .ok_or_else(|| Error::PlatformNotFound(platform.to_string()))?
                .clone();
            debug!(platform = %platform, "resolved to platform manifest");
            let (pm_raw, pm_ct, pm_digest) =
                resolver.fetch_manifest_raw(&desc.digest.to_string()).await?;
            let pm = AnyManifest::from_bytes(&pm_raw, &pm_ct)?;
            match pm {
                AnyManifest::Manifest(m) => (m, pm_digest),
                _ => return Err(Error::Other("nested index not supported".to_string())),
            }
        }
        AnyManifest::Manifest(m) => (m, digest),
    };

    if opts.config {
        let config_data = fetch_config(resolver, &single_manifest.config).await?;
        println!("{}", String::from_utf8_lossy(&config_data));
        return Ok(());
    }

    // Fetch the image config to get OS/arch/env/labels
    let config_data = fetch_config(resolver, &single_manifest.config).await?;
    let config: ImageConfig = serde_json::from_slice(&config_data).unwrap_or_default();

    let layers: Vec<String> = single_manifest
        .layers
        .iter()
        .map(|d| d.digest.to_string())
        .collect();

    let container_cfg = config.config.unwrap_or_default();

    let output = InspectOutput {
        name: name.to_string(),
        digest: manifest_digest,
        repo_tags: vec![], // populated from tag listing if needed
        created: config.created,
        docker_version: String::new(),
        labels: container_cfg.labels.unwrap_or_default(),
        architecture: config.architecture.unwrap_or_else(|| "unknown".to_string()),
        os: config.os.unwrap_or_else(|| "unknown".to_string()),
        layers,
        env: container_cfg.env.unwrap_or_default(),
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn fetch_config(resolver: &DockerResolver, desc: &Descriptor) -> Result<bytes::Bytes> {
    let fetcher: Box<dyn Fetcher> = resolver.fetcher("").await?;
    fetcher.fetch_all(desc).await
}
