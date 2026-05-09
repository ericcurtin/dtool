/// Docker Registry resolver backed by containerd's Go library.
///
/// All registry operations (resolve, fetch manifest, fetch blob, push blob,
/// push manifest, list tags) are delegated to the CGo wrapper in
/// `go/libdcopy.go`, which uses:
///
///   github.com/containerd/containerd/v2/core/remotes/docker
///
/// The Rust `DockerResolver` struct is a lightweight handle that carries
/// connection parameters; the actual HTTP work happens inside Go.
pub mod auth;

use async_trait::async_trait;
use bytes::Bytes;
use futures::{future, stream, Stream};

use crate::error::Result;
use crate::ffi::{go_blob_exists, go_fetch_blob, go_fetch_manifest, go_list_tags, go_push_blob, go_push_manifest};
use crate::images::Descriptor;
use crate::remotes::{Fetcher, Pusher, Resolver};

use auth::Credentials;

// ── DockerResolver ────────────────────────────────────────────────────────────

/// A handle to a Docker/OCI registry repository backed by containerd's Go client.
///
/// Cheap to clone — all fields are `Arc`-free value types.
#[derive(Clone)]
pub struct DockerResolver {
    pub registry: String,
    pub repository: String,
    username: String,
    password: String,
}

impl DockerResolver {
    pub fn new(registry: impl Into<String>, repository: impl Into<String>) -> Self {
        let registry = registry.into();
        let (username, password) = auth::credentials_from_docker_config(&registry)
            .map(|c| (c.username, c.password))
            .unwrap_or_default();
        Self {
            registry,
            repository: repository.into(),
            username,
            password,
        }
    }

    pub fn with_credentials(
        registry: impl Into<String>,
        repository: impl Into<String>,
        creds: Credentials,
    ) -> Self {
        Self {
            registry: registry.into(),
            repository: repository.into(),
            username: creds.username,
            password: creds.password,
        }
    }

    /// List all tags for this repository by calling into containerd's Docker client.
    pub async fn list_tags(&self) -> Result<Vec<String>> {
        go_list_tags(&self.registry, &self.repository, &self.username, &self.password)
    }

    /// Fetch the raw manifest bytes, Content-Type, and digest for `reference`.
    pub async fn fetch_manifest_raw(&self, reference: &str) -> Result<(Bytes, String, String)> {
        let r = go_fetch_manifest(
            &self.registry,
            &self.repository,
            reference,
            &self.username,
            &self.password,
        )?;
        Ok((r.data, r.content_type, r.digest))
    }
}

// ── Resolver impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl Resolver for DockerResolver {
    /// Resolve a reference to a content descriptor via containerd's Go resolver.
    ///
    /// Internally this calls `docker.NewResolver(...).Resolve(ctx, ref)` which
    /// sends a HEAD request to /v2/{name}/manifests/{ref} with the full Accept
    /// header list and handles the WWW-Authenticate bearer-token challenge.
    async fn resolve(&self, reference: &str) -> Result<Descriptor> {
        let r = go_fetch_manifest(
            &self.registry,
            &self.repository,
            reference,
            &self.username,
            &self.password,
        )?;
        let digest = r.digest.parse()?;
        Ok(Descriptor::new(r.content_type, digest, r.data.len() as i64))
    }

    async fn fetcher(&self, _reference: &str) -> Result<Box<dyn Fetcher>> {
        Ok(Box::new(self.clone()))
    }

    async fn pusher(&self, _reference: &str) -> Result<Box<dyn Pusher>> {
        Ok(Box::new(self.clone()))
    }
}

// ── Fetcher impl ──────────────────────────────────────────────────────────────

#[async_trait]
impl Fetcher for DockerResolver {
    /// Fetch a blob from the registry using containerd's Fetcher.
    ///
    /// For manifests the data was already retrieved during `resolve`; for blobs
    /// (configs and layers) this calls `dcopy_fetch_blob` which delegates to
    /// `fetcher.Fetch(ctx, desc)` in Go.
    async fn fetch(
        &self,
        desc: &Descriptor,
    ) -> Result<Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send + Unpin>>
    {
        let data = self.fetch_all(desc).await?;
        Ok(Box::new(stream::once(future::ready(Ok(data)))))
    }

    async fn fetch_all(&self, desc: &Descriptor) -> Result<Bytes> {
        go_fetch_blob(
            &self.registry,
            &self.repository,
            &desc.digest.to_string(),
            &desc.media_type,
            &self.username,
            &self.password,
        )
    }
}

// ── Pusher impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl Pusher for DockerResolver {
    /// Check blob existence using containerd's auth + a HEAD request.
    async fn exists(&self, desc: &Descriptor) -> Result<bool> {
        go_blob_exists(
            &self.registry,
            &self.repository,
            &desc.digest.to_string(),
            &self.username,
            &self.password,
        )
    }

    /// Push a blob using containerd's Pusher (OCI Distribution Spec POST+PUT).
    /// ErrAlreadyExists is handled transparently in the Go layer.
    async fn push(&self, desc: &Descriptor, data: Bytes) -> Result<()> {
        go_push_blob(
            &self.registry,
            &self.repository,
            &desc.digest.to_string(),
            &desc.media_type,
            &self.username,
            &self.password,
            &data,
        )
    }

    /// Push a manifest using containerd's Pusher.
    async fn push_manifest(&self, reference: &str, desc: &Descriptor, data: Bytes) -> Result<()> {
        go_push_manifest(
            &self.registry,
            &self.repository,
            reference,
            &desc.media_type,
            &self.username,
            &self.password,
            &data,
        )
    }
}
