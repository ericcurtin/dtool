/// Remote resolver interfaces.
///
/// This module defines the three core traits that model how dcopy interacts
/// with remote image stores.  The design mirrors containerd's
/// core/remotes/resolver.go exactly:
///
///   `Resolver`  → containerd `remotes.Resolver`   (resolve name → descriptor + fetch/push handles)
///   `Fetcher`   → containerd `remotes.Fetcher`    (stream blobs by descriptor)
///   `Pusher`    → containerd `remotes.Pusher`     (write blobs to remote)
///
/// The `docker` sub-module provides the production implementation for
/// registries speaking the OCI Distribution Spec / Docker Registry HTTP API v2.
pub mod docker;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;

use crate::error::Result;
use crate::images::Descriptor;

/// Resolves an image name to a canonical descriptor and hands back the
/// fetch/push handles for that remote.
///
/// Mirrors containerd `remotes.Resolver`.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve the reference to a content descriptor.
    ///
    /// Returns the digest-pinned descriptor so callers always get a stable
    /// content address even when the reference is a mutable tag.
    async fn resolve(&self, reference: &str) -> Result<Descriptor>;

    /// Return a `Fetcher` that can pull blobs for the given reference.
    async fn fetcher(&self, reference: &str) -> Result<Box<dyn Fetcher>>;

    /// Return a `Pusher` that can push blobs to the given reference destination.
    async fn pusher(&self, reference: &str) -> Result<Box<dyn Pusher>>;
}

/// Fetches blobs from a remote by descriptor.
///
/// Mirrors containerd `remotes.Fetcher`.
#[async_trait]
pub trait Fetcher: Send + Sync {
    /// Stream the blob identified by `desc` from the remote.
    async fn fetch(
        &self,
        desc: &Descriptor,
    ) -> Result<Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send + Unpin>>;

    /// Fetch a blob and collect it entirely into memory.
    /// Convenience wrapper around `fetch`; callers that need streaming should
    /// use `fetch` directly to avoid buffering large layers.
    async fn fetch_all(&self, desc: &Descriptor) -> Result<Bytes>;
}

/// Pushes blobs to a remote.
///
/// Mirrors containerd `remotes.Pusher` / `content.Writer`.
#[async_trait]
pub trait Pusher: Send + Sync {
    /// Check whether the blob described by `desc` already exists at the remote.
    /// This is an optimisation (HEAD request) that avoids re-uploading blobs.
    ///
    /// Mirrors containerd's mount/exists optimisation path.
    async fn exists(&self, desc: &Descriptor) -> Result<bool>;

    /// Upload the blob.  `data` is the full blob bytes; the implementation is
    /// responsible for computing and verifying the digest.
    async fn push(&self, desc: &Descriptor, data: Bytes) -> Result<()>;

    /// Push a manifest blob to the given tag/digest reference.
    async fn push_manifest(&self, reference: &str, desc: &Descriptor, data: Bytes) -> Result<()>;
}
