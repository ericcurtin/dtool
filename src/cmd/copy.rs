/// `dcopy copy` — copy an image between two transports.
///
/// Mirrors `skopeo copy`, implemented using containerd's fetch/push model:
///   1. Resolve the source manifest (get a stable digest)
///   2. Walk the descriptor tree (index → manifest → config + layers)
///   3. For each blob: check if it already exists at dest, skip if so
///   4. Stream blob from source to dest
///   5. Push the manifest(s) to dest under the target reference
///
/// Only the `docker://` transport is fully implemented in this release.
/// OCI layout and docker-archive transports are planned for future work.
use bytes::Bytes;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tracing::{debug, info};

use crate::error::{Error, Result};
use crate::images::{AnyManifest, Manifest};
use crate::media_types;
use crate::platforms::Platform;
use crate::reference::{ImageRef, Transport};
use crate::remotes::docker::{auth::Credentials, DockerResolver};
use crate::remotes::{Fetcher, Pusher, Resolver as _};

pub struct CopyOptions {
    pub src_creds: Option<Credentials>,
    pub dest_creds: Option<Credentials>,
    /// Copy all platforms from a manifest index instead of just the host platform.
    pub all: bool,
    /// Override platform selection (e.g. `linux/amd64`).
    pub platform: Option<Platform>,
    /// Preserve the source manifest type (don't convert Docker→OCI or vice versa).
    pub preserve_digests: bool,
}

impl Default for CopyOptions {
    fn default() -> Self {
        Self {
            src_creds: None,
            dest_creds: None,
            all: false,
            platform: None,
            preserve_digests: false,
        }
    }
}

/// Entry point for `dcopy copy <src> <dest>`.
pub async fn run(src: &str, dest: &str, mut opts: CopyOptions) -> Result<()> {
    let src_ref: ImageRef = src.parse()?;
    let dest_ref: ImageRef = dest.parse()?;

    match (&src_ref.transport, &dest_ref.transport) {
        (Transport::Docker, Transport::Docker) => {
            let sd = src_ref.docker.as_ref().unwrap();
            let dd = dest_ref.docker.as_ref().unwrap();

            let src_resolver = match opts.src_creds.take() {
                Some(c) => DockerResolver::with_credentials(&sd.registry, &sd.repository, c),
                None => DockerResolver::new(&sd.registry, &sd.repository),
            };
            let dest_resolver = match opts.dest_creds.take() {
                Some(c) => DockerResolver::with_credentials(&dd.registry, &dd.repository, c),
                None => DockerResolver::new(&dd.registry, &dd.repository),
            };

            copy_docker_to_docker(
                &src_resolver,
                &sd.reference(),
                &dest_resolver,
                &dd.reference(),
                &opts,
            )
            .await
        }
        (Transport::Docker, _) | (_, Transport::Docker) => Err(Error::UnsupportedTransport(
            "cross-transport copy not yet implemented; both src and dest must be docker://".to_string(),
        )),
        _ => Err(Error::UnsupportedTransport(
            "only docker:// transport is supported in this release".to_string(),
        )),
    }
}

async fn copy_docker_to_docker(
    src: &DockerResolver,
    src_ref: &str,
    dest: &DockerResolver,
    dest_ref: &str,
    opts: &CopyOptions,
) -> Result<()> {
    let mp = MultiProgress::new();

    // ── Step 1: fetch the source manifest ────────────────────────────────────
    let (raw_manifest, content_type, digest_str) = src.fetch_manifest_raw(src_ref).await?;
    let manifest = AnyManifest::from_bytes(&raw_manifest, &content_type)?;

    info!(
        src = src_ref,
        dest = dest_ref,
        media_type = manifest.media_type(),
        digest = %digest_str,
        "resolved source image"
    );

    match manifest {
        AnyManifest::Index(index) => {
            if opts.all {
                // Copy every platform manifest + the index itself
                copy_all_platforms(src, dest, dest_ref, &index, &raw_manifest, &mp).await
            } else {
                // Select the best-matching platform
                let platform = opts
                    .platform
                    .clone()
                    .unwrap_or_else(Platform::host);
                let desc = index
                    .select_platform(&platform)
                    .ok_or_else(|| Error::PlatformNotFound(platform.to_string()))?
                    .clone();

                info!(platform = %platform, digest = %desc.digest, "selected platform manifest");

                // Fetch the platform-specific manifest
                let (plat_raw, plat_ct, _) =
                    src.fetch_manifest_raw(&desc.digest.to_string()).await?;
                let plat_manifest = AnyManifest::from_bytes(&plat_raw, &plat_ct)?;
                let AnyManifest::Manifest(m) = plat_manifest else {
                    return Err(Error::Other(
                        "expected single-image manifest inside index".to_string(),
                    ));
                };

                // Copy blobs then push manifest
                copy_manifest_blobs(src, dest, &m, &mp).await?;

                let dest_pusher = dest.pusher(dest_ref).await?;
                dest_pusher
                    .push_manifest(dest_ref, &desc, plat_raw)
                    .await?;
                info!(dest = dest_ref, "image copy complete");
                Ok(())
            }
        }
        AnyManifest::Manifest(m) => {
            copy_manifest_blobs(src, dest, &m, &mp).await?;
            let dest_pusher = dest.pusher(dest_ref).await?;
            let top_desc = crate::images::Descriptor::new(
                content_type,
                raw_manifest
                    .as_ref()
                    .try_into()
                    .unwrap_or_else(|_| crate::digest::Digest::sha256_of(&raw_manifest)),
                raw_manifest.len() as i64,
            );
            dest_pusher
                .push_manifest(dest_ref, &top_desc, raw_manifest)
                .await?;
            info!(dest = dest_ref, "image copy complete");
            Ok(())
        }
    }
}

/// Copy all platform manifests referenced by an OCI index / Docker manifest list,
/// then push the index itself.
async fn copy_all_platforms(
    src: &DockerResolver,
    dest: &DockerResolver,
    dest_ref: &str,
    index: &crate::images::Index,
    raw_index: &Bytes,
    mp: &MultiProgress,
) -> Result<()> {
    for desc in &index.manifests {
        let plat_label = desc
            .platform
            .as_ref()
            .map(|p| p.to_platform().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        info!(platform = %plat_label, digest = %desc.digest, "copying platform manifest");

        let (plat_raw, plat_ct, _) = src.fetch_manifest_raw(&desc.digest.to_string()).await?;
        let plat_manifest = AnyManifest::from_bytes(&plat_raw, &plat_ct)?;
        if let AnyManifest::Manifest(m) = plat_manifest {
            copy_manifest_blobs(src, dest, &m, mp).await?;
        }
        let dest_pusher = dest.pusher(&desc.digest.to_string()).await?;
        dest_pusher
            .push_manifest(&desc.digest.to_string(), desc, plat_raw)
            .await?;
    }

    // Push the index under the destination reference
    let index_desc = crate::images::Descriptor::new(
        media_types::OCI_INDEX_V1,
        crate::digest::Digest::sha256_of(raw_index),
        raw_index.len() as i64,
    );
    let dest_pusher = dest.pusher(dest_ref).await?;
    dest_pusher
        .push_manifest(dest_ref, &index_desc, raw_index.clone())
        .await?;

    info!(dest = dest_ref, "all-platforms copy complete");
    Ok(())
}

/// Copy all blobs (config + layers) from src to dest, skipping blobs that
/// already exist at dest.
///
/// This mirrors containerd's `transfer/local.go` transfer pipeline.
async fn copy_manifest_blobs(
    src: &DockerResolver,
    dest: &DockerResolver,
    manifest: &Manifest,
    mp: &MultiProgress,
) -> Result<()> {
    let src_fetcher = src.fetcher("").await?;
    let dest_pusher = dest.pusher("").await?;

    let total_blobs = manifest.blobs().len();
    let pb = mp.add(ProgressBar::new(total_blobs as u64));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} blobs {msg}")
            .unwrap(),
    );

    for desc in manifest.blobs() {
        let digest_short = desc.digest.short().to_string();
        pb.set_message(digest_short.clone());

        // Existence check — avoids re-uploading blobs already at the destination.
        // Mirrors containerd's `remotes.MountableHandler` / blob-mount optimisation.
        if dest_pusher.exists(desc).await? {
            debug!(digest = %desc.digest, "blob already exists at destination, skipping");
            pb.inc(1);
            continue;
        }

        debug!(digest = %desc.digest, size = desc.size, "copying blob");

        // Stream the blob: we buffer entirely for now.
        // TODO: pipe directly from fetcher to pusher to avoid the full buffer.
        let data = src_fetcher.fetch_all(desc).await?;

        dest_pusher.push(desc, data).await?;
        pb.inc(1);
    }

    pb.finish_with_message("done");
    Ok(())
}

// ── Helper: build a Digest from &[u8] via TryFrom ─────────────────────────────

impl TryFrom<&[u8]> for crate::digest::Digest {
    type Error = Error;
    fn try_from(b: &[u8]) -> Result<Self> {
        Ok(crate::digest::Digest::sha256_of(b))
    }
}
