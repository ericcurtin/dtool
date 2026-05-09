/// Media type constants for OCI and Docker image formats.
///
/// Mirrors containerd's core/images/mediatypes.go — every constant here
/// has a direct counterpart in that file so the two projects stay aligned.

// ── Docker Schema 2 ──────────────────────────────────────────────────────────

/// Docker image manifest v2 schema 2
pub const DOCKER_MANIFEST_V2: &str =
    "application/vnd.docker.distribution.manifest.v2+json";

/// Docker manifest list (multi-platform index)
pub const DOCKER_MANIFEST_LIST_V2: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

/// Docker image config JSON
pub const DOCKER_IMAGE_CONFIG: &str =
    "application/vnd.docker.container.image.v1+json";

/// Docker layer — tar+gzip
pub const DOCKER_LAYER_GZIP: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// Docker layer — uncompressed tar (foreign/non-distributable)
pub const DOCKER_LAYER_TAR: &str =
    "application/vnd.docker.image.rootfs.diff.tar";

/// Docker foreign layer — tar+gzip (non-distributable)
pub const DOCKER_FOREIGN_LAYER_GZIP: &str =
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";

// ── OCI Image Spec ────────────────────────────────────────────────────────────

/// OCI image manifest
pub const OCI_MANIFEST_V1: &str =
    "application/vnd.oci.image.manifest.v1+json";

/// OCI image index (multi-platform)
pub const OCI_INDEX_V1: &str =
    "application/vnd.oci.image.index.v1+json";

/// OCI image config JSON
pub const OCI_IMAGE_CONFIG: &str =
    "application/vnd.oci.image.config.v1+json";

/// OCI layer — tar+gzip
pub const OCI_LAYER_GZIP: &str =
    "application/vnd.oci.image.layer.v1.tar+gzip";

/// OCI layer — tar+zstd
pub const OCI_LAYER_ZSTD: &str =
    "application/vnd.oci.image.layer.v1.tar+zstd";

/// OCI layer — uncompressed tar
pub const OCI_LAYER_TAR: &str =
    "application/vnd.oci.image.layer.v1.tar";

/// OCI non-distributable layer — tar+gzip
pub const OCI_LAYER_NONDIST_GZIP: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";

/// OCI non-distributable layer — tar+zstd
pub const OCI_LAYER_NONDIST_ZSTD: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";

// ── Encrypted layers (containers/ocicrypt) ────────────────────────────────────

pub const OCI_LAYER_GZIP_ENCRYPTED: &str =
    "application/vnd.oci.image.layer.v1.tar+gzip+encrypted";

pub const OCI_LAYER_ZSTD_ENCRYPTED: &str =
    "application/vnd.oci.image.layer.v1.tar+zstd+encrypted";

// ── Accept header values for manifest negotiation ────────────────────────────

/// The ordered list of media types sent in `Accept:` when fetching a manifest.
/// Mirrors the list used in containerd's core/remotes/docker/fetcher.go and
/// skopeo's go.podman.io/image/v5/manifest package.
pub const MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.oci.image.manifest.v1+json,",
    "application/vnd.oci.image.index.v1+json,",
    "application/vnd.docker.distribution.manifest.v2+json,",
    "application/vnd.docker.distribution.manifest.list.v2+json,",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
);

/// Returns true if the media type represents any kind of manifest index /
/// manifest list (i.e. a multi-platform pointer, not a single-image manifest).
pub fn is_index(media_type: &str) -> bool {
    matches!(
        media_type,
        OCI_INDEX_V1 | DOCKER_MANIFEST_LIST_V2
    )
}

/// Returns true if the media type is a single-image manifest (not an index).
pub fn is_manifest(media_type: &str) -> bool {
    matches!(media_type, OCI_MANIFEST_V1 | DOCKER_MANIFEST_V2)
}

/// Returns true for layer media types that are compressed with gzip.
pub fn is_layer_gzip(media_type: &str) -> bool {
    matches!(
        media_type,
        DOCKER_LAYER_GZIP
            | OCI_LAYER_GZIP
            | OCI_LAYER_GZIP_ENCRYPTED
            | DOCKER_FOREIGN_LAYER_GZIP
            | OCI_LAYER_NONDIST_GZIP
    )
}
