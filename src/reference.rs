/// Image reference parsing.
///
/// Transport-prefixed image reference parsing, modelled on
/// go.podman.io/image/v5/transports/alltransports.
///
/// Supported transports (MVP):
///   docker://   — OCI Distribution Spec registry
///   oci:        — OCI image layout directory
///   oci-archive: — OCI image layout tar archive
///   docker-archive: — Docker `docker save` tar archive
use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Supported image transports — mirrors containerd's remotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Docker Registry API v2 (OCI Distribution Spec)
    Docker,
    /// OCI image layout directory on local filesystem
    OciDir,
    /// OCI image layout as a tar archive
    OciArchive,
    /// Docker `docker save` / `docker load` tar format
    DockerArchive,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Docker => write!(f, "docker"),
            Transport::OciDir => write!(f, "oci"),
            Transport::OciArchive => write!(f, "oci-archive"),
            Transport::DockerArchive => write!(f, "docker-archive"),
        }
    }
}

/// A fully-qualified image reference with explicit transport.
///
/// For `docker://` references the inner `DockerRef` is further parsed into
/// registry / repository / tag / digest components.
#[derive(Debug, Clone)]
pub struct ImageRef {
    pub transport: Transport,
    /// The raw reference string (everything after `transport://` or `transport:`).
    pub raw: String,
    /// Parsed docker-specific components (only set for `Transport::Docker`).
    pub docker: Option<DockerRef>,
}

/// Parsed components of a `docker://` reference.
///
/// Mirrors the normalisation performed by go.podman.io/image/v5/docker/reference
/// and github.com/distribution/reference (shared by containerd and the distribution project).
#[derive(Debug, Clone)]
pub struct DockerRef {
    /// Hostname (+ optional port) of the registry.
    /// Defaults to `registry-1.docker.io`.
    pub registry: String,

    /// Repository path within the registry (e.g. `library/ubuntu`).
    pub repository: String,

    /// Optional tag (e.g. `latest`).  None when a digest is given instead.
    pub tag: Option<String>,

    /// Optional digest reference (e.g. `sha256:abc…`).
    pub digest: Option<String>,
}

impl DockerRef {
    /// Returns the full `registry/repository` string.
    pub fn name(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }

    /// Returns the reference component for use in registry API calls:
    /// digest takes precedence over tag; falls back to `latest`.
    pub fn reference(&self) -> String {
        if let Some(d) = &self.digest {
            d.clone()
        } else {
            self.tag.clone().unwrap_or_else(|| "latest".to_string())
        }
    }
}

impl fmt::Display for DockerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        } else if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        } else {
            write!(f, ":latest")?;
        }
        Ok(())
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.docker {
            Some(d) => write!(f, "docker://{d}"),
            None => write!(f, "{}:{}", self.transport, self.raw),
        }
    }
}

impl FromStr for ImageRef {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // Detect transport prefix.  If none, assume docker://.
        if let Some(rest) = s.strip_prefix("docker://") {
            let docker = parse_docker_ref(rest)?;
            Ok(ImageRef {
                transport: Transport::Docker,
                raw: rest.to_string(),
                docker: Some(docker),
            })
        } else if let Some(rest) = s.strip_prefix("oci-archive:") {
            Ok(ImageRef {
                transport: Transport::OciArchive,
                raw: rest.to_string(),
                docker: None,
            })
        } else if let Some(rest) = s.strip_prefix("docker-archive:") {
            Ok(ImageRef {
                transport: Transport::DockerArchive,
                raw: rest.to_string(),
                docker: None,
            })
        } else if let Some(rest) = s.strip_prefix("oci:") {
            Ok(ImageRef {
                transport: Transport::OciDir,
                raw: rest.to_string(),
                docker: None,
            })
        } else if s.contains("://") {
            let scheme = s.split("://").next().unwrap_or("");
            Err(Error::UnsupportedTransport(scheme.to_string()))
        } else {
            // No transport prefix — treat as implicit docker://
            let docker = parse_docker_ref(s)?;
            Ok(ImageRef {
                transport: Transport::Docker,
                raw: s.to_string(),
                docker: Some(docker),
            })
        }
    }
}

/// Parse the reference portion of a `docker://` URL into a `DockerRef`.
///
/// Implements the same normalisation rules as `github.com/distribution/reference`:
///   - No registry component → `registry-1.docker.io`
///   - Single-component name on docker.io → `library/{name}`
///   - No tag and no digest → tag `latest`
fn parse_docker_ref(s: &str) -> Result<DockerRef> {
    if s.is_empty() {
        return Err(Error::InvalidReference("empty reference".to_string()));
    }

    // Split digest first (@ takes precedence over :tag)
    let (without_digest, digest) = if let Some(pos) = s.rfind('@') {
        (&s[..pos], Some(s[pos + 1..].to_string()))
    } else {
        (s, None)
    };

    // Split tag
    let (name_part, tag) = if digest.is_none() {
        if let Some(pos) = without_digest.rfind(':') {
            // Make sure the colon isn't part of a port number in the host
            let before = &without_digest[..pos];
            // If there's a slash after the last colon it's a tag, not a port
            if before.contains('/') || !before.contains(':') {
                (&without_digest[..pos], Some(without_digest[pos + 1..].to_string()))
            } else {
                (without_digest, None)
            }
        } else {
            (without_digest, None)
        }
    } else {
        (without_digest, None)
    };

    // Split registry from repository path.
    // A component is a registry host if it contains a dot, colon (port), or
    // equals "localhost" — same heuristic as distribution/reference.
    let (registry, repository) = if let Some(slash) = name_part.find('/') {
        let host = &name_part[..slash];
        let rest = &name_part[slash + 1..];
        if host.contains('.') || host.contains(':') || host == "localhost" {
            (host.to_string(), rest.to_string())
        } else {
            // No registry component; implicit docker.io
            ("registry-1.docker.io".to_string(), name_part.to_string())
        }
    } else {
        // Single component with no slash — docker.io official image
        (
            "registry-1.docker.io".to_string(),
            format!("library/{name_part}"),
        )
    };

    // Docker Hub short names: single-slash on docker.io stay as-is
    // (e.g. `user/image` → registry-1.docker.io/user/image)

    // Validation: repository must be non-empty
    if repository.is_empty() {
        return Err(Error::InvalidReference(format!(
            "empty repository in reference: {s}"
        )));
    }

    Ok(DockerRef {
        registry,
        repository,
        tag,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_short_name() {
        let r: ImageRef = "docker://ubuntu".parse().unwrap();
        let d = r.docker.unwrap();
        assert_eq!(d.registry, "registry-1.docker.io");
        assert_eq!(d.repository, "library/ubuntu");
        assert_eq!(d.tag, None);
    }

    #[test]
    fn parse_with_tag() {
        let r: ImageRef = "docker://ubuntu:22.04".parse().unwrap();
        let d = r.docker.unwrap();
        assert_eq!(d.tag, Some("22.04".to_string()));
    }

    #[test]
    fn parse_full() {
        let r: ImageRef = "docker://gcr.io/google-containers/pause:3.1"
            .parse()
            .unwrap();
        let d = r.docker.unwrap();
        assert_eq!(d.registry, "gcr.io");
        assert_eq!(d.repository, "google-containers/pause");
        assert_eq!(d.tag, Some("3.1".to_string()));
    }

    #[test]
    fn parse_digest() {
        let r: ImageRef =
            "docker://ubuntu@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
                .parse()
                .unwrap();
        let d = r.docker.unwrap();
        assert!(d.digest.is_some());
        assert_eq!(d.tag, None);
    }

    #[test]
    fn implicit_docker_transport() {
        let r: ImageRef = "ubuntu:20.04".parse().unwrap();
        assert_eq!(r.transport, Transport::Docker);
        let d = r.docker.unwrap();
        assert_eq!(d.repository, "library/ubuntu");
    }
}
