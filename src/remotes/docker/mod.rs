/// Docker Registry HTTP API v2 resolver.
///
/// Implements `Resolver`, `Fetcher`, and `Pusher` for any registry speaking
/// the OCI Distribution Spec (RFC 9110 + Docker extensions).
///
/// Architecture mirrors containerd's core/remotes/docker/:
///   resolver.go  → `DockerResolver::resolve`
///   fetcher.go   → `DockerResolver::fetch` / `DockerFetcher`
///   pusher.go    → `DockerResolver::push` / `DockerPusher`
///   auth/        → crate::remotes::docker::auth
pub mod auth;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use reqwest::{Client, Response, StatusCode};
use tokio::sync::RwLock;
use tracing::{debug, trace};

use super::{Fetcher, Pusher, Resolver};
use crate::error::{Error, Result};
use crate::images::Descriptor;
use crate::media_types;

use auth::{fetch_token, parse_www_authenticate, AuthChallenge, Credentials};

// ── Token cache ───────────────────────────────────────────────────────────────

/// Per-registry cached bearer token.
/// Mirrors containerd's auth.TokenCache.
#[derive(Default)]
struct TokenCache {
    token: Option<String>,
}

// ── DockerResolver ────────────────────────────────────────────────────────────

/// A resolver for a single Docker/OCI registry endpoint.
///
/// Create one per registry (or per src/dest pair in a copy operation).
/// Clone is cheap — the inner state is Arc-wrapped.
#[derive(Clone)]
pub struct DockerResolver {
    inner: Arc<Inner>,
}

struct Inner {
    /// Hostname (+ optional port) of the registry, e.g. `registry-1.docker.io`.
    registry: String,
    /// Repository path, e.g. `library/ubuntu`.
    repository: String,
    /// Optional explicit credentials (overrides docker config).
    creds: Option<Credentials>,
    /// HTTP client — shared across all requests.
    client: Client,
    /// Cached bearer token.
    token_cache: RwLock<TokenCache>,
    /// Whether to use HTTP instead of HTTPS (for local/insecure registries).
    insecure: bool,
}

impl DockerResolver {
    pub fn new(registry: impl Into<String>, repository: impl Into<String>) -> Self {
        Self::with_options(registry, repository, None, false)
    }

    pub fn with_credentials(
        registry: impl Into<String>,
        repository: impl Into<String>,
        creds: Credentials,
    ) -> Self {
        Self::with_options(registry, repository, Some(creds), false)
    }

    pub fn with_options(
        registry: impl Into<String>,
        repository: impl Into<String>,
        creds: Option<Credentials>,
        insecure: bool,
    ) -> Self {
        let client = Client::builder()
            .user_agent(concat!("dcopy/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build HTTP client");

        let registry = registry.into();

        // Try to load credentials from docker config if none were provided explicitly
        let effective_creds = creds.or_else(|| auth::credentials_from_docker_config(&registry));

        Self {
            inner: Arc::new(Inner {
                registry,
                repository: repository.into(),
                creds: effective_creds,
                client,
                token_cache: RwLock::new(TokenCache::default()),
                insecure,
            }),
        }
    }

    // ── URL helpers ───────────────────────────────────────────────────────────

    fn scheme(&self) -> &str {
        if self.inner.insecure {
            "http"
        } else {
            "https"
        }
    }

    fn base_url(&self) -> String {
        format!(
            "{}://{}/v2/{}",
            self.scheme(),
            self.inner.registry,
            self.inner.repository
        )
    }

    fn manifests_url(&self, reference: &str) -> String {
        format!("{}/manifests/{reference}", self.base_url())
    }

    fn blobs_url(&self, digest: &str) -> String {
        format!("{}/blobs/{digest}", self.base_url())
    }

    fn uploads_url(&self) -> String {
        format!("{}/blobs/uploads/", self.base_url())
    }

    fn tags_url(&self) -> String {
        format!("{}/tags/list", self.base_url())
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    /// Return a valid `Authorization` header value, fetching / refreshing the
    /// bearer token if necessary.
    ///
    /// The flow mirrors containerd's `dockerAuthorizer.Authorize`:
    ///   1. Try the request with the cached token (or no token for the first try)
    ///   2. On 401, parse WWW-Authenticate and fetch a new token
    ///   3. Retry with the new token
    async fn auth_header(&self) -> Option<String> {
        let cache = self.inner.token_cache.read().await;
        cache.token.as_ref().map(|t| format!("Bearer {t}"))
    }

    async fn refresh_token(&self, challenge: &AuthChallenge) -> Result<()> {
        let token = fetch_token(&self.inner.client, challenge, self.inner.creds.as_ref()).await?;
        let mut cache = self.inner.token_cache.write().await;
        cache.token = Some(token);
        Ok(())
    }

    // ── Request helper ────────────────────────────────────────────────────────

    /// Execute an authenticated HTTP request, retrying once after a 401
    /// to handle token expiry / initial token fetch.
    ///
    /// Mirrors containerd's `dockerTransport.RoundTrip` retry logic.
    async fn do_request(
        &self,
        build: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder + Clone,
    ) -> Result<Response> {
        // Attempt 1: use cached token (may be None on first request)
        let mut req = build(&self.inner.client);
        if let Some(auth) = self.auth_header().await {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;

        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // Parse the WWW-Authenticate challenge and fetch a fresh token
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        if let Some(header) = www_auth {
            if let Some(challenge) = parse_www_authenticate(&header) {
                debug!("refreshing auth token from challenge");
                self.refresh_token(&challenge).await?;

                // Attempt 2 with the fresh token
                let mut req2 = build(&self.inner.client);
                if let Some(auth) = self.auth_header().await {
                    req2 = req2.header("Authorization", auth);
                }
                let resp2 = req2.send().await?;
                return Ok(resp2);
            }
        }

        // Fall back to Basic auth if we have credentials and challenge says Basic
        if let Some(creds) = &self.inner.creds {
            let mut req3 = build(&self.inner.client);
            req3 = req3.header("Authorization", creds.basic_header());
            return Ok(req3.send().await?);
        }

        Err(Error::AuthFailed(format!(
            "registry {} returned 401 and no usable auth mechanism found",
            self.inner.registry
        )))
    }

    // ── Tag listing ───────────────────────────────────────────────────────────

    pub async fn list_tags(&self) -> Result<Vec<String>> {
        let url = self.tags_url();
        let resp = self
            .do_request(|c| c.get(&url))
            .await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(vec![]);
        }
        check_status(&resp)?;

        #[derive(serde::Deserialize)]
        struct TagList {
            tags: Option<Vec<String>>,
        }

        let tl: TagList = resp.json().await?;
        Ok(tl.tags.unwrap_or_default())
    }

    // ── Manifest fetch ────────────────────────────────────────────────────────

    /// Fetch the raw manifest bytes + digest + content-type for a reference.
    pub async fn fetch_manifest_raw(&self, reference: &str) -> Result<(Bytes, String, String)> {
        let url = self.manifests_url(reference);
        let resp = self
            .do_request(|c| {
                c.get(&url)
                    .header("Accept", media_types::MANIFEST_ACCEPT)
            })
            .await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Err(Error::ManifestNotFound(reference.to_string()));
        }
        check_status(&resp)?;

        let content_type = resp
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(media_types::OCI_MANIFEST_V1)
            .to_string();

        let digest = resp
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body = resp.bytes().await?;
        Ok((body, content_type, digest))
    }
}

// ── Resolver impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl Resolver for DockerResolver {
    async fn resolve(&self, reference: &str) -> Result<Descriptor> {
        let url = self.manifests_url(reference);
        let resp = self
            .do_request(|c| {
                c.head(&url)
                    .header("Accept", media_types::MANIFEST_ACCEPT)
            })
            .await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Err(Error::ManifestNotFound(reference.to_string()));
        }
        check_status(&resp)?;

        let content_type = resp
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(media_types::OCI_MANIFEST_V1)
            .to_string();

        let digest_str = resp
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let size = resp
            .headers()
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(-1);

        // If the server didn't send Docker-Content-Digest on HEAD we fall back
        // to a GET and compute the digest ourselves
        let digest = if digest_str.is_empty() {
            let (body, _, _) = self.fetch_manifest_raw(reference).await?;
            crate::digest::Digest::sha256_of(&body).to_string()
        } else {
            digest_str
        };

        Ok(Descriptor::new(
            content_type,
            digest.parse()?,
            size,
        ))
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
    async fn fetch(
        &self,
        desc: &Descriptor,
    ) -> Result<Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send + Unpin>>
    {
        let digest = desc.digest.to_string();
        let url = self.blobs_url(&digest);
        trace!(%digest, "fetching blob");

        let resp = self.do_request(|c| c.get(&url)).await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Err(Error::BlobNotFound(digest));
        }
        check_status(&resp)?;

        Ok(Box::new(resp.bytes_stream()))
    }

    async fn fetch_all(&self, desc: &Descriptor) -> Result<Bytes> {
        let digest = desc.digest.to_string();
        let url = self.blobs_url(&digest);
        trace!(%digest, "fetching blob (buffered)");

        let resp = self.do_request(|c| c.get(&url)).await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Err(Error::BlobNotFound(digest));
        }
        check_status(&resp)?;

        Ok(resp.bytes().await?)
    }
}

// ── Pusher impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl Pusher for DockerResolver {
    async fn exists(&self, desc: &Descriptor) -> Result<bool> {
        let url = self.blobs_url(&desc.digest.to_string());
        let resp = self.do_request(|c| c.head(&url)).await?;
        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(Error::Registry {
                status: s.as_u16(),
                message: format!("unexpected status checking blob existence: {s}"),
            }),
        }
    }

    /// Push a blob using the OCI Distribution Spec chunked-upload protocol.
    ///
    /// Mirrors containerd core/remotes/docker/pusher.go:
    ///   1. POST /v2/{name}/blobs/uploads/        → 202 + Location
    ///   2. PUT  {location}?digest={digest}        → 201
    ///
    /// (We do a single-PUT monolithic upload rather than chunked PATCH for
    /// simplicity; this is spec-compliant and supported by all major registries.)
    async fn push(&self, desc: &Descriptor, data: Bytes) -> Result<()> {
        let digest_str = desc.digest.to_string();

        // POST to initiate upload session
        let post_url = self.uploads_url();
        let post_resp = self.do_request(|c| c.post(&post_url)).await?;
        let post_status = post_resp.status();

        // Extract Location header before consuming the response body
        let location_opt = post_resp
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        match post_status {
            StatusCode::CREATED => {
                // Registry accepted the blob via the POST (monolithic upload)
                return Ok(());
            }
            StatusCode::ACCEPTED => {} // normal path: proceed to PUT
            s => {
                let body = post_resp.text().await.unwrap_or_default();
                check_status_code(s, body)?;
            }
        }

        let location = location_opt.ok_or_else(|| Error::Registry {
            status: 202,
            message: "missing Location header in blob upload response".to_string(),
        })?;

        // Resolve relative Location URL
        let put_base = if location.starts_with("http://") || location.starts_with("https://") {
            location.clone()
        } else {
            format!(
                "{}://{}{}",
                self.scheme(),
                self.inner.registry,
                location
            )
        };

        // Append digest query parameter
        let separator = if put_base.contains('?') { "&" } else { "?" };
        let put_url = format!("{put_base}{separator}digest={digest_str}");

        let put_resp = self
            .do_request(|c| {
                c.put(&put_url)
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", data.len().to_string())
                    .body(data.clone())
            })
            .await?;

        match put_resp.status() {
            StatusCode::CREATED => Ok(()),
            s => Err(Error::Registry {
                status: s.as_u16(),
                message: put_resp.text().await.unwrap_or_default(),
            }),
        }
    }

    async fn push_manifest(&self, reference: &str, _desc: &Descriptor, data: Bytes) -> Result<()> {
        // Detect media type from the raw manifest bytes
        let media_type = detect_manifest_media_type(&data);
        let url = self.manifests_url(reference);

        let resp = self
            .do_request(|c| {
                c.put(&url)
                    .header("Content-Type", media_type)
                    .header("Content-Length", data.len().to_string())
                    .body(data.clone())
            })
            .await?;

        match resp.status() {
            StatusCode::CREATED | StatusCode::OK => Ok(()),
            s => Err(Error::Registry {
                status: s.as_u16(),
                message: resp.text().await.unwrap_or_default(),
            }),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn check_status(resp: &Response) -> Result<()> {
    check_status_code(resp.status(), String::new())
}

fn check_status_code(status: StatusCode, body: String) -> Result<()> {
    if status.is_success() {
        return Ok(());
    }
    Err(Error::Registry {
        status: status.as_u16(),
        message: body,
    })
}

/// Detect the manifest media type from the JSON content.
fn detect_manifest_media_type(data: &[u8]) -> &'static str {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return media_types::OCI_MANIFEST_V1;
    };
    let mt = v
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if mt == media_types::DOCKER_MANIFEST_V2 {
        return media_types::DOCKER_MANIFEST_V2;
    }
    if mt == media_types::DOCKER_MANIFEST_LIST_V2 {
        return media_types::DOCKER_MANIFEST_LIST_V2;
    }
    if v.get("manifests").is_some() {
        media_types::OCI_INDEX_V1
    } else {
        media_types::OCI_MANIFEST_V1
    }
}
