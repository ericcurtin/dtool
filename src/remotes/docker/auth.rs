/// Docker Registry HTTP API v2 authentication.
///
/// Mirrors containerd's core/remotes/docker/auth/ package — implements the
/// same WWW-Authenticate challenge/response cycle and bearer-token caching.
///
/// Supported schemes:
///   - Bearer (token service, used by Docker Hub and most hosted registries)
///   - Basic  (simple username:password, used by many private registries)
use std::collections::HashMap;

use base64::Engine as _;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::error::{Error, Result};

/// Parsed credentials for a single registry.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.username.is_empty() && self.password.is_empty()
    }

    /// Encode as HTTP Basic auth header value (`Basic base64(user:pass)`).
    pub fn basic_header(&self) -> String {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.username, self.password));
        format!("Basic {encoded}")
    }
}

// ── WWW-Authenticate header parsing ──────────────────────────────────────────

/// A parsed `WWW-Authenticate` challenge.
#[derive(Debug)]
pub enum AuthChallenge {
    Bearer {
        realm: String,
        service: Option<String>,
        scope: Option<String>,
    },
    Basic {
        realm: Option<String>,
    },
}

/// Parse the `WWW-Authenticate` header returned by a registry on a 401.
///
/// Mirrors containerd core/remotes/docker/auth/fetch.go `parseAuthHeader`.
pub fn parse_www_authenticate(header: &str) -> Option<AuthChallenge> {
    let header = header.trim();

    if let Some(rest) = header.strip_prefix("Bearer ") {
        let params = parse_kv_params(rest);
        Some(AuthChallenge::Bearer {
            realm: params.get("realm").cloned().unwrap_or_default(),
            service: params.get("service").cloned(),
            scope: params.get("scope").cloned(),
        })
    } else if header.to_ascii_lowercase().starts_with("basic") {
        let rest = header["Basic".len()..].trim();
        let params = parse_kv_params(rest);
        Some(AuthChallenge::Basic {
            realm: params.get("realm").cloned(),
        })
    } else {
        warn!("unrecognised WWW-Authenticate scheme: {header}");
        None
    }
}

/// Parse comma-separated `key="value"` or `key=value` pairs.
fn parse_kv_params(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim().to_lowercase();
            let value = part[eq + 1..].trim().trim_matches('"').to_string();
            map.insert(key, value);
        }
    }
    map
}

// ── Bearer token response ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    // expires_in, issued_at — ignored for MVP (tokens are short-lived enough)
}

impl TokenResponse {
    fn into_token(self) -> Option<String> {
        self.token.or(self.access_token)
    }
}

// ── Token fetching ────────────────────────────────────────────────────────────

/// Fetch a bearer token from the token service described by `challenge`.
///
/// Mirrors containerd core/remotes/docker/auth/fetch.go `FetchToken`.
pub async fn fetch_token(
    client: &Client,
    challenge: &AuthChallenge,
    creds: Option<&Credentials>,
) -> Result<String> {
    let AuthChallenge::Bearer {
        realm,
        service,
        scope,
    } = challenge
    else {
        return Err(Error::AuthFailed(
            "fetch_token called with non-Bearer challenge".to_string(),
        ));
    };

    if realm.is_empty() {
        return Err(Error::AuthFailed("empty realm in Bearer challenge".to_string()));
    }

    let mut req = client.get(realm.as_str());

    // Append query parameters
    let mut query: Vec<(&str, &str)> = Vec::new();
    if let Some(svc) = service {
        query.push(("service", svc.as_str()));
    }
    if let Some(sc) = scope {
        query.push(("scope", sc.as_str()));
    }
    req = req.query(&query);

    // Add credentials if provided
    if let Some(c) = creds {
        if !c.is_empty() {
            debug!(username = %c.username, "authenticating to token service");
            req = req.basic_auth(&c.username, Some(&c.password));
        }
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        return Err(Error::AuthFailed(format!(
            "token service returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        )));
    }

    let token_resp: TokenResponse = resp.json().await?;
    token_resp
        .into_token()
        .ok_or_else(|| Error::AuthFailed("token service returned no token".to_string()))
}

// ── Docker config.json credential store ──────────────────────────────────────

/// Read credentials for `registry` from `~/.docker/config.json`.
///
/// Mirrors go.podman.io/common/pkg/auth and containerd's credential helpers.
/// Only handles the `auths` map with base64-encoded `auth` values (no external
/// credential helpers in MVP — those require shelling out).
pub fn credentials_from_docker_config(registry: &str) -> Option<Credentials> {
    let config_path = dirs::home_dir()?.join(".docker").join("config.json");
    let data = std::fs::read(&config_path).ok()?;

    let v: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let auths = v.get("auths")?.as_object()?;

    // Registries are stored with varying key forms; try several.
    let candidates = [
        registry.to_string(),
        format!("https://{registry}"),
        format!("https://{registry}/"),
    ];

    for key in &candidates {
        if let Some(entry) = auths.get(key) {
            if let Some(auth_b64) = entry.get("auth").and_then(|v| v.as_str()) {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(auth_b64)
                    .ok()?;
                let s = String::from_utf8(decoded).ok()?;
                if let Some((user, pass)) = s.split_once(':') {
                    return Some(Credentials::new(user, pass));
                }
            }
            // Some entries store username/password separately
            if let (Some(user), Some(pass)) = (
                entry.get("username").and_then(|v| v.as_str()),
                entry.get("password").and_then(|v| v.as_str()),
            ) {
                return Some(Credentials::new(user, pass));
            }
        }
    }

    None
}
