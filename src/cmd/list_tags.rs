/// `dcopy list-tags` — list all tags for an image repository.
///
/// Mirrors `skopeo list-tags` — calls the OCI Distribution Spec
/// `/v2/{name}/tags/list` endpoint.
use serde::Serialize;

use crate::error::{Error, Result};
use crate::reference::{ImageRef, Transport};
use crate::remotes::docker::{auth::Credentials, DockerResolver};

pub struct ListTagsOptions {
    pub creds: Option<Credentials>,
}

impl Default for ListTagsOptions {
    fn default() -> Self {
        Self { creds: None }
    }
}

#[derive(Debug, Serialize)]
struct TagsOutput {
    #[serde(rename = "Repository")]
    repository: String,
    #[serde(rename = "Tags")]
    tags: Vec<String>,
}

pub async fn run(reference: &str, opts: ListTagsOptions) -> Result<()> {
    let image_ref: ImageRef = reference.parse()?;

    match image_ref.transport {
        Transport::Docker => {
            let dr = image_ref.docker.as_ref().unwrap();
            let resolver = match opts.creds {
                Some(c) => DockerResolver::with_credentials(&dr.registry, &dr.repository, c),
                None => DockerResolver::new(&dr.registry, &dr.repository),
            };

            let mut tags = resolver.list_tags().await?;
            tags.sort();

            let output = TagsOutput {
                repository: dr.name(),
                tags,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
            Ok(())
        }
        t => Err(Error::UnsupportedTransport(t.to_string())),
    }
}
