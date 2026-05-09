/// dcopy — container image copy utility
///
/// Like skopeo, written in Rust.  The internal architecture mirrors
/// containerd's core/remotes/ and core/images/ packages.
mod cmd;
mod digest;
mod error;
mod images;
mod media_types;
mod platforms;
mod reference;
mod remotes;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use cmd::{
    copy::{self, CopyOptions},
    inspect::{self, InspectOptions},
    list_tags::{self, ListTagsOptions},
};
use remotes::docker::auth::Credentials;

// ── CLI definition ────────────────────────────────────────────────────────────

/// dcopy: copy container images between registries and local formats.
///
/// References use the format TRANSPORT:REFERENCE, e.g.:
///   docker://registry.io/image:tag
///   oci:/path/to/oci-dir
///   docker-archive:/path/to/archive.tar
#[derive(Parser)]
#[command(
    name = "dcopy",
    version,
    about = "Copy container images — like skopeo, written in Rust",
    long_about = None,
)]
struct Cli {
    /// Set log level (error, warn, info, debug, trace).
    /// Can also be set via RUST_LOG.
    #[arg(long, global = true, default_value = "warn", env = "DCOPY_LOG")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Copy an image from one location to another.
    ///
    /// SOURCE and DESTINATION use the TRANSPORT:REFERENCE notation.
    /// Currently supported transport: docker://
    Copy {
        /// Source image reference (e.g. docker://ubuntu:22.04)
        source: String,

        /// Destination image reference (e.g. docker://myregistry.io/ubuntu:22.04)
        destination: String,

        /// Source credentials in USER:PASS format
        #[arg(long)]
        src_creds: Option<String>,

        /// Destination credentials in USER:PASS format
        #[arg(long)]
        dest_creds: Option<String>,

        /// Copy all platforms from a manifest index (default: select host platform)
        #[arg(long, short = 'a')]
        all: bool,

        /// Override the target platform (e.g. linux/amd64, linux/arm64/v8)
        #[arg(long)]
        platform: Option<String>,
    },

    /// Inspect image metadata without pulling layers.
    Inspect {
        /// Image reference to inspect (e.g. docker://ubuntu:22.04)
        image: String,

        /// Credentials in USER:PASS format
        #[arg(long)]
        creds: Option<String>,

        /// Output the raw manifest JSON
        #[arg(long)]
        raw: bool,

        /// Output the raw config JSON
        #[arg(long)]
        config: bool,

        /// Override platform for index images (e.g. linux/amd64)
        #[arg(long)]
        platform: Option<String>,
    },

    /// List all tags for an image repository.
    ListTags {
        /// Repository reference (e.g. docker://ubuntu or docker://registry.io/myimage)
        image: String,

        /// Credentials in USER:PASS format
        #[arg(long)]
        creds: Option<String>,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialise structured logging, respecting RUST_LOG and --log-level
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_writer(std::io::stderr)
        .init();

    let result = dispatch(cli.command).await;

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn dispatch(cmd: Commands) -> error::Result<()> {
    match cmd {
        Commands::Copy {
            source,
            destination,
            src_creds,
            dest_creds,
            all,
            platform,
        } => {
            let opts = CopyOptions {
                src_creds: src_creds.as_deref().and_then(parse_creds),
                dest_creds: dest_creds.as_deref().and_then(parse_creds),
                all,
                platform: platform.as_deref().and_then(|p| p.parse().ok()),
                preserve_digests: false,
            };
            copy::run(&source, &destination, opts).await
        }

        Commands::Inspect {
            image,
            creds,
            raw,
            config,
            platform,
        } => {
            let opts = InspectOptions {
                creds: creds.as_deref().and_then(parse_creds),
                raw,
                config,
                platform: platform.as_deref().and_then(|p| p.parse().ok()),
            };
            inspect::run(&image, opts).await
        }

        Commands::ListTags { image, creds } => {
            let opts = ListTagsOptions {
                creds: creds.as_deref().and_then(parse_creds),
            };
            list_tags::run(&image, opts).await
        }
    }
}

/// Parse `user:password` credential strings.
fn parse_creds(s: &str) -> Option<Credentials> {
    let (user, pass) = s.split_once(':')?;
    Some(Credentials::new(user, pass))
}
