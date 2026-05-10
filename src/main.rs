/// dcopy — container image copy utility
///
/// Written in Rust.  The internal architecture mirrors
/// containerd's core/remotes/ and core/images/ packages.
mod cmd;
mod digest;
mod error;
mod ffi;
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
use ffi::{go_daemon_to_oci_dir, go_run_image_proxy};

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
    about = "Copy container images between registries and local formats",
    long_about = None,
)]
struct Cli {
    /// Set log level (error, warn, info, debug, trace).
    /// Can also be set via RUST_LOG.
    #[arg(long, global = true, default_value = "warn", env = "DCOPY_LOG")]
    log_level: String,

    // Podman-compatible global flags (accepted when dcopy is called as "podman")
    /// Container storage root (podman --root)
    #[arg(long, global = true, default_value = "")]
    root: String,

    /// Container storage run-root (podman --runroot)
    #[arg(long, global = true, default_value = "")]
    runroot: String,

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

    /// Implement the containers-image-proxy wire protocol on an already-open
    /// Unix socket.  This is the same protocol as
    /// `skopeo experimental-image-proxy --sockfd N` so that dcopy can be
    /// hardlinked as /usr/bin/skopeo and used transparently by bootc.
    ExperimentalImageProxy {
        /// File-descriptor number of the already-open Unix socket.
        #[arg(long = "sockfd")]
        sockfd: i32,
        /// Disable authentication (accepted but ignored).
        #[arg(long = "no-creds")]
        no_creds: bool,
        /// Extra flags (accepted but ignored for forward compat).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
    },

    /// Minimal podman-compatible interface for bootc's imgstorage management.
    ///
    /// bootc 1.15.x calls `podman --root PATH images` to initialize its image
    /// storage and `podman pull` to import the source image.  dcopy is hardlinked
    /// as /usr/bin/podman and implements just enough to satisfy bootc.
    Images {
        /// Output format (ignored)
        #[arg(long, default_value = "")]
        format: String,
        /// Extra filters / flags (accepted but ignored)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
    },

    /// Pull an image (podman-compatible stub for bootc).
    Pull {
        /// Image reference (e.g. docker-daemon:image:tag)
        image: String,
        /// Extra flags (accepted but ignored)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
    },

    /// Save an image from the local Docker daemon to an OCI layout directory.
    ///
    /// Connects to /var/run/docker.sock, exports the image via the
    /// GET /images/{name}/get endpoint, and writes the result as an OCI image
    /// layout (oci-layout + index.json + blobs/) at DEST.
    ///
    /// The index.json is annotated with org.opencontainers.image.ref.name so
    /// that tools like bootc can reference the image with oci:DEST:TAG.
    ///
    /// Example:
    ///   dcopy save-oci myimage:latest /output/.oci-dir
    SaveOci {
        /// Image name as understood by the Docker daemon (e.g. myimage:latest)
        image: String,
        /// Destination OCI layout directory (will be created/replaced)
        dest: String,
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

    let result = dispatch(cli.command, &cli.root).await;

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn dispatch(cmd: Commands, _root: &str) -> error::Result<()> {
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

        // Minimal podman compatibility for bootc's imgstorage management.
        // bootc calls "podman images" to check the storage is accessible;
        // if empty the storage is uninitialized and bootc will populate it.
        Commands::Images { .. } => {
            // Return exit 0 with empty output: storage accessible, no images cached.
            eprintln!("[dcopy-podman] images: storage check OK (empty)");
            Ok(())
        }

        Commands::Pull { image, extra, .. } => {
            let oci_dir = std::env::var("DCOPY_OCI_DIR").unwrap_or_default();
            eprintln!("[dcopy-podman] pull: {image} extra={extra:?} oci_dir={oci_dir}");
            // Return success; bootc may use Rust-native import for the actual data.
            Ok(())
        }

        Commands::ExperimentalImageProxy { sockfd, .. } => {
            go_run_image_proxy(sockfd).map_err(|e| {
                crate::error::Error::Other(format!("experimental-image-proxy: {e}"))
            })
        }

        Commands::SaveOci { image, dest } => {
            // Strip optional docker-daemon:// prefix for convenience.
            let name = image
                .strip_prefix("docker-daemon://")
                .unwrap_or(&image);
            go_daemon_to_oci_dir(name, &dest).map_err(|e| {
                crate::error::Error::Other(format!("save-oci: {e}"))
            })
        }
    }
}

/// Parse `user:password` credential strings.
fn parse_creds(s: &str) -> Option<Credentials> {
    let (user, pass) = s.split_once(':')?;
    Some(Credentials::new(user, pass))
}
