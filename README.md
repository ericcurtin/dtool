# dcopy

A container image copy utility, modelled on [containerd](https://github.com/containerd/containerd)'s architecture.

## Features

- **Copy** container images between registries with progress reporting
- **Inspect** image metadata without pulling image layers
- **List tags** for an image repository
- Supports OCI Image Spec and Docker Schema 2 wire formats
- Multi-platform manifest index support (`--all` or `--platform`)
- Reads credentials from `~/.docker/config.json` automatically

## Usage

### Copy an image

```bash
dcopy copy docker://ubuntu:22.04 docker://myregistry.io/ubuntu:22.04
```

Copy all platforms from a manifest index:

```bash
dcopy copy --all docker://ubuntu:22.04 docker://myregistry.io/ubuntu:22.04
```

Copy a specific platform:

```bash
dcopy copy --platform linux/arm64 docker://ubuntu:22.04 docker://myregistry.io/ubuntu:22.04
```

### Inspect image metadata

```bash
dcopy inspect docker://ubuntu:22.04
```

Print raw manifest or config JSON:

```bash
dcopy inspect --raw docker://ubuntu:22.04
dcopy inspect --config docker://ubuntu:22.04
```

### List tags

```bash
dcopy list-tags docker://ubuntu
```

## Reference Format

References use a `TRANSPORT:REFERENCE` notation. The `docker://` transport is the only one fully implemented. When no transport prefix is given, `docker://` is assumed.

```
docker://registry.io/image:tag
docker://registry.io/image@sha256:<digest>
```

## Authentication

Credentials are resolved in this order:

1. `--src-creds USER:PASS` / `--dest-creds USER:PASS` / `--creds USER:PASS` CLI flags
2. `~/.docker/config.json` (the `auth` field or `username`/`password` fields)

> **Note:** External credential helpers (e.g. `docker-credential-desktop`) are not currently supported.

## Architecture

`dcopy` mirrors containerd's architecture in Rust:

- `Resolver`, `Fetcher`, and `Pusher` traits map to containerd's `core/remotes/` interfaces
- `Descriptor`, `Manifest`, `Index` model OCI and Docker Schema 2 wire formats
- Platform matching follows the same rules as `github.com/containerd/platforms`

The registry HTTP client is implemented in Go (`go/libdcopy.go`) using containerd's `core/remotes/docker` package and compiled into a static C archive (`libdcopy_go.a`) that is linked into the Rust binary at build time.

