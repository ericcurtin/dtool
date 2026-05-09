// Package main provides a CGo-exported C library that wraps containerd's
// Docker Registry client for use by the Rust dcopy binary.
//
// All registry HTTP operations use containerd's auth stack:
//
//	github.com/containerd/containerd/v2/core/remotes/docker.NewDockerAuthorizer
//
// which implements the same bearer-token challenge/response cycle that
// containerd itself uses.  Blob push operations additionally use containerd's
// Pusher interface (docker.NewResolver → resolver.Pusher) so that the
// OCI Distribution Spec POST+PUT upload protocol is handled by containerd code.
//
// Memory contract
//
//	All *C.char pointers returned by exported functions are heap-allocated via
//	C.CString or C.CBytes and MUST be freed by the caller with dcopy_free.
//	Input *C.char parameters are read-only; Go copies them with C.GoString.
package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"
import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Accept header sent when fetching manifests — same list as containerd's
// core/remotes/docker/fetcher.go.
const manifestAccept = "application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.oci.image.index.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json," +
	"application/vnd.docker.distribution.manifest.v1+prettyjws"

// ── Helpers ───────────────────────────────────────────────────────────────────

func gostr(s *C.char) string { return C.GoString(s) }

func errResult(err error) *C.char {
	return C.CString(fmt.Sprintf("ERROR:%s", err.Error()))
}

func bytesResult(b []byte, outLen *C.int) *C.char {
	*outLen = C.int(len(b))
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(C.CBytes(b))
}

// makeAuthorizer creates a containerd docker.Authorizer with optional
// credentials.  This is the core of the Go integration — the authorizer
// handles the full bearer-token challenge/response cycle including:
//   - Docker Hub anonymous token (auth.docker.io)
//   - Authenticated token fetch (private registries)
//   - Token caching between requests (via the shared authorizer instance)
func makeAuthorizer(username, password string) docker.Authorizer {
	if username != "" {
		return docker.NewDockerAuthorizer(
			docker.WithAuthCreds(func(string) (string, string, error) {
				return username, password, nil
			}),
		)
	}
	return docker.NewDockerAuthorizer()
}

// makeResolver creates a containerd Docker resolver.
// Used only for push operations, which need the full Pusher interface.
func makeResolver(registry, username, password string) *docker.ResolverOptions {
	var regOpts []docker.RegistryOpt
	regOpts = append(regOpts, docker.WithAuthorizer(makeAuthorizer(username, password)))
	return &docker.ResolverOptions{
		Hosts: docker.ConfigureDefaultRegistries(regOpts...),
	}
}

// doAuthedRequest sends an HTTP request with containerd's bearer-token auth.
//
// Implements the same challenge/response cycle as
// containerd core/remotes/docker/resolver.go:
//  1. Send request (may get 401 on first call)
//  2. Call authorizer.AddResponses to fetch/refresh token
//  3. Retry once with the new token
func doAuthedRequest(ctx context.Context, client *http.Client, authorizer docker.Authorizer, req *http.Request) (*http.Response, error) {
	// Clone request for potential retry
	reqClone, err := cloneRequest(req)
	if err != nil {
		return nil, err
	}

	if err := authorizer.Authorize(ctx, req); err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Feed the 401 to the authorizer to trigger a token fetch, then retry.
	if addErr := authorizer.AddResponses(ctx, []*http.Response{resp}); addErr != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("auth challenge: %w", addErr)
	}
	resp.Body.Close()

	if err := authorizer.Authorize(ctx, reqClone); err != nil {
		return nil, fmt.Errorf("authorize (retry): %w", err)
	}
	return client.Do(reqClone)
}

// cloneRequest creates a shallow clone of an HTTP request suitable for retry.
func cloneRequest(req *http.Request) (*http.Request, error) {
	clone, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Header {
		clone.Header[k] = v
	}
	if req.Body != nil {
		clone.Body = req.Body
	}
	return clone, nil
}

// ── dcopy_free ────────────────────────────────────────────────────────────────

// dcopy_free releases C-heap memory previously returned by any dcopy_* call.
//
//export dcopy_free
func dcopy_free(ptr unsafe.Pointer) {
	C.free(ptr)
}

// ── dcopy_list_tags ───────────────────────────────────────────────────────────

// dcopy_list_tags lists all tags via GET /v2/{name}/tags/list.
//
// Uses containerd's docker.NewDockerAuthorizer for the full bearer-token cycle.
//
//export dcopy_list_tags
func dcopy_list_tags(
	cRegistry, cRepository, cUsername, cPassword *C.char,
	outLen *C.int,
) *C.char {
	tags, err := listTags(gostr(cRegistry), gostr(cRepository), gostr(cUsername), gostr(cPassword))
	if err != nil {
		*outLen = -1
		return errResult(err)
	}
	data, err := json.Marshal(tags)
	if err != nil {
		*outLen = -1
		return errResult(err)
	}
	return bytesResult(data, outLen)
}

func listTags(registry, repository, username, password string) ([]string, error) {
	ctx := context.Background()
	authorizer := makeAuthorizer(username, password)
	client := &http.Client{}

	url := fmt.Sprintf("https://%s/v2/%s/tags/list", registry, repository)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := doAuthedRequest(ctx, client, authorizer, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags/list returned %d", resp.StatusCode)
	}

	var tagList struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tagList); err != nil {
		return nil, err
	}
	return tagList.Tags, nil
}

// ── dcopy_fetch_manifest ──────────────────────────────────────────────────────

// dcopy_fetch_manifest fetches a manifest using containerd's DockerAuthorizer.
//
// Sends GET /v2/{name}/manifests/{reference} with the full Accept header list.
// Uses containerd's bearer-token auth (same code as resolver.Resolve).
//
//export dcopy_fetch_manifest
func dcopy_fetch_manifest(
	cRegistry, cRepository, cReference, cUsername, cPassword *C.char,
	outLen *C.int,
	outContentType **C.char,
	outDigest **C.char,
) *C.char {
	data, ct, dg, err := fetchManifest(
		gostr(cRegistry), gostr(cRepository), gostr(cReference),
		gostr(cUsername), gostr(cPassword),
	)
	if err != nil {
		*outLen = -1
		return errResult(err)
	}
	*outContentType = C.CString(ct)
	*outDigest = C.CString(dg)
	return bytesResult(data, outLen)
}

func fetchManifest(registry, repository, reference, username, password string) ([]byte, string, string, error) {
	ctx := context.Background()
	authorizer := makeAuthorizer(username, password)
	client := &http.Client{}

	ref := reference
	if ref == "" {
		ref = "latest"
	}
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Accept", manifestAccept)

	resp, err := doAuthedRequest(ctx, client, authorizer, req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("manifest GET returned %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	dg := resp.Header.Get("Docker-Content-Digest")

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", err
	}

	// Compute digest if not provided by the registry
	if dg == "" {
		h := sha256.New()
		h.Write(data)
		dg = "sha256:" + hex.EncodeToString(h.Sum(nil))
	}

	return data, ct, dg, nil
}

// ── dcopy_fetch_blob ──────────────────────────────────────────────────────────

// dcopy_fetch_blob fetches a blob via GET /v2/{name}/blobs/{digest}.
//
// Uses containerd's docker.NewDockerAuthorizer for auth.
//
//export dcopy_fetch_blob
func dcopy_fetch_blob(
	cRegistry, cRepository, cDigest, cMediaType, cUsername, cPassword *C.char,
	outLen *C.int,
) *C.char {
	data, err := fetchBlob(
		gostr(cRegistry), gostr(cRepository),
		gostr(cDigest), gostr(cMediaType),
		gostr(cUsername), gostr(cPassword),
	)
	if err != nil {
		*outLen = -1
		return errResult(err)
	}
	return bytesResult(data, outLen)
}

func fetchBlob(registry, repository, dgstStr, _, username, password string) ([]byte, error) {
	ctx := context.Background()
	authorizer := makeAuthorizer(username, password)
	client := &http.Client{}

	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, dgstStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := doAuthedRequest(ctx, client, authorizer, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("blob GET returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ── dcopy_blob_exists ─────────────────────────────────────────────────────────

// dcopy_blob_exists checks blob existence via HEAD /v2/{name}/blobs/{digest}.
//
// Returns 1=exists, 0=not found, -1=error.
//
//export dcopy_blob_exists
func dcopy_blob_exists(
	cRegistry, cRepository, cDigest, cUsername, cPassword *C.char,
	outError **C.char,
) C.int {
	exists, err := blobExists(
		gostr(cRegistry), gostr(cRepository), gostr(cDigest),
		gostr(cUsername), gostr(cPassword),
	)
	if err != nil {
		*outError = C.CString(err.Error())
		return -1
	}
	if exists {
		return 1
	}
	return 0
}

func blobExists(registry, repository, dgstStr, username, password string) (bool, error) {
	ctx := context.Background()
	authorizer := makeAuthorizer(username, password)
	client := &http.Client{}

	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, dgstStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, err
	}

	resp, err := doAuthedRequest(ctx, client, authorizer, req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("HEAD blob returned %d", resp.StatusCode)
	}
}

// ── dcopy_push_blob ───────────────────────────────────────────────────────────

// dcopy_push_blob pushes a blob using containerd's Pusher interface.
//
// Delegates to docker.NewResolver → resolver.Pusher → pusher.Push →
// content.Writer.Commit, which implements the OCI Distribution Spec
// POST + PUT upload protocol.  ErrAlreadyExists is treated as success.
//
//export dcopy_push_blob
func dcopy_push_blob(
	cRegistry, cRepository, cDigest, cMediaType, cUsername, cPassword *C.char,
	data *C.char, dataLen C.int,
) *C.char {
	raw := C.GoBytes(unsafe.Pointer(data), dataLen)
	err := pushBlob(
		gostr(cRegistry), gostr(cRepository),
		gostr(cDigest), gostr(cMediaType),
		gostr(cUsername), gostr(cPassword),
		raw,
	)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func pushBlob(registry, repository, dgstStr, mediaType, username, password string, data []byte) error {
	ctx := context.Background()

	dgst, err := godigest.Parse(dgstStr)
	if err != nil {
		return fmt.Errorf("parse digest: %w", err)
	}

	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    dgst,
		Size:      int64(len(data)),
	}

	opts := makeResolver(registry, username, password)
	resolver := docker.NewResolver(*opts)
	ref := fmt.Sprintf("%s/%s:dcopy-upload", registry, repository)

	pusher, err := resolver.Pusher(ctx, ref)
	if err != nil {
		return fmt.Errorf("pusher: %w", err)
	}

	writer, err := pusher.Push(ctx, desc)
	if errdefs.IsAlreadyExists(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("push init: %w", err)
	}
	defer writer.Close()

	if _, err := io.Copy(writer, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write blob: %w", err)
	}

	if err := writer.Commit(ctx, int64(len(data)), dgst); err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("commit blob: %w", err)
	}
	return nil
}

// ── dcopy_push_manifest ───────────────────────────────────────────────────────

// dcopy_push_manifest pushes a manifest via PUT /v2/{name}/manifests/{reference}.
//
// Uses containerd's docker.NewDockerAuthorizer for auth then a direct PUT
// request.  This matches containerd's own manifest push path.
//
//export dcopy_push_manifest
func dcopy_push_manifest(
	cRegistry, cRepository, cReference, cMediaType, cUsername, cPassword *C.char,
	data *C.char, dataLen C.int,
) *C.char {
	raw := C.GoBytes(unsafe.Pointer(data), dataLen)
	err := pushManifest(
		gostr(cRegistry), gostr(cRepository), gostr(cReference),
		gostr(cMediaType),
		gostr(cUsername), gostr(cPassword),
		raw,
	)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func pushManifest(registry, repository, reference, mediaType, username, password string, data []byte) error {
	ctx := context.Background()
	authorizer := makeAuthorizer(username, password)
	client := &http.Client{}

	ref := reference
	if ref == "" {
		dgst := sha256.New()
		dgst.Write(data)
		ref = "sha256:" + hex.EncodeToString(dgst.Sum(nil))
	}

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	resp, err := doAuthedRequest(ctx, client, authorizer, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		return nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("push manifest returned %d: %s", resp.StatusCode, body)
	}
}

// ── dcopy_daemon_to_oci_dir ───────────────────────────────────────────────────

// dcopy_daemon_to_oci_dir reads an image from the local Docker daemon via
// /var/run/docker.sock (using the GET /images/{name}/get endpoint which
// returns a docker-archive tar stream) and writes it as an OCI image layout
// directory at destPath.
//
// The OCI index.json is annotated with org.opencontainers.image.ref.name so
// that bootc/ostree-ext can locate the image by tag (e.g. oci:/path:latest).
//
// Returns NULL on success; an "ERROR:…" C string on failure (free with dcopy_free).
//
//export dcopy_daemon_to_oci_dir
func dcopy_daemon_to_oci_dir(cImageName, cDestPath *C.char) *C.char {
	if err := daemonToOCIDir(gostr(cImageName), gostr(cDestPath)); err != nil {
		return C.CString(fmt.Sprintf("ERROR:%s", err.Error()))
	}
	return nil
}

// dockerArchiveManifest is a single entry in the manifest.json that docker save emits.
type dockerArchiveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// ociManifestJSON is the OCI image manifest (schemaVersion 2).
type ociManifestJSON struct {
	SchemaVersion int            `json:"schemaVersion"`
	MediaType     string         `json:"mediaType"`
	Config        ociDescriptor  `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

// ociDescriptor is a content descriptor used in OCI manifests and indices.
type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ociIndex is the OCI image index (index.json).
type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

func daemonToOCIDir(imageName, destPath string) error {
	// Dial the Docker daemon Unix socket for all requests.
	dockerClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}

	// GET /v1.44/images/{name}/get  →  docker-archive tar stream.
	endpoint := fmt.Sprintf("http://localhost/v1.44/images/%s/get",
		url.PathEscape(imageName))
	resp, err := dockerClient.Get(endpoint)
	if err != nil {
		return fmt.Errorf("docker GET image: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker GET image returned %d: %s", resp.StatusCode, body)
	}

	// ── Read every tar entry into memory ─────────────────────────────────────
	// The docker-archive is typically a few hundred MB to a few GB; reading into
	// a map[path][]byte is the simplest approach given that we need random access
	// to entries (manifest.json may appear last in the stream).
	entries := map[string][]byte{}
	tr := tar.NewReader(resp.Body)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("read tar entry %s: %w", hdr.Name, err)
		}
		entries[hdr.Name] = data
	}

	// ── Parse manifest.json ───────────────────────────────────────────────────
	manifestJSON, ok := entries["manifest.json"]
	if !ok {
		return fmt.Errorf("manifest.json not found in docker archive")
	}
	var archiveManifests []dockerArchiveManifest
	if err := json.Unmarshal(manifestJSON, &archiveManifests); err != nil {
		return fmt.Errorf("parse manifest.json: %w", err)
	}
	if len(archiveManifests) == 0 {
		return fmt.Errorf("no images in docker archive")
	}
	am := archiveManifests[0]

	// ── Set up OCI layout directory ───────────────────────────────────────────
	os.RemoveAll(destPath)
	blobsDir := filepath.Join(destPath, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return fmt.Errorf("create blobs dir: %w", err)
	}

	writeBlob := func(data []byte) (string, error) {
		dgst := sha256Hex(data)
		path := filepath.Join(blobsDir, dgst)
		if err := os.WriteFile(path, data, 0644); err != nil {
			return "", fmt.Errorf("write blob %s: %w", dgst, err)
		}
		return "sha256:" + dgst, nil
	}

	// oci-layout marker file (required by OCI spec)
	ociLayoutMarker := []byte(`{"imageLayoutVersion":"1.0.0"}`)
	if err := os.WriteFile(filepath.Join(destPath, "oci-layout"), ociLayoutMarker, 0644); err != nil {
		return fmt.Errorf("write oci-layout: %w", err)
	}

	// ── Write config blob ─────────────────────────────────────────────────────
	configData, ok := entries[am.Config]
	if !ok {
		return fmt.Errorf("config %s not found in docker archive", am.Config)
	}
	configDigest, err := writeBlob(configData)
	if err != nil {
		return err
	}

	// ── Write layer blobs ─────────────────────────────────────────────────────
	// Docker-archive layers are stored as plain (uncompressed) tars.
	// OCI requires gzip-compressed layers.
	ociLayers := make([]ociDescriptor, 0, len(am.Layers))
	for _, layerPath := range am.Layers {
		layerData, ok := entries[layerPath]
		if !ok {
			return fmt.Errorf("layer %s not found in docker archive", layerPath)
		}

		// Gzip the layer if it is not already compressed.
		var blobData []byte
		if isGzip(layerData) {
			blobData = layerData
		} else {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			if _, err := gw.Write(layerData); err != nil {
				return fmt.Errorf("gzip layer: %w", err)
			}
			if err := gw.Close(); err != nil {
				return fmt.Errorf("gzip close: %w", err)
			}
			blobData = buf.Bytes()
		}

		layerDigest, err := writeBlob(blobData)
		if err != nil {
			return err
		}
		ociLayers = append(ociLayers, ociDescriptor{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Digest:    layerDigest,
			Size:      int64(len(blobData)),
		})
	}

	// ── Build and write OCI image manifest ───────────────────────────────────
	ociMan := ociManifestJSON{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config: ociDescriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configData)),
		},
		Layers: ociLayers,
	}
	manifestData, err := json.Marshal(ociMan)
	if err != nil {
		return fmt.Errorf("marshal OCI manifest: %w", err)
	}
	manifestDigest, err := writeBlob(manifestData)
	if err != nil {
		return err
	}

	// ── Build and write index.json ────────────────────────────────────────────
	// Extract the tag to set as org.opencontainers.image.ref.name so that
	// bootc/ostree-ext can look up the image by tag (e.g. oci:/path:latest).
	tag := "latest"
	if len(am.RepoTags) > 0 {
		parts := strings.SplitN(am.RepoTags[0], ":", 2)
		if len(parts) == 2 {
			tag = parts[1]
		}
	}

	idx := ociIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    manifestDigest,
				Size:      int64(len(manifestData)),
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": tag,
				},
			},
		},
	}
	indexData, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("marshal OCI index: %w", err)
	}
	if err := os.WriteFile(filepath.Join(destPath, "index.json"), indexData, 0644); err != nil {
		return fmt.Errorf("write index.json: %w", err)
	}

	return nil
}

// ── dcopy_run_image_proxy ─────────────────────────────────────────────────────

// dcopy_run_image_proxy implements the containers-image-proxy protocol v0.
//
// bootc (via the containers-image-proxy-rs Rust crate) calls
// "skopeo experimental-image-proxy --sockfd N" to get image data without
// having to pull from a registry.  We implement that same protocol so dcopy
// can act as a drop-in skopeo replacement (hardlinked as /usr/bin/skopeo).
//
// Protocol (v0):
//   Each message is framed as [uint32 big-endian length][JSON bytes].
//   Request:  {"method": "...", "args": <value>}
//   Reply:    {"success": bool, "value": <value>, "err": "..."}
//   FetchBlob reply additionally sends the pipe read-fd via SCM_RIGHTS.
//
//export dcopy_run_image_proxy
func dcopy_run_image_proxy(cSockFD C.int) *C.char {
	if err := runImageProxy(int(cSockFD)); err != nil {
		return C.CString(fmt.Sprintf("ERROR:%s", err.Error()))
	}
	return nil
}

// imageHandle holds the state for a single opened OCI image.
type imageHandle struct {
	ociDir         string
	manifestData   []byte
	manifestDigest string
}

func runImageProxy(sockFD int) error {
	// Wrap the inherited fd as a *net.UnixConn so we can call WriteMsgUnix
	// (needed for SCM_RIGHTS blob-fd passing).
	nc, err := net.FileConn(os.NewFile(uintptr(sockFD), "proxy"))
	if err != nil {
		return fmt.Errorf("wrap sockfd %d: %w", sockFD, err)
	}
	defer nc.Close()
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("sockfd %d is not a Unix socket", sockFD)
	}

	handles := map[uint32]*imageHandle{}
	var nextHandle uint32 = 1

	// readMsg reads one length-prefixed JSON message from the socket.
	readMsg := func() (method string, args json.RawMessage, err error) {
		var lb [4]byte
		if _, err = io.ReadFull(uc, lb[:]); err != nil {
			return
		}
		buf := make([]byte, binary.BigEndian.Uint32(lb[:]))
		if _, err = io.ReadFull(uc, buf); err != nil {
			return
		}
		var req struct {
			Method string          `json:"method"`
			Args   json.RawMessage `json:"args"`
		}
		err = json.Unmarshal(buf, &req)
		return req.Method, req.Args, err
	}

	// sendMsg sends a length-prefixed JSON reply, optionally with a file
	// descriptor attached via SCM_RIGHTS (set fd < 0 to skip).
	sendMsg := func(rep interface{}, fd int) {
		data, _ := json.Marshal(rep)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(data)))
		msg := append(lb[:], data...)
		if fd >= 0 {
			uc.WriteMsgUnix(msg, syscall.UnixRights(fd), nil) //nolint:errcheck
		} else {
			uc.Write(msg) //nolint:errcheck
		}
	}

	ok2Reply := func(value interface{}) map[string]interface{} {
		return map[string]interface{}{"success": true, "value": value}
	}
	errReply := func(e string) map[string]interface{} {
		return map[string]interface{}{"success": false, "err": e}
	}

	for {
		method, rawArgs, err := readMsg()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read message: %w", err)
		}

		switch method {

		case "Initialize":
			// Negotiate protocol version 0.
			sendMsg(ok2Reply(uint32(0)), -1)

		case "OpenImage", "OpenImageOptional":
			var ref string
			json.Unmarshal(rawArgs, &ref) //nolint:errcheck
			dir, tag := parseOCIRef(ref)
			mdata, mdigest, err := readOCIManifest(dir, tag)
			if err != nil {
				if method == "OpenImageOptional" {
					sendMsg(ok2Reply(nil), -1)
				} else {
					sendMsg(errReply(err.Error()), -1)
				}
				continue
			}
			h := nextHandle
			nextHandle++
			handles[h] = &imageHandle{dir, mdata, mdigest}
			sendMsg(ok2Reply(h), -1)

		case "GetManifest":
			// args may be just the handle (int) or {"handle":N,"accept_types":[...]}
			var h uint32
			if err := json.Unmarshal(rawArgs, &h); err != nil {
				// try object form
				var obj struct {
					Handle uint32 `json:"handle"`
				}
				json.Unmarshal(rawArgs, &obj) //nolint:errcheck
				h = obj.Handle
			}
			img := handles[h]
			if img == nil {
				sendMsg(errReply("invalid handle"), -1)
				continue
			}
			sendMsg(ok2Reply(map[string]interface{}{
				"manifest": base64.StdEncoding.EncodeToString(img.manifestData),
				"digest":   img.manifestDigest,
			}), -1)

		case "FetchBlob":
			var args struct {
				Handle uint32 `json:"handle"`
				Digest string `json:"digest"`
			}
			json.Unmarshal(rawArgs, &args) //nolint:errcheck
			img := handles[args.Handle]
			if img == nil {
				sendMsg(errReply("invalid handle"), -1)
				continue
			}
			hexDg := strings.TrimPrefix(args.Digest, "sha256:")
			blobPath := filepath.Join(img.ociDir, "blobs", "sha256", hexDg)
			fi, err := os.Stat(blobPath)
			if err != nil {
				sendMsg(errReply(err.Error()), -1)
				continue
			}
			// Create a pipe; stream blob to write-end in a goroutine;
			// send read-end to client via SCM_RIGHTS.
			r, w, err := os.Pipe()
			if err != nil {
				sendMsg(errReply(err.Error()), -1)
				continue
			}
			go func(blobPath string, w *os.File) {
				defer w.Close()
				f, err := os.Open(blobPath)
				if err != nil {
					return
				}
				defer f.Close()
				io.Copy(w, f) //nolint:errcheck
			}(blobPath, w)
			// Reply carries the blob size; the pipe read-fd is attached via SCM_RIGHTS.
			sendMsg(ok2Reply(fi.Size()), int(r.Fd()))
			r.Close() // kernel keeps the fd alive in the socket buffer

		case "CloseImage":
			var h uint32
			json.Unmarshal(rawArgs, &h) //nolint:errcheck
			delete(handles, h)
			sendMsg(ok2Reply(nil), -1)

		case "Finish", "Complete":
			sendMsg(ok2Reply(nil), -1)
			return nil

		default:
			sendMsg(errReply(fmt.Sprintf("unknown method: %s", method)), -1)
		}
	}
}

// parseOCIRef parses an "oci:/path:tag" reference into (dir, tag).
func parseOCIRef(ref string) (dir, tag string) {
	rest := strings.TrimPrefix(ref, "oci:")
	// Tag is the component after the LAST colon, but only if the colon is
	// not inside the path (Linux paths don't contain colons).
	if idx := strings.LastIndex(rest, ":"); idx > 0 {
		return rest[:idx], rest[idx+1:]
	}
	return rest, "latest"
}

// readOCIManifest reads the manifest for `tag` from an OCI layout directory.
func readOCIManifest(ociDir, tag string) (data []byte, digest string, err error) {
	indexData, err := os.ReadFile(filepath.Join(ociDir, "index.json"))
	if err != nil {
		return nil, "", fmt.Errorf("read index.json: %w", err)
	}
	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, "", fmt.Errorf("parse index.json: %w", err)
	}
	for _, m := range index.Manifests {
		if m.Annotations["org.opencontainers.image.ref.name"] == tag {
			digest = m.Digest
			break
		}
	}
	if digest == "" && len(index.Manifests) > 0 {
		digest = index.Manifests[0].Digest // fallback: first manifest
	}
	if digest == "" {
		return nil, "", fmt.Errorf("no manifest found for tag %q in %s", tag, ociDir)
	}
	hex := strings.TrimPrefix(digest, "sha256:")
	data, err = os.ReadFile(filepath.Join(ociDir, "blobs", "sha256", hex))
	if err != nil {
		return nil, "", fmt.Errorf("read manifest blob: %w", err)
	}
	return data, digest, nil
}

// sha256Hex returns the hex-encoded SHA-256 digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// isGzip reports whether data begins with the gzip magic number.
func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func main() {}
