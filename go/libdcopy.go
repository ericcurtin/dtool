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

// dcopy_run_image_proxy implements the containers-image-proxy protocol.
//
// containers-image-proxy-rs v0.9+ passes the proxy socket as stdin (fd 0)
// via c.stdin(Stdio::from(theirsock)) using AF_UNIX SOCK_SEQPACKET.
//
// Protocol: raw JSON datagrams over SOCK_SEQPACKET — no length prefix.
//   Request:  {"method":"...","args":[...]}   (one send per message)
//   Reply:    {"success":bool,"error":"...","pipeid":N,"value":...}
//   Blob data and manifests are streamed via pipe fds passed in SCM_RIGHTS.
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

// proxyReply is the wire reply struct for the containers-image-proxy protocol.
type proxyReply struct {
	Success bool        `json:"success"`
	Error   string      `json:"error"`
	PipeId  uint32      `json:"pipeid"`
	Value   interface{} `json:"value"`
}

// maxMsgSize matches the skopeo constant; no JSON message exceeds this.
const maxMsgSize = 32 * 1024

func runImageProxy(sockFD int) error {
	ppidForLog := os.Getppid()
	fmt.Fprintf(os.Stderr, "[dcopy-proxy] starting on fd %d DCOPY_OCI_DIR=%s DCOPY_OCI_FD=%s ppid=%d\n",
		sockFD, os.Getenv("DCOPY_OCI_DIR"), os.Getenv("DCOPY_OCI_FD"), ppidForLog)
	if fdStr := os.Getenv("DCOPY_OCI_FD"); fdStr != "" {
		testDir := fmt.Sprintf("/proc/%d/fd/%s", ppidForLog, fdStr)
		if entries, err := os.ReadDir(testDir); err == nil {
			fmt.Fprintf(os.Stderr, "[dcopy-proxy] OCI dir %s accessible: %d entries\n", testDir, len(entries))
		} else {
			fmt.Fprintf(os.Stderr, "[dcopy-proxy] OCI dir %s NOT accessible: %v\n", testDir, err)
		}
	}

	// Wrap the inherited SEQPACKET fd as a *net.UnixConn.
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
	var nextPipe uint32 = 1
	pipewEnds := map[uint32]*os.File{} // pipeid → write end (close on FinishPipe)

	// sendOK sends a success reply, optionally attaching fds via SCM_RIGHTS.
	sendOK := func(value interface{}, pipeid uint32, fds ...int) {
		data, _ := json.Marshal(proxyReply{Success: true, PipeId: pipeid, Value: value})
		if len(fds) > 0 {
			uc.WriteMsgUnix(data, syscall.UnixRights(fds...), nil) //nolint:errcheck
		} else {
			uc.Write(data) //nolint:errcheck
		}
	}
	sendErr := func(e string) {
		data, _ := json.Marshal(proxyReply{Error: e})
		uc.Write(data) //nolint:errcheck
	}

	buf := make([]byte, maxMsgSize)
	for {
		// SEQPACKET: each Read returns exactly one complete datagram.
		n, err := uc.Read(buf)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		var req struct {
			Method string            `json:"method"`
			Args   []json.RawMessage `json:"args"`
		}
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			sendErr(fmt.Sprintf("parse request: %v", err))
			continue
		}

		arg0 := func() json.RawMessage {
			if len(req.Args) > 0 {
				return req.Args[0]
			}
			return nil
		}

		switch req.Method {

		case "Initialize":
			// Return 0.2.5: satisfies ^0.2.3 (base) AND ^0.2.5 (GetLayerInfo).
			// GetLayerInfo is required by ostree-ext for docker-daemon: transport.
			sendOK("0.2.5", 0)

		case "OpenImage", "OpenImageOptional":
			var ref string
			json.Unmarshal(arg0(), &ref) //nolint:errcheck
			fmt.Fprintf(os.Stderr, "[dcopy-proxy] %s: %s\n", req.Method, ref)

			var dir, tag string
			if fdStr := os.Getenv("DCOPY_OCI_FD"); fdStr != "" {
				// Access the OCI dir through the parent process's open fd.
				// bootc changes its mount namespace before spawning us, so
				// filesystem paths may not resolve.  /proc/$PPID/fd/N is
				// process-scoped (not namespace-scoped) and always works.
				dir = fmt.Sprintf("/proc/%d/fd/%s", os.Getppid(), fdStr)
				_, tag = parseOCIRef(ref)
				if tag == "" {
					tag = "latest"
				}
			} else if cacheDir := os.Getenv("DCOPY_OCI_DIR"); cacheDir != "" {
				dir = cacheDir
				_, tag = parseOCIRef(ref)
				if tag == "" {
					tag = "latest"
				}
			} else {
				dir, tag = parseOCIRef(ref)
			}

			mdata, mdigest, err := readOCIManifest(dir, tag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[dcopy-proxy] %s error: %v\n", req.Method, err)
				if req.Method == "OpenImageOptional" {
					sendOK(uint32(0), 0) // 0 = not found
				} else {
					sendErr(err.Error())
				}
				continue
			}
			h := nextHandle
			nextHandle++
			handles[h] = &imageHandle{dir, mdata, mdigest}
			sendOK(h, 0)

		case "GetManifest":
			var h uint32
			json.Unmarshal(arg0(), &h) //nolint:errcheck
			img := handles[h]
			if img == nil {
				sendErr("invalid handle")
				continue
			}
			r, w, err := os.Pipe()
			if err != nil {
				sendErr(err.Error())
				continue
			}
			pid := nextPipe
			nextPipe++
			pipewEnds[pid] = w
			go func(data []byte) { defer w.Close(); w.Write(data) }(img.manifestData) //nolint:errcheck
			// value = digest string; pipeid = pid; SCM_RIGHTS = [r]
			sendOK(img.manifestDigest, pid, int(r.Fd()))
			r.Close()

		case "GetFullConfig":
			var h uint32
			json.Unmarshal(arg0(), &h) //nolint:errcheck
			img := handles[h]
			if img == nil {
				sendErr("invalid handle")
				continue
			}
			cfgData, err := readOCIConfig(img.ociDir, img.manifestData)
			if err != nil {
				sendErr(err.Error())
				continue
			}
			r, w, err := os.Pipe()
			if err != nil {
				sendErr(err.Error())
				continue
			}
			pid := nextPipe
			nextPipe++
			pipewEnds[pid] = w
			go func(data []byte) { defer w.Close(); w.Write(data) }(cfgData) //nolint:errcheck
			sendOK(nil, pid, int(r.Fd()))
			r.Close()

		case "GetBlob":
			var h uint32
			var digest string
			json.Unmarshal(arg0(), &h) //nolint:errcheck
			if len(req.Args) > 1 {
				json.Unmarshal(req.Args[1], &digest) //nolint:errcheck
			}
			img := handles[h]
			if img == nil {
				sendErr("invalid handle")
				continue
			}
			blobPath := blobFilePath(img.ociDir, digest)
			fi, err := os.Stat(blobPath)
			if err != nil {
				// Include diagnostic info in the error so it appears in bootc output.
				diag := fmt.Sprintf("stat(%s): %v", blobPath, err)
				blobDir := filepath.Join(img.ociDir, "blobs", "sha256")
				if entries, rderr := os.ReadDir(blobDir); rderr == nil {
					diag += fmt.Sprintf("; blobs/sha256 has %d files", len(entries))
					if len(entries) > 0 {
						diag += fmt.Sprintf("; first=%s", entries[0].Name())
					}
					if len(entries) > 1 {
						diag += fmt.Sprintf("; last=%s", entries[len(entries)-1].Name())
					}
				} else {
					diag += fmt.Sprintf("; readdir(%s): %v", blobDir, rderr)
				}
				sendErr(diag)
				continue
			}
			r, w, err := os.Pipe()
			if err != nil {
				sendErr(err.Error())
				continue
			}
			pid := nextPipe
			nextPipe++
			pipewEnds[pid] = w
			go func(path string) {
				defer w.Close()
				if f, err := os.Open(path); err == nil {
					defer f.Close()
					io.Copy(w, f) //nolint:errcheck
				}
			}(blobPath)
			sendOK(fi.Size(), pid, int(r.Fd()))
			r.Close()

		case "GetRawBlob":
			var h uint32
			var digest string
			json.Unmarshal(arg0(), &h) //nolint:errcheck
			if len(req.Args) > 1 {
				json.Unmarshal(req.Args[1], &digest) //nolint:errcheck
			}
			img := handles[h]
			if img == nil {
				sendErr("invalid handle")
				continue
			}
			blobPath := blobFilePath(img.ociDir, digest)
			fi, err := os.Stat(blobPath)
			if err != nil {
				sendErr(err.Error())
				continue
			}
			dataR, dataW, _ := os.Pipe()
			errR, errW, _ := os.Pipe()
			go func(path string) {
				defer dataW.Close()
				defer errW.Close()
				f, err := os.Open(path)
				if err != nil {
					errJSON, _ := json.Marshal(map[string]string{"code": "other", "message": err.Error()})
					errW.Write(errJSON) //nolint:errcheck
					return
				}
				defer f.Close()
				io.Copy(dataW, f) //nolint:errcheck
			}(blobPath)
			// value = bloblen (i64); pipeid = 0; SCM_RIGHTS = [dataR, errR]
			sendOK(fi.Size(), 0, int(dataR.Fd()), int(errR.Fd()))
			dataR.Close()
			errR.Close()

		case "GetLayerInfo":
			var h uint32
			json.Unmarshal(arg0(), &h) //nolint:errcheck
			img := handles[h]
			if img == nil {
				sendErr("invalid handle")
				continue
			}
			info, err := buildLayerInfoList(img.ociDir, img.manifestData)
			if err != nil {
				sendErr(err.Error())
				continue
			}
			sendOK(info, 0)

		case "FinishPipe":
			var pid uint32
			json.Unmarshal(arg0(), &pid) //nolint:errcheck
			if w, ok := pipewEnds[pid]; ok {
				w.Close() //nolint:errcheck
				delete(pipewEnds, pid)
			}
			sendOK(nil, 0)

		case "CloseImage":
			var h uint32
			json.Unmarshal(arg0(), &h) //nolint:errcheck
			delete(handles, h)
			sendOK(nil, 0)

		case "Shutdown":
			sendOK(nil, 0)
			return nil

		default:
			fmt.Fprintf(os.Stderr, "[dcopy-proxy] unknown method: %s\n", req.Method)
			sendErr(fmt.Sprintf("unknown method: %s", req.Method))
		}
	}
}

// layerInfoEntry is the wire type for GetLayerInfo response entries.
// Fields match containers-image-proxy-rs ConvertedLayerInfo:
//   digest     = uncompressed diff ID from config.rootfs.diff_ids (sha256:...)
//   size       = compressed blob size from manifest.layers[i].size
//   media_type = compressed blob media type from manifest.layers[i].mediaType
type layerInfoEntry struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
}

// buildLayerInfoList reads the manifest and config to produce per-layer info.
// ostree-ext requires this for docker-daemon: transport (version ≥ 0.2.5).
func buildLayerInfoList(ociDir string, manifestData []byte) ([]layerInfoEntry, error) {
	var manifest struct {
		Layers []struct {
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			MediaType string `json:"mediaType"`
		} `json:"layers"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	cfgData, err := os.ReadFile(blobFilePath(ociDir, manifest.Config.Digest))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	result := make([]layerInfoEntry, len(manifest.Layers))
	for i, layer := range manifest.Layers {
		var diffID string
		if i < len(cfg.RootFS.DiffIDs) {
			diffID = cfg.RootFS.DiffIDs[i] // "sha256:uncompressed_hex"
		}
		result[i] = layerInfoEntry{
			Digest:    diffID,
			Size:      layer.Size,
			MediaType: layer.MediaType,
		}
	}
	return result, nil
}

// blobFilePath returns the path to a blob in an OCI layout directory.
func blobFilePath(ociDir, digest string) string {
	return filepath.Join(ociDir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// readOCIConfig reads the config blob from an OCI layout, given the manifest.
func readOCIConfig(ociDir string, manifestData []byte) ([]byte, error) {
	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest for config digest: %w", err)
	}
	return os.ReadFile(blobFilePath(ociDir, manifest.Config.Digest))
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
