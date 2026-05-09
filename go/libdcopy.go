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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"unsafe"

	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Accept header sent when fetching manifests — same list as containerd's
// core/remotes/docker/fetcher.go and skopeo's go.podman.io/image/v5/manifest.
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

func main() {}
