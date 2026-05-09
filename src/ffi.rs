/// FFI bindings to the Go/containerd c-archive (`libdcopy_go.a`).
///
/// Every `extern "C"` declaration here corresponds to an `//export dcopy_*`
/// function in `go/libdcopy.go`.  The Go functions use containerd's
/// `core/remotes/docker` package for all registry operations.
///
/// # Memory safety
///
/// - All `*mut c_char` return values are allocated on the C heap by Go
///   (via `C.CString` or `C.CBytes`) and **must** be freed by calling
///   [`dcopy_free`] after use.
/// - All `*const c_char` input parameters are read-only; Go copies them
///   immediately with `C.GoString`.
/// - `*mut *mut c_char` output parameters are set to newly-allocated C
///   strings; each must be freed independently.
use std::ffi::{c_char, c_int, c_void};

extern "C" {
    /// Free a pointer previously returned by any `dcopy_*` function.
    ///
    /// Safe to call with NULL (no-op).
    pub fn dcopy_free(ptr: *mut c_void);

    /// List all tags for `registry/repository`.
    ///
    /// Returns JSON-encoded `string[]` on success; `"ERROR:…"` on failure.
    /// `*out_len` is set to the byte length of the returned buffer, or `-1` on error.
    ///
    /// Caller must free the returned pointer with `dcopy_free`.
    pub fn dcopy_list_tags(
        registry: *const c_char,
        repository: *const c_char,
        username: *const c_char,
        password: *const c_char,
        out_len: *mut c_int,
    ) -> *mut c_char;

    /// Resolve and fetch a manifest from `registry/repository` at `reference`
    /// (a tag or digest string).
    ///
    /// On success:
    ///   - returns the raw manifest bytes
    ///   - sets `*out_len` to the byte count
    ///   - sets `*out_content_type` to a newly-allocated C string
    ///   - sets `*out_digest` to a newly-allocated C string
    ///
    /// On failure returns `"ERROR:…"` and sets `*out_len = -1`.
    ///
    /// Caller must free all three pointers with `dcopy_free`.
    pub fn dcopy_fetch_manifest(
        registry: *const c_char,
        repository: *const c_char,
        reference: *const c_char,
        username: *const c_char,
        password: *const c_char,
        out_len: *mut c_int,
        out_content_type: *mut *mut c_char,
        out_digest: *mut *mut c_char,
    ) -> *mut c_char;

    /// Fetch a blob (image config or layer) identified by `digest`.
    ///
    /// Returns the raw blob bytes on success; `"ERROR:…"` on failure.
    /// `*out_len` is set to the byte count, or `-1` on error.
    ///
    /// Caller must free the returned pointer with `dcopy_free`.
    pub fn dcopy_fetch_blob(
        registry: *const c_char,
        repository: *const c_char,
        digest: *const c_char,
        media_type: *const c_char,
        username: *const c_char,
        password: *const c_char,
        out_len: *mut c_int,
    ) -> *mut c_char;

    /// Check whether a blob exists at the registry (HEAD request).
    ///
    /// Returns:
    ///   - `1`  — blob exists
    ///   - `0`  — blob does not exist
    ///   - `-1` — error; `*out_error` is set to a newly-allocated error string
    ///
    /// Caller must free `*out_error` (if set) with `dcopy_free`.
    pub fn dcopy_blob_exists(
        registry: *const c_char,
        repository: *const c_char,
        digest: *const c_char,
        username: *const c_char,
        password: *const c_char,
        out_error: *mut *mut c_char,
    ) -> c_int;

    /// Push a blob to the registry using containerd's Pusher interface
    /// (OCI Distribution Spec POST+PUT upload).
    ///
    /// If the blob already exists the push is a no-op (ErrAlreadyExists is
    /// swallowed).
    ///
    /// Returns NULL on success; a newly-allocated error C string on failure.
    /// Caller must free non-NULL returns with `dcopy_free`.
    pub fn dcopy_push_blob(
        registry: *const c_char,
        repository: *const c_char,
        digest: *const c_char,
        media_type: *const c_char,
        username: *const c_char,
        password: *const c_char,
        data: *const c_char,
        data_len: c_int,
    ) -> *mut c_char;

    /// Push a manifest to `registry/repository` at `reference` (tag or digest).
    ///
    /// Returns NULL on success; a newly-allocated error C string on failure.
    /// Caller must free non-NULL returns with `dcopy_free`.
    pub fn dcopy_push_manifest(
        registry: *const c_char,
        repository: *const c_char,
        reference: *const c_char,
        media_type: *const c_char,
        username: *const c_char,
        password: *const c_char,
        data: *const c_char,
        data_len: c_int,
    ) -> *mut c_char;
}

// ── Safe wrappers ─────────────────────────────────────────────────────────────
//
// These thin safe wrappers handle CString conversion and memory ownership so
// the rest of the Rust code never has to touch raw pointers.

use std::ffi::CString;

use bytes::Bytes;

use crate::error::{Error, Result};

/// Helper: convert a Rust `&str` to a nul-terminated `CString`, returning an
/// `Error` if the string contains an interior nul byte (which would be invalid
/// in a C string).
fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| CString::new("<invalid>").unwrap())
}

/// Helper: read a raw pointer returned by a `dcopy_*` function, detect the
/// `"ERROR:…"` sentinel, and free the pointer via `dcopy_free`.
///
/// Contract from Go side:
///   - On error  : `len = -1`,  returned buffer is a null-terminated error
///                 string starting with `"ERROR:"`.
///   - On success: `len >= 0`, returned buffer is exactly `len` bytes of
///                 arbitrary (possibly binary) data.
///
/// # Safety
/// `ptr` must have been returned by a `dcopy_*` call and not yet freed.
unsafe fn take_result(ptr: *mut c_char, len: c_int) -> Result<Bytes> {
    if ptr.is_null() {
        return if len == 0 {
            Ok(Bytes::new())
        } else {
            Err(Error::Other("dcopy_* returned null".to_string()))
        };
    }

    if len < 0 {
        // Error path: read as null-terminated C string (len == -1 is a sentinel,
        // not the actual length of the error message).
        let msg = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { dcopy_free(ptr as *mut c_void) };
        let stripped = msg.strip_prefix("ERROR:").unwrap_or(&msg).to_string();
        return Err(Error::Other(stripped));
    }

    // Success path: copy exactly `len` bytes then free.
    let bytes = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec()
    };
    unsafe { dcopy_free(ptr as *mut c_void) };
    Ok(Bytes::from(bytes))
}

// ── Public safe API ───────────────────────────────────────────────────────────

pub fn go_list_tags(registry: &str, repository: &str, username: &str, password: &str) -> Result<Vec<String>> {
    let mut len: c_int = 0;
    let ptr = unsafe {
        dcopy_list_tags(
            cstr(registry).as_ptr(),
            cstr(repository).as_ptr(),
            cstr(username).as_ptr(),
            cstr(password).as_ptr(),
            &mut len,
        )
    };
    let bytes = unsafe { take_result(ptr, len) }?;
    serde_json::from_slice(&bytes).map_err(Error::Json)
}

pub struct ManifestResult {
    pub data: Bytes,
    pub content_type: String,
    pub digest: String,
}

pub fn go_fetch_manifest(
    registry: &str,
    repository: &str,
    reference: &str,
    username: &str,
    password: &str,
) -> Result<ManifestResult> {
    let mut len: c_int = 0;
    let mut ct_ptr: *mut c_char = std::ptr::null_mut();
    let mut dg_ptr: *mut c_char = std::ptr::null_mut();

    let ptr = unsafe {
        dcopy_fetch_manifest(
            cstr(registry).as_ptr(),
            cstr(repository).as_ptr(),
            cstr(reference).as_ptr(),
            cstr(username).as_ptr(),
            cstr(password).as_ptr(),
            &mut len,
            &mut ct_ptr,
            &mut dg_ptr,
        )
    };

    // Read auxiliary strings before consuming `ptr`
    let content_type = if ct_ptr.is_null() {
        String::new()
    } else {
        let s = unsafe { std::ffi::CStr::from_ptr(ct_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { dcopy_free(ct_ptr as *mut c_void) };
        s
    };
    let digest = if dg_ptr.is_null() {
        String::new()
    } else {
        let s = unsafe { std::ffi::CStr::from_ptr(dg_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { dcopy_free(dg_ptr as *mut c_void) };
        s
    };

    let data = unsafe { take_result(ptr, len) }?;
    Ok(ManifestResult { data, content_type, digest })
}

pub fn go_fetch_blob(
    registry: &str,
    repository: &str,
    digest: &str,
    media_type: &str,
    username: &str,
    password: &str,
) -> Result<Bytes> {
    let mut len: c_int = 0;
    let ptr = unsafe {
        dcopy_fetch_blob(
            cstr(registry).as_ptr(),
            cstr(repository).as_ptr(),
            cstr(digest).as_ptr(),
            cstr(media_type).as_ptr(),
            cstr(username).as_ptr(),
            cstr(password).as_ptr(),
            &mut len,
        )
    };
    unsafe { take_result(ptr, len) }
}

pub fn go_blob_exists(
    registry: &str,
    repository: &str,
    digest: &str,
    username: &str,
    password: &str,
) -> Result<bool> {
    let mut err_ptr: *mut c_char = std::ptr::null_mut();
    let rc = unsafe {
        dcopy_blob_exists(
            cstr(registry).as_ptr(),
            cstr(repository).as_ptr(),
            cstr(digest).as_ptr(),
            cstr(username).as_ptr(),
            cstr(password).as_ptr(),
            &mut err_ptr,
        )
    };
    if rc == -1 {
        let msg = if err_ptr.is_null() {
            "unknown blob_exists error".to_string()
        } else {
            let s = unsafe { std::ffi::CStr::from_ptr(err_ptr) }
                .to_string_lossy()
                .into_owned();
            unsafe { dcopy_free(err_ptr as *mut c_void) };
            s
        };
        return Err(Error::Other(msg));
    }
    Ok(rc == 1)
}

pub fn go_push_blob(
    registry: &str,
    repository: &str,
    digest: &str,
    media_type: &str,
    username: &str,
    password: &str,
    data: &[u8],
) -> Result<()> {
    let err_ptr = unsafe {
        dcopy_push_blob(
            cstr(registry).as_ptr(),
            cstr(repository).as_ptr(),
            cstr(digest).as_ptr(),
            cstr(media_type).as_ptr(),
            cstr(username).as_ptr(),
            cstr(password).as_ptr(),
            data.as_ptr() as *const c_char,
            data.len() as c_int,
        )
    };
    if err_ptr.is_null() {
        return Ok(());
    }
    let msg = unsafe { std::ffi::CStr::from_ptr(err_ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { dcopy_free(err_ptr as *mut c_void) };
    Err(Error::Other(msg))
}

pub fn go_push_manifest(
    registry: &str,
    repository: &str,
    reference: &str,
    media_type: &str,
    username: &str,
    password: &str,
    data: &[u8],
) -> Result<()> {
    let err_ptr = unsafe {
        dcopy_push_manifest(
            cstr(registry).as_ptr(),
            cstr(repository).as_ptr(),
            cstr(reference).as_ptr(),
            cstr(media_type).as_ptr(),
            cstr(username).as_ptr(),
            cstr(password).as_ptr(),
            data.as_ptr() as *const c_char,
            data.len() as c_int,
        )
    };
    if err_ptr.is_null() {
        return Ok(());
    }
    let msg = unsafe { std::ffi::CStr::from_ptr(err_ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { dcopy_free(err_ptr as *mut c_void) };
    Err(Error::Other(msg))
}
