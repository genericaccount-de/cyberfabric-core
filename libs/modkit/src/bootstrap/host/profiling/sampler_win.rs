//! Windows CPU profiler backend using `SuspendThread` / `GetThreadContext` /
//! `ResumeThread` — the same approach used by Go's runtime (`os_windows.go:profileLoop`).
//!
//! A dedicated high-priority sampler thread periodically suspends every other
//! thread in the process, captures the instruction pointer from its context,
//! resolves symbols via `backtrace::resolve`, and aggregates the results into
//! pprof-compatible protobuf output.

use std::collections::HashMap;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::pprof_proto;
use super::server::ProfOutputFormat;

/// Capture a CPU profile for `seconds` at the given `frequency` Hz.
pub(super) async fn capture(seconds: u64, frequency: u32, format: ProfOutputFormat) -> Response {
    let result =
        tokio::task::spawn_blocking(move || capture_blocking(seconds, frequency, format)).await;

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Windows CPU profile capture failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("profiling error: {e}"),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Windows CPU profile task panicked");
            (StatusCode::INTERNAL_SERVER_ERROR, "profiling task panicked").into_response()
        }
    }
}

fn capture_blocking(
    seconds: u64,
    frequency: u32,
    format: ProfOutputFormat,
) -> anyhow::Result<Response> {
    let freq = if frequency == 0 { 100 } else { frequency };

    let samples = ffi::sample_threads(seconds, freq);

    let duration_nanos = seconds * 1_000_000_000;

    match format {
        ProfOutputFormat::Protobuf => {
            let raw = pprof_proto::encode_pprof(&samples, duration_nanos, freq)?;
            let compressed = gzip_compress(&raw)?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CONTENT_ENCODING, "gzip"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"profile.pb.gz\"",
                    ),
                ],
                compressed,
            )
                .into_response())
        }
        ProfOutputFormat::Flamegraph => {
            let folded = build_folded_stacks(&samples);
            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!(
                    "# Folded stack format (pipe through `inferno-flamegraph` to produce SVG)\n\
                     # Install: cargo install inferno\n\
                     # Usage:   curl ... | inferno-flamegraph > flame.svg\n\n\
                     {folded}"
                ),
            )
                .into_response())
        }
    }
}

/// Build folded-stack text (compatible with `inferno-flamegraph`).
fn build_folded_stacks(samples: &HashMap<Vec<usize>, u64>) -> String {
    let mut lines = Vec::with_capacity(samples.len());
    for (addrs, &count) in samples {
        let names: Vec<String> = addrs
            .iter()
            .rev()
            .map(|&addr| resolve_symbol(addr))
            .collect();
        lines.push(format!("{} {count}", names.join(";")));
    }
    lines.sort();
    lines.join("\n")
}

fn resolve_symbol(addr: usize) -> String {
    let mut name = format!("0x{addr:x}");
    backtrace::resolve(addr as *mut std::ffi::c_void, |symbol| {
        if let Some(n) = symbol.name() {
            name = n.to_string();
        }
    });
    name
}

fn gzip_compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| anyhow::anyhow!("gzip write failed: {e}"))?;
    encoder
        .finish()
        .map_err(|e| anyhow::anyhow!("gzip finish failed: {e}"))
}

// ---------------------------------------------------------------------------
// Win32 FFI — all `unsafe` code is confined to this inner module.
// ---------------------------------------------------------------------------

#[allow(unsafe_code)]
mod ffi {
    use std::collections::HashMap;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT, CONTEXT_CONTROL, GetThreadContext,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
        THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    /// Sample all threads in the current process for `seconds` at `frequency_hz`.
    pub(super) fn sample_threads(seconds: u64, frequency_hz: u32) -> HashMap<Vec<usize>, u64> {
        let freq = if frequency_hz == 0 { 100 } else { frequency_hz };
        let interval = std::time::Duration::from_nanos(1_000_000_000 / u64::from(freq));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);

        let my_tid = unsafe { GetCurrentThreadId() };
        let my_pid = unsafe { GetCurrentProcessId() };

        // Elevate sampler thread priority for timing accuracy (non-fatal on failure).
        unsafe {
            windows_sys::Win32::System::Threading::SetThreadPriority(
                windows_sys::Win32::System::Threading::GetCurrentThread(),
                windows_sys::Win32::System::Threading::THREAD_PRIORITY_HIGHEST,
            );
        }

        let mut samples: HashMap<Vec<usize>, u64> = HashMap::new();

        while std::time::Instant::now() < deadline {
            sample_all_threads(my_pid, my_tid, &mut samples);
            std::thread::sleep(interval);
        }

        samples
    }

    fn sample_all_threads(pid: u32, self_tid: u32, samples: &mut HashMap<Vec<usize>, u64>) {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };

        if unsafe { Thread32First(snapshot, &mut entry) } == 0 {
            unsafe { CloseHandle(snapshot) };
            return;
        }

        loop {
            if entry.th32OwnerProcessID == pid && entry.th32ThreadID != self_tid {
                sample_thread(entry.th32ThreadID, samples);
            }

            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                break;
            }
        }

        unsafe { CloseHandle(snapshot) };
    }

    fn sample_thread(tid: u32, samples: &mut HashMap<Vec<usize>, u64>) {
        let handle: HANDLE =
            unsafe { OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, 0, tid) };
        if handle == 0 {
            return;
        }

        // SuspendThread returns previous suspend count, or u32::MAX on error.
        if unsafe { SuspendThread(handle) } == u32::MAX {
            unsafe { CloseHandle(handle) };
            return;
        }

        // CONTEXT must be 16-byte aligned on x86-64.
        #[repr(align(16))]
        struct AlignedContext {
            ctx: CONTEXT,
        }

        let mut aligned = AlignedContext {
            ctx: unsafe { std::mem::zeroed() },
        };
        aligned.ctx.ContextFlags = CONTEXT_CONTROL;

        let got_ctx = unsafe { GetThreadContext(handle, &mut aligned.ctx) };

        // Always resume, even if GetThreadContext failed.
        unsafe { ResumeThread(handle) };
        unsafe { CloseHandle(handle) };

        if got_ctx == 0 {
            return;
        }

        // Extract instruction pointer (architecture-specific).
        #[cfg(target_arch = "x86_64")]
        let ip = aligned.ctx.Rip as usize;

        #[cfg(target_arch = "x86")]
        let ip = aligned.ctx.Eip as usize;

        #[cfg(target_arch = "aarch64")]
        let ip = aligned.ctx.Pc as usize;

        if ip != 0 {
            *samples.entry(vec![ip]).or_insert(0) += 1;
        }
    }
}
