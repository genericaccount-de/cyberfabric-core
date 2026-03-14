//! Unix CPU profiler backend using `pprof-rs` (signal-based sampling).
//!
//! Flamegraph SVG is generated directly by `pprof-rs`.  Protobuf output uses
//! the shared [`pprof_proto`] encoder to avoid a `prost` version conflict
//! (`pprof 0.15` depends on `prost 0.12`; the workspace uses `prost 0.14`).

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
            tracing::error!(error = %e, "CPU profile capture failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("profiling error: {e}"),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "CPU profile task panicked");
            (StatusCode::INTERNAL_SERVER_ERROR, "profiling task panicked").into_response()
        }
    }
}

fn capture_blocking(
    seconds: u64,
    frequency: u32,
    format: ProfOutputFormat,
) -> anyhow::Result<Response> {
    let frequency_i32 = i32::try_from(frequency).unwrap_or(100);

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(frequency_i32)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .map_err(|e| anyhow::anyhow!("failed to start profiler: {e}"))?;

    std::thread::sleep(std::time::Duration::from_secs(seconds));

    let report = guard
        .report()
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build report: {e}"))?;

    match format {
        ProfOutputFormat::Flamegraph => {
            let mut svg = Vec::new();
            report
                .flamegraph(&mut svg)
                .map_err(|e| anyhow::anyhow!("flamegraph generation failed: {e}"))?;

            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "image/svg+xml")],
                svg,
            )
                .into_response())
        }
        ProfOutputFormat::Protobuf => {
            let samples = report_to_stack_samples(&report);
            let duration_nanos = seconds * 1_000_000_000;
            let raw = pprof_proto::encode_pprof(&samples, duration_nanos, frequency)?;
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
    }
}

/// Convert a `pprof::Report` into our generic `StackSamples` format.
///
/// Each `Frames` entry has resolved symbol addresses.  We extract the first
/// symbol address from each frame level to build a flat address list.
fn report_to_stack_samples(report: &pprof::Report) -> HashMap<Vec<usize>, u64> {
    let mut samples: HashMap<Vec<usize>, u64> = HashMap::new();

    for (frames, count) in &report.data {
        let addrs: Vec<usize> = frames
            .frames
            .iter()
            .filter_map(|syms| syms.first().and_then(|s| s.addr.map(|p| p as usize)))
            .collect();

        if !addrs.is_empty() {
            let count_u64 = u64::try_from(*count).unwrap_or(0);
            *samples.entry(addrs).or_insert(0) += count_u64;
        }
    }

    samples
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
