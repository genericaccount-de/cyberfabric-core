//! Builds a pprof `profile.proto` from aggregated stack trace data.
//!
//! This module is used by the Windows sampler backend to produce output
//! compatible with `go tool pprof` and other pprof-based tooling.

use std::collections::HashMap;

/// A collected stack sample: instruction pointer addresses (top-of-stack first)
/// mapped to the number of times this exact stack was observed.
pub(super) type StackSamples = HashMap<Vec<usize>, u64>;

/// Encode aggregated stack samples into the pprof protobuf wire format.
///
/// The output is a raw (uncompressed) `perftools.profiles.Profile` message
/// encoded via `prost`.  The caller is responsible for gzip-compressing
/// if needed.
pub(super) fn encode_pprof(
    samples: &StackSamples,
    duration_nanos: u64,
    frequency_hz: u32,
) -> anyhow::Result<Vec<u8>> {
    // String table: index 0 is always the empty string.
    let mut string_table: Vec<String> = vec![String::new()];
    let mut string_index: HashMap<String, i64> = HashMap::new();
    string_index.insert(String::new(), 0);

    let mut intern = |s: &str| -> i64 {
        if let Some(&idx) = string_index.get(s) {
            return idx;
        }
        let idx = i64::try_from(string_table.len()).unwrap_or(0);
        string_table.push(s.to_owned());
        string_index.insert(s.to_owned(), idx);
        idx
    };

    let sample_type_name = intern("samples");
    let sample_type_unit = intern("count");
    let cpu_type_name = intern("cpu");
    let cpu_type_unit = intern("nanoseconds");

    // Build locations and functions.
    let mut locations: Vec<Location> = Vec::new();
    let mut functions: Vec<Function> = Vec::new();
    let mut location_index: HashMap<usize, u64> = HashMap::new();
    let mut function_id_counter: u64 = 1;
    let mut location_id_counter: u64 = 1;

    for addrs in samples.keys() {
        for &addr in addrs {
            if location_index.contains_key(&addr) {
                continue;
            }

            let loc_id = location_id_counter;
            location_id_counter += 1;
            location_index.insert(addr, loc_id);

            // Resolve symbol name.
            let mut func_name = format!("0x{addr:x}");
            let mut file_name = String::new();
            let mut line_no: i64 = 0;

            backtrace::resolve(addr as *mut std::ffi::c_void, |symbol| {
                if let Some(name) = symbol.name() {
                    func_name = name.to_string();
                }
                if let Some(f) = symbol.filename() {
                    file_name = f.display().to_string();
                }
                if let Some(l) = symbol.lineno() {
                    line_no = i64::from(l);
                }
            });

            let fn_name_idx = intern(&func_name);
            let file_name_idx = intern(&file_name);

            let func_id = function_id_counter;
            function_id_counter += 1;

            functions.push(Function {
                id: func_id,
                name: fn_name_idx,
                system_name: fn_name_idx,
                filename: file_name_idx,
                start_line: 0,
            });

            locations.push(Location {
                id: loc_id,
                address: addr.try_into().unwrap_or(0),
                line: vec![Line {
                    function_id: func_id,
                    line: line_no,
                }],
            });
        }
    }

    // Build samples.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let period_ns = if frequency_hz > 0 {
        (1_000_000_000_f64 / f64::from(frequency_hz)).round() as u64
    } else {
        10_000_000
    };

    let mut proto_samples: Vec<Sample> = Vec::with_capacity(samples.len());
    for (addrs, &count) in samples {
        let location_ids: Vec<u64> = addrs
            .iter()
            .filter_map(|a| location_index.get(a).copied())
            .collect();

        let cpu_nanos = i64::try_from(count.saturating_mul(period_ns)).unwrap_or(i64::MAX);

        proto_samples.push(Sample {
            location_id: location_ids,
            value: vec![i64::try_from(count).unwrap_or(i64::MAX), cpu_nanos],
            label: Vec::new(),
        });
    }

    let period_type_name = intern("cpu");
    let period_type_unit = intern("nanoseconds");

    let profile = Profile {
        sample_type: vec![
            ValueType {
                r#type: sample_type_name,
                unit: sample_type_unit,
            },
            ValueType {
                r#type: cpu_type_name,
                unit: cpu_type_unit,
            },
        ],
        sample: proto_samples,
        location: locations,
        function: functions,
        string_table,
        drop_frames: 0,
        keep_frames: 0,
        time_nanos: 0,
        duration_nanos: i64::try_from(duration_nanos).unwrap_or(i64::MAX),
        period_type: Some(ValueType {
            r#type: period_type_name,
            unit: period_type_unit,
        }),
        period: i64::try_from(period_ns).unwrap_or(0),
        comment: Vec::new(),
        default_sample_type: 0,
    };

    let mut buf = Vec::new();
    prost::Message::encode(&profile, &mut buf)
        .map_err(|e| anyhow::anyhow!("protobuf encoding failed: {e}"))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Minimal pprof protobuf message types (hand-rolled for prost::Message).
//
// These mirror `perftools.profiles.Profile` from
// <https://github.com/google/pprof/blob/main/proto/profile.proto>.
// We define them here to avoid depending on a full proto compilation step.
// ---------------------------------------------------------------------------

#[derive(Clone, prost::Message)]
struct Profile {
    #[prost(message, repeated, tag = "1")]
    sample_type: Vec<ValueType>,
    #[prost(message, repeated, tag = "2")]
    sample: Vec<Sample>,
    // mapping omitted (tag 3)
    #[prost(message, repeated, tag = "4")]
    location: Vec<Location>,
    #[prost(message, repeated, tag = "5")]
    function: Vec<Function>,
    #[prost(string, repeated, tag = "6")]
    string_table: Vec<String>,
    #[prost(int64, tag = "7")]
    drop_frames: i64,
    #[prost(int64, tag = "8")]
    keep_frames: i64,
    #[prost(int64, tag = "9")]
    time_nanos: i64,
    #[prost(int64, tag = "10")]
    duration_nanos: i64,
    #[prost(message, optional, tag = "11")]
    period_type: Option<ValueType>,
    #[prost(int64, tag = "12")]
    period: i64,
    #[prost(int64, repeated, tag = "13")]
    comment: Vec<i64>,
    #[prost(int64, tag = "14")]
    default_sample_type: i64,
}

#[derive(Clone, prost::Message)]
struct ValueType {
    #[prost(int64, tag = "1")]
    r#type: i64,
    #[prost(int64, tag = "2")]
    unit: i64,
}

#[derive(Clone, prost::Message)]
struct Sample {
    #[prost(uint64, repeated, tag = "1")]
    location_id: Vec<u64>,
    #[prost(int64, repeated, tag = "2")]
    value: Vec<i64>,
    #[prost(message, repeated, tag = "3")]
    label: Vec<Label>,
}

#[derive(Clone, prost::Message)]
struct Label {
    #[prost(int64, tag = "1")]
    key: i64,
    #[prost(int64, tag = "2")]
    str: i64,
    #[prost(int64, tag = "3")]
    num: i64,
    #[prost(int64, tag = "4")]
    num_unit: i64,
}

#[derive(Clone, prost::Message)]
struct Location {
    #[prost(uint64, tag = "1")]
    id: u64,
    // mapping_id omitted (tag 2)
    #[prost(uint64, tag = "3")]
    address: u64,
    #[prost(message, repeated, tag = "4")]
    line: Vec<Line>,
}

#[derive(Clone, prost::Message)]
struct Line {
    #[prost(uint64, tag = "1")]
    function_id: u64,
    #[prost(int64, tag = "2")]
    line: i64,
}

#[derive(Clone, prost::Message)]
struct Function {
    #[prost(uint64, tag = "1")]
    id: u64,
    #[prost(int64, tag = "2")]
    name: i64,
    #[prost(int64, tag = "3")]
    system_name: i64,
    #[prost(int64, tag = "4")]
    filename: i64,
    #[prost(int64, tag = "5")]
    start_line: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the raw protobuf back into a `Profile` for assertions.
    #[allow(clippy::useless_asref)]
    fn decode_profile(buf: &[u8]) -> Profile {
        <Profile as prost::Message>::decode(buf.as_ref()).expect("valid protobuf")
    }

    #[test]
    fn encode_empty_samples() {
        let samples = StackSamples::new();
        let buf = encode_pprof(&samples, 1_000_000_000, 100).unwrap();
        let profile = decode_profile(&buf);

        assert!(profile.sample.is_empty());
        assert!(profile.location.is_empty());
        assert!(profile.function.is_empty());
        // String table always has at least the empty string at index 0.
        assert!(!profile.string_table.is_empty());
        assert_eq!(profile.string_table[0], "");
    }

    #[test]
    fn encode_single_sample() {
        let mut samples = StackSamples::new();
        samples.insert(vec![0x1000], 42);

        let buf = encode_pprof(&samples, 5_000_000_000, 100).unwrap();
        let profile = decode_profile(&buf);

        assert_eq!(profile.sample.len(), 1);
        assert_eq!(profile.location.len(), 1);
        assert_eq!(profile.function.len(), 1);

        // Two sample types: samples/count and cpu/nanoseconds.
        assert_eq!(profile.sample_type.len(), 2);

        // Value[0] = count, Value[1] = cpu_nanos.
        let sample = &profile.sample[0];
        assert_eq!(sample.value[0], 42);
        // period_ns at 100 Hz = 10_000_000 ns; cpu_nanos = 42 * 10_000_000.
        assert_eq!(sample.value[1], 42 * 10_000_000);

        // Duration and period.
        assert_eq!(profile.duration_nanos, 5_000_000_000);
        assert_eq!(profile.period, 10_000_000);
    }

    #[test]
    fn encode_multiple_samples_and_shared_addresses() {
        let mut samples = StackSamples::new();
        samples.insert(vec![0xA, 0xB], 10);
        samples.insert(vec![0xA, 0xC], 20);

        let buf = encode_pprof(&samples, 2_000_000_000, 50).unwrap();
        let profile = decode_profile(&buf);

        assert_eq!(profile.sample.len(), 2);
        // Three unique addresses: 0xA, 0xB, 0xC.
        assert_eq!(profile.location.len(), 3);
        assert_eq!(profile.function.len(), 3);

        // Each sample should reference exactly 2 locations.
        for s in &profile.sample {
            assert_eq!(s.location_id.len(), 2);
        }
    }

    #[test]
    fn zero_frequency_uses_default_period() {
        let mut samples = StackSamples::new();
        samples.insert(vec![0x1], 1);

        let buf = encode_pprof(&samples, 1_000_000_000, 0).unwrap();
        let profile = decode_profile(&buf);

        // Default period when frequency_hz == 0 is 10_000_000 ns (100 Hz equivalent).
        assert_eq!(profile.period, 10_000_000);
    }

    #[test]
    fn period_precision_with_non_divisible_frequency() {
        let mut samples = StackSamples::new();
        samples.insert(vec![0x1], 1);

        // 7 Hz → 1_000_000_000 / 7 = 142_857_142.857..., rounded to 142_857_143.
        let buf = encode_pprof(&samples, 1_000_000_000, 7).unwrap();
        let profile = decode_profile(&buf);
        assert_eq!(profile.period, 142_857_143);

        // 3 Hz → 1_000_000_000 / 3 = 333_333_333.333..., rounded to 333_333_333.
        let buf = encode_pprof(&samples, 1_000_000_000, 3).unwrap();
        let profile = decode_profile(&buf);
        assert_eq!(profile.period, 333_333_333);
    }

    #[test]
    fn string_table_contains_required_entries() {
        let mut samples = StackSamples::new();
        samples.insert(vec![0x1], 1);

        let buf = encode_pprof(&samples, 1_000_000_000, 100).unwrap();
        let profile = decode_profile(&buf);

        // Must contain: "", "samples", "count", "cpu", "nanoseconds", and at
        // least one function name (hex fallback or resolved symbol).
        assert!(profile.string_table.contains(&String::new()));
        assert!(profile.string_table.contains(&"samples".to_owned()));
        assert!(profile.string_table.contains(&"count".to_owned()));
        assert!(profile.string_table.contains(&"cpu".to_owned()));
        assert!(profile.string_table.contains(&"nanoseconds".to_owned()));
    }

    #[test]
    fn location_ids_are_unique_and_nonzero() {
        let mut samples = StackSamples::new();
        samples.insert(vec![0xA, 0xB, 0xC], 5);

        let buf = encode_pprof(&samples, 1_000_000_000, 100).unwrap();
        let profile = decode_profile(&buf);

        let ids: Vec<u64> = profile.location.iter().map(|l| l.id).collect();
        assert!(ids.iter().all(|&id| id > 0));

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "location IDs must be unique");
    }

    #[test]
    fn function_ids_are_unique_and_nonzero() {
        let mut samples = StackSamples::new();
        samples.insert(vec![0xA, 0xB], 1);

        let buf = encode_pprof(&samples, 1_000_000_000, 100).unwrap();
        let profile = decode_profile(&buf);

        let ids: Vec<u64> = profile.function.iter().map(|f| f.id).collect();
        assert!(ids.iter().all(|&id| id > 0));

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "function IDs must be unique");
    }
}
