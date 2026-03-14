# On-Demand Profiling Endpoint

The profiling feature adds a **separate HTTP server** exposing pprof-compatible
CPU and memory profiling endpoints.  It is designed for incident analysis in
production and pre-production environments.

## Quick start

### 1. Build with the `profiling` feature

```bash
cargo build --release --features profiling
```

### 2. Enable in configuration

Add a `profiling` section to your YAML config (or use environment variables):

```yaml
profiling:
  enabled: true
  bind_addr: "127.0.0.1:6060"
  cpu_sample_duration_secs: 30
  cpu_sample_frequency_hz: 100
  # auth_token: "my-secret-token"   # optional
```

Or via environment:

```bash
export APP__PROFILING__ENABLED=true
export APP__PROFILING__BIND_ADDR="127.0.0.1:6060"
# export APP__PROFILING__AUTH_TOKEN="my-secret-token"
```

### 3. Collect a profile

```bash
# CPU profile (pprof protobuf, 30 seconds)
curl -o profile.pb.gz "http://127.0.0.1:6060/debug/pprof/profile?seconds=30"

# CPU flamegraph (SVG on Unix, folded stacks on Windows)
curl -o flame.svg "http://127.0.0.1:6060/debug/pprof/profile?seconds=10&format=flamegraph"

# Heap / process memory stats
curl "http://127.0.0.1:6060/debug/pprof/heap"

# With auth token
curl -H "Authorization: Bearer my-secret-token" \
     -o profile.pb.gz "http://127.0.0.1:6060/debug/pprof/profile?seconds=30"
```

### 4. Visualize

```bash
# Interactive web UI (requires Go toolchain)
go tool pprof -http=:8080 profile.pb.gz

# CLI top functions
go tool pprof -top profile.pb.gz

# Windows folded stacks → flamegraph (requires inferno)
cargo install inferno
curl "http://127.0.0.1:6060/debug/pprof/profile?seconds=10&format=flamegraph" \
  | inferno-flamegraph > flame.svg
```

---

## Endpoints

| Method | Path                        | Description                              |
|--------|-----------------------------|------------------------------------------|
| GET    | `/debug/pprof/`             | Index — lists available profiles         |
| GET    | `/debug/pprof/profile`      | CPU profile (pprof protobuf or SVG)      |
| GET    | `/debug/pprof/heap`         | Heap / process memory statistics (JSON)  |

### Query parameters for `/debug/pprof/profile`

| Param     | Default    | Description                                          |
|-----------|------------|------------------------------------------------------|
| `seconds` | 30         | Profile duration (clamped to `cpu_sample_duration_secs`) |
| `format`  | `protobuf` | Output format: `protobuf` or `flamegraph`            |

---

## Configuration reference

| Field                       | Type     | Default            | Description                                    |
|-----------------------------|----------|--------------------|------------------------------------------------|
| `enabled`                   | bool     | `false`            | Enable the profiling endpoint                  |
| `bind_addr`                 | string   | `127.0.0.1:6060`   | Socket address for the profiling server        |
| `cpu_sample_duration_secs`  | u64      | `30`               | Maximum allowed CPU profile duration           |
| `cpu_sample_frequency_hz`   | u32      | `100`              | Sampling frequency (samples per second)        |
| `auth_token`                | string?  | `null`             | Optional bearer token for authentication       |

---

## Platform support

| Platform       | CPU profiling backend                                       |
|----------------|-------------------------------------------------------------|
| Linux / macOS  | `pprof-rs` — signal-based sampling via `SIGPROF`            |
| Windows        | Custom sampler thread — `SuspendThread` / `GetThreadContext` |

Both backends produce **pprof protobuf** output compatible with `go tool pprof`,
Grafana Pyroscope, and other standard pprof tooling.

### Windows notes

- The Windows sampler captures instruction pointers (single-frame samples).
  Full stack walking may be added in a future iteration.
- Flamegraph output on Windows returns folded-stack text format; pipe through
  `inferno-flamegraph` to produce SVG.
- Symbol resolution requires debug info.  Release builds with `debug = 1`
  (the workspace default) provide function-level names.

---

## Security

The profiling server is **separate** from the main api-gateway and is:

- **Loopback-only** by default (`127.0.0.1:6060`) — not reachable from outside
  the host.
- **Disabled** by default — must be explicitly enabled in configuration.
- **Optionally authenticated** via a bearer token.

### Kubernetes recommendations

- Do **not** expose the profiling port in Service or Ingress definitions.
- Use `kubectl port-forward` to access the profiling endpoint:
  ```bash
  kubectl port-forward pod/my-pod 6060:6060
  curl -o profile.pb.gz "http://127.0.0.1:6060/debug/pprof/profile?seconds=30"
  ```
- Consider a `NetworkPolicy` restricting egress/ingress on port 6060.

---

## Overhead

Profiling is **on-demand only** — no overhead when idle.  During active
collection:

- **Unix**: `pprof-rs` uses `SIGPROF` at the configured frequency.  At 100 Hz
  the overhead is typically < 1 % CPU.
- **Windows**: The sampler thread briefly suspends each thread per sample.  At
  100 Hz with a small number of threads, overhead is negligible.

---

## Cargo feature

The feature is opt-in per binary:

```toml
# apps/hyperspot-server/Cargo.toml
[features]
profiling = ["modkit/profiling"]
```

Build without the feature to completely exclude all profiling code and
dependencies from the binary.
