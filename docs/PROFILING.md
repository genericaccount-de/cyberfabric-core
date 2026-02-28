# CPU Profiling

On-demand CPU profiling for incident analysis in production and pre-production environments.

## Overview

HyperSpot embeds a [pprof-rs](https://github.com/tikv/pprof-rs)-based CPU profiler
that exposes pprof-compatible endpoints on a **separate internal HTTP server**.
Profiles can be collected without restarting the process and analyzed with standard
tools (`go tool pprof`, Grafana Pyroscope, speedscope, etc.).

## Prerequisites

The binary must be compiled with the `profiling` Cargo feature:

```bash
cargo build --release --features profiling
```

Without this feature, profiling code is not compiled into the binary at all.

## Configuration

Profiling is configured under the `tracing.profiling` section in YAML:

```yaml
tracing:
  profiling:
    enabled: true
    address: "127.0.0.1"   # Bind address (default: 127.0.0.1)
    port: 6060              # Bind port (default: 6060)
    auth_token: "${PROFILING_TOKEN}"  # Optional bearer token
```

### Environment variable overrides

All fields can be overridden via environment variables:

| Field | Env var | Example |
|-------|---------|---------|
| `enabled` | `APP__TRACING__PROFILING__ENABLED` | `true` |
| `address` | `APP__TRACING__PROFILING__ADDRESS` | `0.0.0.0` |
| `port` | `APP__TRACING__PROFILING__PORT` | `6060` |
| `auth_token` | `APP__TRACING__PROFILING__AUTH_TOKEN` | `my-secret` |

The `auth_token` field also supports `${ENV_VAR}` expansion syntax (like database passwords).

### Defaults

| Field | Default |
|-------|---------|
| `enabled` | `false` |
| `address` | `127.0.0.1` |
| `port` | `6060` |
| `auth_token` | none (no auth) |

## Endpoints

| Endpoint | Content-Type | Description |
|----------|-------------|-------------|
| `GET /debug/pprof/profile` | `application/octet-stream` | CPU profile in pprof protobuf format |
| `GET /debug/pprof/flamegraph` | `image/svg+xml` | CPU profile as interactive flamegraph SVG |

### Query parameters

| Param | Default | Max | Description |
|-------|---------|-----|-------------|
| `seconds` | 30 | 300 | Profiling duration in seconds |
| `frequency` | 99 | 999 | Sampling frequency in Hz |

## Collecting profiles

### pprof protobuf (for `go tool pprof` / Grafana)

```bash
# Collect a 30-second CPU profile
curl -o profile.pb http://127.0.0.1:6060/debug/pprof/profile?seconds=30

# With authentication
curl -H "Authorization: Bearer $PROFILING_TOKEN" \
     -o profile.pb http://127.0.0.1:6060/debug/pprof/profile?seconds=30

# Analyze with go tool pprof
go tool pprof -http=:8080 profile.pb
```

### Flamegraph SVG

```bash
# Collect and open in browser
curl -o flamegraph.svg http://127.0.0.1:6060/debug/pprof/flamegraph?seconds=30
open flamegraph.svg  # macOS
```

### In Kubernetes

```bash
# Port-forward the profiling port
kubectl port-forward pod/hyperspot-abc123 6060:6060

# Then collect from localhost
curl -o profile.pb http://127.0.0.1:6060/debug/pprof/profile?seconds=30
```

## Security

### Network isolation

By default the profiling server binds to `127.0.0.1` (localhost only), which means
it is **not accessible from outside the container/host**. Use `kubectl port-forward`
or SSH tunnels to access it remotely.

If you must bind to `0.0.0.0` (e.g., for sidecar access), protect the port with a
Kubernetes `NetworkPolicy`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-profiling-external
spec:
  podSelector:
    matchLabels:
      app: hyperspot
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: sre-tools
      ports:
        - port: 6060
```

### Authentication

Set `auth_token` to require a `Authorization: Bearer <token>` header on all
profiling requests. The token value supports `${ENV_VAR}` expansion so you
can inject it from a Kubernetes secret.

## Limitations

- **CPU profiling only** — heap/memory profiling is not available because the
  project uses `mimalloc` (heap profiling requires `jemalloc` with `prof` support).
- **Linux-optimized** — signal-based sampling (`perf_event_open` / `SIGPROF`) works
  best on Linux. On macOS the profiler compiles and runs but produces lower-fidelity
  results. A warning is logged on non-Linux platforms.
- **Single profile at a time** — concurrent profile requests will run overlapping
  profiler guards; for best results, collect one profile at a time.
