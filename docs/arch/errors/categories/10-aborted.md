# 10 Aborted

**Category**: `aborted`
**GTS ID**: `gts.cf.core.errors.err.v1~cf.core.err.aborted.v1~`
**HTTP Status**: 409
**Title**: "Aborted"
**Context Type**: `Aborted`
**Use When**: The operation was aborted due to a concurrency conflict (optimistic locking failure, transaction conflict). The client can retry.
**Similar Categories**: `already_exists` — duplicate on create vs conflict on update
**Default Message**: "Operation aborted due to concurrency conflict"

## Context Schema

| Field | Type | Description |
|-------|------|-------------|
| `resource_type` | `String` | GTS type identifier of the associated resource |
| `resource_name` | `String` | Identifier of the associated resource |
| `reason` | `String` | Machine-readable reason code (e.g., `OPTIMISTIC_LOCK_FAILURE`) |
| `domain` | `String` | Logical grouping (e.g., `"cf.oagw"`) |
| `extra` | `Option<Object>` | Reserved for derived GTS type extensions (p3+); absent in p1 |

## Rust Definitions and Constructor Example

```rust
use cf_modkit_errors::{CanonicalError, Aborted};
use std::collections::HashMap;

let err = CanonicalError::aborted(
    Aborted::new("OPTIMISTIC_LOCK_FAILURE", "cf.oagw")
);
```

## JSON Wire — JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "gts://gts.cf.core.errors.err.v1~cf.core.err.aborted.v1~",
  "type": "object",
  "allOf": [
    { "$ref": "gts://gts.cf.core.errors.err.v1~" },
    {
      "properties": {
        "type": {
          "const": "gts://gts.cf.core.errors.err.v1~cf.core.err.aborted.v1~"
        },
        "title": { "const": "Aborted" },
        "status": { "const": 409 },
        "context": {
          "type": "object",
          "required": ["reason", "domain"],
          "properties": {
            "resource_type": {
              "type": "string",
              "description": "GTS type identifier of the associated resource (injected when resource_type is set)"
            },
            "resource_name": {
              "type": "string",
              "description": "Identifier of the associated resource (injected when resource_name is set)"
            },
            "reason": {
              "type": "string",
              "description": "Machine-readable reason code (e.g., OPTIMISTIC_LOCK_FAILURE)"
            },
            "domain": {
              "type": "string",
              "description": "Logical grouping (e.g., cf.oagw)"
            },
            "extra": {
              "type": ["object", "null"],
              "description": "Reserved for derived GTS type extensions (p3+); absent in p1"
            }
          },
          "additionalProperties": false
        }
      }
    }
  ]
}
```

## JSON Wire — JSON Example

```json
{
  "type": "gts://gts.cf.core.errors.err.v1~cf.core.err.aborted.v1~",
  "title": "Aborted",
  "status": 409,
  "detail": "Operation aborted due to concurrency conflict",
  "context": {
    "resource_type": "gts.cf.oagw.upstreams.upstream.v1~",
    "resource_name": "upstream-123",
    "reason": "OPTIMISTIC_LOCK_FAILURE",
    "domain": "cf.oagw"
  }
}
```
