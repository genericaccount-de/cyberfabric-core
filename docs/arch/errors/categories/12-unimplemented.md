# 12 Unimplemented

**Category**: `unimplemented`
**GTS ID**: `gts.cf.core.errors.err.v1~cf.core.err.unimplemented.v1~`
**HTTP Status**: 501
**Title**: "Unimplemented"
**Context Type**: `Unimplemented`
**Use When**: The requested operation is recognized but not implemented (e.g., a planned feature, an unsupported protocol variant).
**Similar Categories**: `internal` — bug vs intentionally unimplemented
**Default Message**: "This operation is not implemented"

## Context Schema

| Field | Type | Description |
|-------|------|-------------|
| `resource_type` | `String` | GTS type identifier of the associated resource |
| `resource_name` | `String` | Identifier of the associated resource |
| `reason` | `String` | Machine-readable reason code (e.g., `GRPC_ROUTING`) |
| `domain` | `String` | Logical grouping (e.g., `"cf.oagw"`) |
| `extra` | `Option<Object>` | Reserved for derived GTS type extensions (p3+); absent in p1 |

## Constructor Example

```rust
use cf_modkit_errors::{CanonicalError, Unimplemented};

let err = CanonicalError::unimplemented(
    Unimplemented::new("GRPC_ROUTING", "cf.oagw")
);
```

## JSON Wire — JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "gts://gts.cf.core.errors.err.v1~cf.core.err.unimplemented.v1~",
  "type": "object",
  "allOf": [
    { "$ref": "gts://gts.cf.core.errors.err.v1~" },
    {
      "properties": {
        "type": {
          "const": "gts://gts.cf.core.errors.err.v1~cf.core.err.unimplemented.v1~"
        },
        "title": { "const": "Unimplemented" },
        "status": { "const": 501 },
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
              "description": "Machine-readable reason code (e.g., GRPC_ROUTING)"
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
  "type": "gts://gts.cf.core.errors.err.v1~cf.core.err.unimplemented.v1~",
  "title": "Unimplemented",
  "status": 501,
  "detail": "This operation is not implemented",
  "context": {
    "resource_type": "gts.cf.oagw.upstreams.upstream.v1~",
    "resource_name": "upstream-123",
    "reason": "GRPC_ROUTING",
    "domain": "cf.oagw"
  }
}
```
