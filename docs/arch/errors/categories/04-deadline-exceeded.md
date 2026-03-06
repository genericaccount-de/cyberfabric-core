# 04 Deadline Exceeded

**Category**: `deadline_exceeded`
**GTS ID**: `gts.cf.core.errors.err.v1~cf.core.err.deadline_exceeded.v1~`
**HTTP Status**: 504
**Title**: "Deadline Exceeded"
**Context Type**: `DeadlineExceeded`
**Use When**: The server did not complete the operation within the allowed time.
**Similar Categories**: `cancelled` — client-initiated cancellation, not server-side timeout
**Default Message**: "Operation did not complete within the allowed time"

## Context Schema

| Field | Type | Description |
|-------|------|-------------|
| `resource_type` | `String` | GTS type identifier of the associated resource |
| `resource_name` | `String` | Identifier of the associated resource |
| `extra` | `Option<Object>` | Reserved for derived GTS type extensions (p3+); absent in p1 |

## Constructor Example

```rust
use cf_modkit_errors::{CanonicalError, DeadlineExceeded};

let err = CanonicalError::deadline_exceeded(DeadlineExceeded::new());
```

## JSON Wire — JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "gts://gts.cf.core.errors.err.v1~cf.core.err.deadline_exceeded.v1~",
  "type": "object",
  "allOf": [
    { "$ref": "gts://gts.cf.core.errors.err.v1~" },
    {
      "properties": {
        "type": {
          "const": "gts://gts.cf.core.errors.err.v1~cf.core.err.deadline_exceeded.v1~"
        },
        "title": { "const": "Deadline Exceeded" },
        "status": { "const": 504 },
        "context": {
          "type": "object",
          "properties": {
            "resource_type": {
              "type": "string",
              "description": "GTS type identifier of the associated resource (injected when resource_type is set)"
            },
            "resource_name": {
              "type": "string",
              "description": "Identifier of the associated resource (injected when resource_name is set)"
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
  "type": "gts://gts.cf.core.errors.err.v1~cf.core.err.deadline_exceeded.v1~",
  "title": "Deadline Exceeded",
  "status": 504,
  "detail": "Operation did not complete within the allowed time",
  "context": {
    "resource_type": "gts.cf.core.users.user.v1~",
    "resource_name": "user-123"
  }
}
```
