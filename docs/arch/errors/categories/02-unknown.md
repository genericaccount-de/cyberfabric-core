# 02 Unknown

**Category**: `unknown`
**GTS ID**: `gts.cf.core.errors.err.v1~cf.core.err.unknown.v1~`
**HTTP Status**: 500
**Title**: "Unknown"
**Context Type**: `Unknown`
**Use When**: An error occurred that does not match any other canonical category. Prefer a more specific category when possible.
**Similar Categories**: `internal` — known infrastructure failure vs truly unknown error
**Default Message**: Same as the `detail` parameter passed to the constructor.

## Context Schema

| Field | Type | Description |
|-------|------|-------------|
| `resource_type` | `String` | GTS type identifier of the associated resource |
| `resource_name` | `String` | Identifier of the associated resource |
| `description` | `String` | Human-readable debug message (generic in production) |
| `extra` | `Option<Object>` | Reserved for derived GTS type extensions (p3+); absent in p1 |

## Constructor Example

```rust
use cf_modkit_errors::{CanonicalError, Unknown};

let err = CanonicalError::unknown(
    Unknown { description: "Unexpected response from payment provider".to_string() }
);
```

## JSON Wire — JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "gts://gts.cf.core.errors.err.v1~cf.core.err.unknown.v1~",
  "type": "object",
  "allOf": [
    { "$ref": "gts://gts.cf.core.errors.err.v1~" },
    {
      "properties": {
        "type": {
          "const": "gts://gts.cf.core.errors.err.v1~cf.core.err.unknown.v1~"
        },
        "title": { "const": "Unknown" },
        "status": { "const": 500 },
        "context": {
          "type": "object",
          "required": ["description"],
          "properties": {
            "resource_type": {
              "type": "string",
              "description": "GTS type identifier of the associated resource (injected when resource_type is set)"
            },
            "resource_name": {
              "type": "string",
              "description": "Identifier of the associated resource (injected when resource_name is set)"
            },
            "description": {
              "type": "string",
              "description": "Human-readable debug message (generic in production)"
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
  "type": "gts://gts.cf.core.errors.err.v1~cf.core.err.unknown.v1~",
  "title": "Unknown",
  "status": 500,
  "detail": "Unexpected response from payment provider",
  "context": {
    "resource_type": "gts.cf.core.payments.payment.v1~",
    "resource_name": "pay-456",
    "description": "Unexpected response from payment provider"
  }
}
```
