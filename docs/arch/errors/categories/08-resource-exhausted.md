# 08 Resource Exhausted

**Category**: `resource_exhausted`
**GTS ID**: `gts.cf.core.errors.err.v1~cf.core.err.resource_exhausted.v1~`
**HTTP Status**: 429
**Title**: "Resource Exhausted"
**Context Type**: `ResourceExhausted`
**Use When**: A quota or rate limit was exceeded.
**Similar Categories**: `service_unavailable` — system overload vs per-caller quota
**Default Message**: "Quota exceeded"

## Context Schema

Quota failure:

| Field | Type | Description |
|-------|------|-------------|
| `resource_type` | `String` | GTS type identifier of the associated resource |
| `resource_name` | `String` | Identifier of the associated resource |
| `violations` | `Vec<QuotaViolation>` | List of quota violations |
| `extra` | `Option<Object>` | Reserved for derived GTS type extensions (p3+); absent in p1 |

Quota violation:

| Field | Type | Description |
|-------|------|-------------|
| `subject` | `String` | What the quota applies to (e.g., `"requests_per_minute"`) |
| `description` | `String` | Human-readable explanation |

## Constructor Example

```rust
use cf_modkit_errors::{CanonicalError, ResourceExhausted, QuotaViolation};

let err = CanonicalError::resource_exhausted(
    ResourceExhausted::new(vec![
        QuotaViolation::new(
            "requests_per_minute",
            "Limit of 100 requests per minute exceeded",
        )
    ])
);
```

## JSON Wire — JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "gts://gts.cf.core.errors.err.v1~cf.core.err.resource_exhausted.v1~",
  "type": "object",
  "allOf": [
    { "$ref": "gts://gts.cf.core.errors.err.v1~" },
    {
      "properties": {
        "type": {
          "const": "gts://gts.cf.core.errors.err.v1~cf.core.err.resource_exhausted.v1~"
        },
        "title": { "const": "Resource Exhausted" },
        "status": { "const": 429 },
        "context": {
          "type": "object",
          "required": ["violations"],
          "properties": {
            "resource_type": {
              "type": "string",
              "description": "GTS type identifier of the associated resource (injected when resource_type is set)"
            },
            "resource_name": {
              "type": "string",
              "description": "Identifier of the associated resource (injected when resource_name is set)"
            },
            "violations": {
              "type": "array",
              "items": { "$ref": "#/$defs/QuotaViolation" }
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
  ],
  "$defs": {
    "QuotaViolation": {
      "type": "object",
      "required": ["subject", "description"],
      "properties": {
        "subject": { "type": "string", "description": "What the quota applies to" },
        "description": { "type": "string", "description": "Human-readable explanation" }
      },
      "additionalProperties": false
    }
  }
}
```

## JSON Wire — JSON Example

```json
{
  "type": "gts://gts.cf.core.errors.err.v1~cf.core.err.resource_exhausted.v1~",
  "title": "Resource Exhausted",
  "status": 429,
  "detail": "Quota exceeded",
  "context": {
    "resource_type": "gts.cf.core.users.user.v1~",
    "resource_name": "user-123",
    "violations": [
      {
        "subject": "requests_per_minute",
        "description": "Limit of 100 requests per minute exceeded"
      }
    ]
  }
}
```
