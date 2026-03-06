# 11 Out of Range

**Category**: `out_of_range`
**GTS ID**: `gts.cf.core.errors.err.v1~cf.core.err.out_of_range.v1~`
**HTTP Status**: 400
**Title**: "Out of Range"
**Context Type**: `OutOfRange`
**Use When**: A value is syntactically valid but outside the acceptable range (e.g., age beyond allowed maximum, negative quantity).
**Similar Categories**: `invalid_argument` — bad format vs valid format but out of range
**Default Message**: "Value out of range"

## Context Schema

| Field | Type | Description |
|-------|------|-------------|
| `resource_type` | `String` | GTS type identifier of the associated resource |
| `resource_name` | `String` | Identifier of the associated resource |
| `field_violations` | `Vec<FieldViolation>` | List of per-field out-of-range errors |
| `extra` | `Option<Object>` | Reserved for derived GTS type extensions (p3+); absent in p1 |

Field violation:

| Field | Type | Description |
|-------|------|-------------|
| `field` | `String` | Field path (e.g., `"age"`, `"quantity"`) |
| `description` | `String` | Human-readable explanation |
| `reason` | `String` | Machine-readable reason code (e.g., `OUT_OF_RANGE`) |

## Constructor Example

```rust
use cf_modkit_errors::{CanonicalError, OutOfRange, FieldViolation};

let err = CanonicalError::out_of_range(
    OutOfRange::new(vec![
        FieldViolation::new("age", "must be between 1 and 150", "OUT_OF_RANGE"),
    ])
);
```

## JSON Wire — JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "gts://gts.cf.core.errors.err.v1~cf.core.err.out_of_range.v1~",
  "type": "object",
  "allOf": [
    { "$ref": "gts://gts.cf.core.errors.err.v1~" },
    {
      "properties": {
        "type": {
          "const": "gts://gts.cf.core.errors.err.v1~cf.core.err.out_of_range.v1~"
        },
        "title": { "const": "Out of Range" },
        "status": { "const": 400 },
        "context": {
          "type": "object",
          "required": ["field_violations"],
          "properties": {
            "resource_type": { "type": "string" },
            "resource_name": { "type": "string" },
            "field_violations": {
              "type": "array",
              "items": { "$ref": "#/$defs/FieldViolation" }
            },
            "extra": { "type": ["object", "null"] }
          },
          "additionalProperties": false
        }
      }
    }
  ],
  "$defs": {
    "FieldViolation": {
      "type": "object",
      "required": ["field", "description", "reason"],
      "properties": {
        "field": { "type": "string" },
        "description": { "type": "string" },
        "reason": { "type": "string" }
      },
      "additionalProperties": false
    }
  }
}
```

## JSON Wire — JSON Example

```json
{
  "type": "gts://gts.cf.core.errors.err.v1~cf.core.err.out_of_range.v1~",
  "title": "Out of Range",
  "status": 400,
  "detail": "Value out of range",
  "context": {
    "resource_type": "gts.cf.core.users.user.v1~",
    "resource_name": "user-123",
    "field_violations": [
      {
        "field": "age",
        "description": "must be between 1 and 150",
        "reason": "OUT_OF_RANGE"
      }
    ]
  }
}
```
