use serde::Serialize;

// ---------------------------------------------------------------------------
// Shared inner types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct FieldViolation {
    pub field: String,
    pub description: String,
    pub reason: String,
}

impl FieldViolation {
    #[must_use]
    pub fn new(
        field: impl Into<String>,
        description: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            description: description.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QuotaViolation {
    pub subject: String,
    pub description: String,
}

impl QuotaViolation {
    #[must_use]
    pub fn new(subject: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            description: description.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PreconditionViolation {
    #[serde(rename = "type")]
    pub type_: String,
    pub subject: String,
    pub description: String,
}

impl PreconditionViolation {
    #[must_use]
    pub fn new(
        type_: impl Into<String>,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            type_: type_.into(),
            subject: subject.into(),
            description: description.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-category context types
// ---------------------------------------------------------------------------

// 01 Cancelled — context: Cancelled
#[derive(Debug, Clone, Serialize)]
pub struct Cancelled {}

impl Cancelled {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

// 02 Unknown — context: Unknown
#[derive(Debug, Clone, Serialize)]
pub struct Unknown {
    pub description: String,
}

impl Unknown {
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
        }
    }
}

// 03 InvalidArgument — context: InvalidArgument (enum with 3 variants)
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum InvalidArgument {
    FieldViolations {
        field_violations: Vec<FieldViolation>,
    },
    Format {
        format: String,
    },
    Constraint {
        constraint: String,
    },
}

impl InvalidArgument {
    #[must_use]
    pub fn fields(violations: impl Into<Vec<FieldViolation>>) -> Self {
        Self::FieldViolations {
            field_violations: violations.into(),
        }
    }

    #[must_use]
    pub fn format(msg: impl Into<String>) -> Self {
        Self::Format { format: msg.into() }
    }

    #[must_use]
    pub fn constraint(msg: impl Into<String>) -> Self {
        Self::Constraint {
            constraint: msg.into(),
        }
    }
}

// 04 DeadlineExceeded — context: DeadlineExceeded
#[derive(Debug, Clone, Serialize)]
pub struct DeadlineExceeded {}

impl DeadlineExceeded {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

// 05 NotFound — context: NotFound
#[derive(Debug, Clone, Serialize)]
pub struct NotFound {
    pub resource_type: String,
    pub resource_name: String,
    pub description: String,
}

impl NotFound {
    #[must_use]
    pub fn new(resource_type: impl Into<String>, resource_name: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            description: String::from("Resource not found"),
        }
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

// 06 AlreadyExists — context: AlreadyExists
#[derive(Debug, Clone, Serialize)]
pub struct AlreadyExists {
    pub resource_type: String,
    pub resource_name: String,
    pub description: String,
}

impl AlreadyExists {
    #[must_use]
    pub fn new(resource_type: impl Into<String>, resource_name: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            description: String::from("Resource already exists"),
        }
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

// 07 PermissionDenied — context: PermissionDenied
#[derive(Debug, Clone, Serialize)]
pub struct PermissionDenied {
    pub reason: String,
    pub domain: String,
}

impl PermissionDenied {
    #[must_use]
    pub fn new(reason: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            domain: domain.into(),
        }
    }
}

// 08 ResourceExhausted — context: ResourceExhausted
#[derive(Debug, Clone, Serialize)]
pub struct ResourceExhausted {
    pub violations: Vec<QuotaViolation>,
}

impl ResourceExhausted {
    #[must_use]
    pub fn new(violations: impl Into<Vec<QuotaViolation>>) -> Self {
        Self {
            violations: violations.into(),
        }
    }
}

// 09 FailedPrecondition — context: FailedPrecondition
#[derive(Debug, Clone, Serialize)]
pub struct FailedPrecondition {
    pub violations: Vec<PreconditionViolation>,
}

impl FailedPrecondition {
    #[must_use]
    pub fn new(violations: impl Into<Vec<PreconditionViolation>>) -> Self {
        Self {
            violations: violations.into(),
        }
    }
}

// 10 Aborted — context: Aborted
#[derive(Debug, Clone, Serialize)]
pub struct Aborted {
    pub reason: String,
    pub domain: String,
}

impl Aborted {
    #[must_use]
    pub fn new(reason: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            domain: domain.into(),
        }
    }
}

// 11 OutOfRange — context: OutOfRange
#[derive(Debug, Clone, Serialize)]
pub struct OutOfRange {
    pub field_violations: Vec<FieldViolation>,
}

impl OutOfRange {
    #[must_use]
    pub fn new(violations: impl Into<Vec<FieldViolation>>) -> Self {
        Self {
            field_violations: violations.into(),
        }
    }
}

// 12 Unimplemented — context: Unimplemented
#[derive(Debug, Clone, Serialize)]
pub struct Unimplemented {
    pub reason: String,
    pub domain: String,
}

impl Unimplemented {
    #[must_use]
    pub fn new(reason: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            domain: domain.into(),
        }
    }
}

// 13 Internal — context: Internal
#[derive(Debug, Clone, Serialize)]
pub struct Internal {
    pub description: String,
}

impl Internal {
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
        }
    }
}

// 14 ServiceUnavailable — context: ServiceUnavailable
#[derive(Debug, Clone, Serialize)]
pub struct ServiceUnavailable {
    pub retry_after_seconds: u64,
}

impl ServiceUnavailable {
    #[must_use]
    pub fn new(retry_after_seconds: u64) -> Self {
        Self {
            retry_after_seconds,
        }
    }
}

// 15 DataLoss — context: DataLoss
#[derive(Debug, Clone, Serialize)]
pub struct DataLoss {
    pub resource_type: String,
    pub resource_name: String,
    pub description: String,
}

impl DataLoss {
    #[must_use]
    pub fn new(resource_type: impl Into<String>, resource_name: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            description: String::from("Data loss detected"),
        }
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

// 16 Unauthenticated — context: Unauthenticated
#[derive(Debug, Clone, Serialize)]
pub struct Unauthenticated {
    pub reason: String,
    pub domain: String,
}

impl Unauthenticated {
    #[must_use]
    pub fn new(reason: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            domain: domain.into(),
        }
    }
}

