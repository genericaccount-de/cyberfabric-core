use std::fmt;

use crate::context::{
    Aborted, AlreadyExists, Cancelled, DataLoss, DeadlineExceeded, FailedPrecondition,
    Internal, InvalidArgument, NotFound, OutOfRange, PermissionDenied, ResourceExhausted,
    ServiceUnavailable, Unauthenticated, Unimplemented, Unknown,
};

// ---------------------------------------------------------------------------
// CanonicalError Enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum CanonicalError {
    Cancelled {
        ctx: Cancelled,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    Unknown {
        ctx: Unknown,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    InvalidArgument {
        ctx: InvalidArgument,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    DeadlineExceeded {
        ctx: DeadlineExceeded,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    NotFound {
        ctx: NotFound,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    AlreadyExists {
        ctx: AlreadyExists,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    PermissionDenied {
        ctx: PermissionDenied,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    ResourceExhausted {
        ctx: ResourceExhausted,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    FailedPrecondition {
        ctx: FailedPrecondition,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    Aborted {
        ctx: Aborted,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    OutOfRange {
        ctx: OutOfRange,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    Unimplemented {
        ctx: Unimplemented,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    Internal {
        ctx: Internal,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    ServiceUnavailable {
        ctx: ServiceUnavailable,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    DataLoss {
        ctx: DataLoss,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
    Unauthenticated {
        ctx: Unauthenticated,
        message: String,
        resource_type: Option<String>,
        resource_name: Option<String>,
    },
}

impl CanonicalError {
    // --- Ergonomic constructors (one per category) ---

    #[must_use]
    pub fn cancelled(ctx: Cancelled) -> Self {
        Self::Cancelled {
            ctx,
            message: String::from("Operation cancelled by the client"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn unknown(ctx: Unknown) -> Self {
        let message = ctx.description.clone();
        Self::Unknown {
            ctx,
            message,
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn invalid_argument(ctx: InvalidArgument) -> Self {
        let message = match &ctx {
            InvalidArgument::FieldViolations { .. } => String::from("Request validation failed"),
            InvalidArgument::Format { format } => format.clone(),
            InvalidArgument::Constraint { constraint } => constraint.clone(),
        };
        Self::InvalidArgument {
            ctx,
            message,
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn deadline_exceeded(ctx: DeadlineExceeded) -> Self {
        Self::DeadlineExceeded {
            ctx,
            message: String::from("Operation did not complete within the allowed time"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn not_found(ctx: NotFound) -> Self {
        Self::NotFound {
            ctx,
            message: String::from("Resource not found"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn already_exists(ctx: AlreadyExists) -> Self {
        let message = ctx.description.clone();
        Self::AlreadyExists {
            ctx,
            message,
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn permission_denied(ctx: PermissionDenied) -> Self {
        Self::PermissionDenied {
            ctx,
            message: String::from("You do not have permission to perform this operation"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn resource_exhausted(ctx: ResourceExhausted) -> Self {
        Self::ResourceExhausted {
            ctx,
            message: String::from("Quota exceeded"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn failed_precondition(ctx: FailedPrecondition) -> Self {
        Self::FailedPrecondition {
            ctx,
            message: String::from("Operation precondition not met"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn aborted(ctx: Aborted) -> Self {
        Self::Aborted {
            ctx,
            message: String::from("Operation aborted due to concurrency conflict"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn out_of_range(ctx: OutOfRange) -> Self {
        Self::OutOfRange {
            ctx,
            message: String::from("Value out of range"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn unimplemented(ctx: Unimplemented) -> Self {
        Self::Unimplemented {
            ctx,
            message: String::from("This operation is not implemented"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn internal(ctx: Internal) -> Self {
        Self::Internal {
            ctx,
            message: String::from("An internal error occurred. Please retry later."),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn service_unavailable(ctx: ServiceUnavailable) -> Self {
        Self::ServiceUnavailable {
            ctx,
            message: String::from("Service temporarily unavailable"),
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn data_loss(ctx: DataLoss) -> Self {
        let message = ctx.description.clone();
        Self::DataLoss {
            ctx,
            message,
            resource_type: None,
            resource_name: None,
        }
    }

    #[must_use]
    pub fn unauthenticated(ctx: Unauthenticated) -> Self {
        Self::Unauthenticated {
            ctx,
            message: String::from("Authentication required"),
            resource_type: None,
            resource_name: None,
        }
    }

    // --- Builder methods ---

    #[must_use]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        let msg = msg.into();
        match &mut self {
            Self::Cancelled { message, .. }
            | Self::Unknown { message, .. }
            | Self::InvalidArgument { message, .. }
            | Self::DeadlineExceeded { message, .. }
            | Self::NotFound { message, .. }
            | Self::AlreadyExists { message, .. }
            | Self::PermissionDenied { message, .. }
            | Self::ResourceExhausted { message, .. }
            | Self::FailedPrecondition { message, .. }
            | Self::Aborted { message, .. }
            | Self::OutOfRange { message, .. }
            | Self::Unimplemented { message, .. }
            | Self::Internal { message, .. }
            | Self::ServiceUnavailable { message, .. }
            | Self::DataLoss { message, .. }
            | Self::Unauthenticated { message, .. } => *message = msg,
        }
        self
    }

    #[must_use]
    pub fn with_resource_type(mut self, rt: impl Into<String>) -> Self {
        let rt = Some(rt.into());
        match &mut self {
            Self::Cancelled { resource_type, .. }
            | Self::Unknown { resource_type, .. }
            | Self::InvalidArgument { resource_type, .. }
            | Self::DeadlineExceeded { resource_type, .. }
            | Self::NotFound { resource_type, .. }
            | Self::AlreadyExists { resource_type, .. }
            | Self::PermissionDenied { resource_type, .. }
            | Self::ResourceExhausted { resource_type, .. }
            | Self::FailedPrecondition { resource_type, .. }
            | Self::Aborted { resource_type, .. }
            | Self::OutOfRange { resource_type, .. }
            | Self::Unimplemented { resource_type, .. }
            | Self::Internal { resource_type, .. }
            | Self::ServiceUnavailable { resource_type, .. }
            | Self::DataLoss { resource_type, .. }
            | Self::Unauthenticated { resource_type, .. } => *resource_type = rt,
        }
        self
    }

    #[must_use]
    pub fn with_resource_name(mut self, rn: impl Into<String>) -> Self {
        let rn = Some(rn.into());
        match &mut self {
            Self::Cancelled { resource_name, .. }
            | Self::Unknown { resource_name, .. }
            | Self::InvalidArgument { resource_name, .. }
            | Self::DeadlineExceeded { resource_name, .. }
            | Self::NotFound { resource_name, .. }
            | Self::AlreadyExists { resource_name, .. }
            | Self::PermissionDenied { resource_name, .. }
            | Self::ResourceExhausted { resource_name, .. }
            | Self::FailedPrecondition { resource_name, .. }
            | Self::Aborted { resource_name, .. }
            | Self::OutOfRange { resource_name, .. }
            | Self::Unimplemented { resource_name, .. }
            | Self::Internal { resource_name, .. }
            | Self::ServiceUnavailable { resource_name, .. }
            | Self::DataLoss { resource_name, .. }
            | Self::Unauthenticated { resource_name, .. } => *resource_name = rn,
        }
        self
    }

    // --- Accessors ---

    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Cancelled { message, .. }
            | Self::Unknown { message, .. }
            | Self::InvalidArgument { message, .. }
            | Self::DeadlineExceeded { message, .. }
            | Self::NotFound { message, .. }
            | Self::AlreadyExists { message, .. }
            | Self::PermissionDenied { message, .. }
            | Self::ResourceExhausted { message, .. }
            | Self::FailedPrecondition { message, .. }
            | Self::Aborted { message, .. }
            | Self::OutOfRange { message, .. }
            | Self::Unimplemented { message, .. }
            | Self::Internal { message, .. }
            | Self::ServiceUnavailable { message, .. }
            | Self::DataLoss { message, .. }
            | Self::Unauthenticated { message, .. } => message,
        }
    }

    #[must_use]
    pub fn resource_type(&self) -> Option<&str> {
        match self {
            Self::Cancelled { resource_type, .. }
            | Self::Unknown { resource_type, .. }
            | Self::InvalidArgument { resource_type, .. }
            | Self::DeadlineExceeded { resource_type, .. }
            | Self::NotFound { resource_type, .. }
            | Self::AlreadyExists { resource_type, .. }
            | Self::PermissionDenied { resource_type, .. }
            | Self::ResourceExhausted { resource_type, .. }
            | Self::FailedPrecondition { resource_type, .. }
            | Self::Aborted { resource_type, .. }
            | Self::OutOfRange { resource_type, .. }
            | Self::Unimplemented { resource_type, .. }
            | Self::Internal { resource_type, .. }
            | Self::ServiceUnavailable { resource_type, .. }
            | Self::DataLoss { resource_type, .. }
            | Self::Unauthenticated { resource_type, .. } => resource_type.as_deref(),
        }
    }

    #[must_use]
    pub fn resource_name(&self) -> Option<&str> {
        match self {
            Self::Cancelled { resource_name, .. }
            | Self::Unknown { resource_name, .. }
            | Self::InvalidArgument { resource_name, .. }
            | Self::DeadlineExceeded { resource_name, .. }
            | Self::NotFound { resource_name, .. }
            | Self::AlreadyExists { resource_name, .. }
            | Self::PermissionDenied { resource_name, .. }
            | Self::ResourceExhausted { resource_name, .. }
            | Self::FailedPrecondition { resource_name, .. }
            | Self::Aborted { resource_name, .. }
            | Self::OutOfRange { resource_name, .. }
            | Self::Unimplemented { resource_name, .. }
            | Self::Internal { resource_name, .. }
            | Self::ServiceUnavailable { resource_name, .. }
            | Self::DataLoss { resource_name, .. }
            | Self::Unauthenticated { resource_name, .. } => resource_name.as_deref(),
        }
    }

    // --- Metadata accessors (direct match) ---

    #[must_use]
    pub fn gts_type(&self) -> &'static str {
        match self {
            Self::Cancelled { .. } => "gts.cf.core.errors.err.v1~cf.core.err.cancelled.v1~",
            Self::Unknown { .. } => "gts.cf.core.errors.err.v1~cf.core.err.unknown.v1~",
            Self::InvalidArgument { .. } => "gts.cf.core.errors.err.v1~cf.core.err.invalid_argument.v1~",
            Self::DeadlineExceeded { .. } => "gts.cf.core.errors.err.v1~cf.core.err.deadline_exceeded.v1~",
            Self::NotFound { .. } => "gts.cf.core.errors.err.v1~cf.core.err.not_found.v1~",
            Self::AlreadyExists { .. } => "gts.cf.core.errors.err.v1~cf.core.err.already_exists.v1~",
            Self::PermissionDenied { .. } => "gts.cf.core.errors.err.v1~cf.core.err.permission_denied.v1~",
            Self::ResourceExhausted { .. } => "gts.cf.core.errors.err.v1~cf.core.err.resource_exhausted.v1~",
            Self::FailedPrecondition { .. } => "gts.cf.core.errors.err.v1~cf.core.err.failed_precondition.v1~",
            Self::Aborted { .. } => "gts.cf.core.errors.err.v1~cf.core.err.aborted.v1~",
            Self::OutOfRange { .. } => "gts.cf.core.errors.err.v1~cf.core.err.out_of_range.v1~",
            Self::Unimplemented { .. } => "gts.cf.core.errors.err.v1~cf.core.err.unimplemented.v1~",
            Self::Internal { .. } => "gts.cf.core.errors.err.v1~cf.core.err.internal.v1~",
            Self::ServiceUnavailable { .. } => "gts.cf.core.errors.err.v1~cf.core.err.service_unavailable.v1~",
            Self::DataLoss { .. } => "gts.cf.core.errors.err.v1~cf.core.err.data_loss.v1~",
            Self::Unauthenticated { .. } => "gts.cf.core.errors.err.v1~cf.core.err.unauthenticated.v1~",
        }
    }

    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidArgument { .. }
            | Self::FailedPrecondition { .. }
            | Self::OutOfRange { .. } => 400,
            Self::Unauthenticated { .. } => 401,
            Self::PermissionDenied { .. } => 403,
            Self::NotFound { .. } => 404,
            Self::AlreadyExists { .. } | Self::Aborted { .. } => 409,
            Self::ResourceExhausted { .. } => 429,
            Self::Cancelled { .. } => 499,
            Self::Unknown { .. } | Self::Internal { .. } | Self::DataLoss { .. } => 500,
            Self::Unimplemented { .. } => 501,
            Self::ServiceUnavailable { .. } => 503,
            Self::DeadlineExceeded { .. } => 504,
        }
    }

    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Self::Cancelled { .. } => "Cancelled",
            Self::Unknown { .. } => "Unknown",
            Self::InvalidArgument { .. } => "Invalid Argument",
            Self::DeadlineExceeded { .. } => "Deadline Exceeded",
            Self::NotFound { .. } => "Not Found",
            Self::AlreadyExists { .. } => "Already Exists",
            Self::PermissionDenied { .. } => "Permission Denied",
            Self::ResourceExhausted { .. } => "Resource Exhausted",
            Self::FailedPrecondition { .. } => "Failed Precondition",
            Self::Aborted { .. } => "Aborted",
            Self::OutOfRange { .. } => "Out of Range",
            Self::Unimplemented { .. } => "Unimplemented",
            Self::Internal { .. } => "Internal",
            Self::ServiceUnavailable { .. } => "Service Unavailable",
            Self::DataLoss { .. } => "Data Loss",
            Self::Unauthenticated { .. } => "Unauthenticated",
        }
    }

    fn category_name(&self) -> &'static str {
        match self {
            Self::Cancelled { .. } => "cancelled",
            Self::Unknown { .. } => "unknown",
            Self::InvalidArgument { .. } => "invalid_argument",
            Self::DeadlineExceeded { .. } => "deadline_exceeded",
            Self::NotFound { .. } => "not_found",
            Self::AlreadyExists { .. } => "already_exists",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::ResourceExhausted { .. } => "resource_exhausted",
            Self::FailedPrecondition { .. } => "failed_precondition",
            Self::Aborted { .. } => "aborted",
            Self::OutOfRange { .. } => "out_of_range",
            Self::Unimplemented { .. } => "unimplemented",
            Self::Internal { .. } => "internal",
            Self::ServiceUnavailable { .. } => "service_unavailable",
            Self::DataLoss { .. } => "data_loss",
            Self::Unauthenticated { .. } => "unauthenticated",
        }
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.category_name(), self.message())
    }
}

impl std::error::Error for CanonicalError {}
