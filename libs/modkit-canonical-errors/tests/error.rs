extern crate cf_modkit_errors;

use cf_modkit_errors::{
    Aborted, AlreadyExists, Cancelled, CanonicalError, DataLoss, DeadlineExceeded,
    FailedPrecondition, Internal, InvalidArgument, NotFound, OutOfRange, PermissionDenied, Problem,
    ResourceExhausted, ServiceUnavailable, Unauthenticated, Unimplemented, Unknown,
};

#[test]
fn not_found_gts_type() {
    let err = CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1~", "user-123"));
    assert_eq!(
        err.gts_type(),
        "gts.cf.core.errors.err.v1~cf.core.err.not_found.v1~"
    );
}

#[test]
fn not_found_status_code() {
    let err = CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1~", "user-123"));
    assert_eq!(err.status_code(), 404);
}

#[test]
fn not_found_title() {
    let err = CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1~", "user-123"));
    assert_eq!(err.title(), "Not Found");
}

#[test]
fn display_includes_category_and_message() {
    let err = CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1~", "user-123"))
        .with_message("User not found");
    assert_eq!(format!("{err}"), "not_found: User not found");
}

#[test]
fn with_message_overrides_default() {
    let err = CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1~", "user-123"))
        .with_message("custom detail");
    assert_eq!(err.message(), "custom detail");
}

#[test]
fn all_16_categories_convert_to_problem() {
    let errors: Vec<CanonicalError> = vec![
        CanonicalError::cancelled(Cancelled::new()),
        CanonicalError::unknown(Unknown::new("unknown error")),
        CanonicalError::invalid_argument(InvalidArgument::format("bad")),
        CanonicalError::deadline_exceeded(DeadlineExceeded::new()),
        CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1~", "user-123")),
        CanonicalError::already_exists(AlreadyExists::new("gts.cf.core.users.user.v1~", "user-123")),
        CanonicalError::permission_denied(PermissionDenied::new("R", "D")),
        CanonicalError::resource_exhausted(ResourceExhausted::new(vec![])),
        CanonicalError::failed_precondition(FailedPrecondition::new(vec![])),
        CanonicalError::aborted(Aborted::new("R", "D")),
        CanonicalError::out_of_range(OutOfRange::new(vec![])),
        CanonicalError::unimplemented(Unimplemented::new("R", "D")),
        CanonicalError::internal(Internal::new("bug")),
        CanonicalError::service_unavailable(ServiceUnavailable::new(10)),
        CanonicalError::data_loss(DataLoss::new("gts.cf.core.users.user.v1~", "user-123")),
        CanonicalError::unauthenticated(Unauthenticated::new("R", "D")),
    ];
    assert_eq!(errors.len(), 16);
    for err in errors {
        let problem = Problem::from(err);
        assert!(!problem.problem_type.is_empty());
        assert!(!problem.title.is_empty());
        assert!(problem.status > 0);
    }
}

// =========================================================================
// GTS ID validation — ensures all IDs in the crate are valid GTS identifiers
// =========================================================================

#[test]
fn validate_all_gts_ids() {
    let errors = vec![
        CanonicalError::cancelled(Cancelled::new()),
        CanonicalError::unknown(Unknown::new("e")),
        CanonicalError::invalid_argument(InvalidArgument::format("f")),
        CanonicalError::deadline_exceeded(DeadlineExceeded::new()),
        CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1~", "user-123")),
        CanonicalError::already_exists(AlreadyExists::new("gts.cf.core.users.user.v1~", "user-123")),
        CanonicalError::permission_denied(PermissionDenied::new("R", "D")),
        CanonicalError::resource_exhausted(ResourceExhausted::new(vec![])),
        CanonicalError::failed_precondition(FailedPrecondition::new(vec![])),
        CanonicalError::aborted(Aborted::new("R", "D")),
        CanonicalError::out_of_range(OutOfRange::new(vec![])),
        CanonicalError::unimplemented(Unimplemented::new("R", "D")),
        CanonicalError::internal(Internal::new("d")),
        CanonicalError::service_unavailable(ServiceUnavailable::new(1)),
        CanonicalError::data_loss(DataLoss::new("gts.cf.core.users.user.v1~", "user-123")),
        CanonicalError::unauthenticated(Unauthenticated::new("R", "D")),
    ];
    for err in &errors {
        let id = err.gts_type();
        assert!(id.ends_with('~'), "GTS type ID must end with ~: {id}");
        gts_id::validate_gts_id(id, false)
            .unwrap_or_else(|e| panic!("Invalid GTS type ID '{id}': {e}"));
    }
}
