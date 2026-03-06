extern crate cf_modkit_errors;

use cf_modkit_errors::{CanonicalError, NotFound, Problem, ServiceUnavailable, Unknown};

#[test]
fn problem_from_not_found_has_correct_fields() {
    let err = CanonicalError::not_found(NotFound::new("gts.cf.core.users.user.v1", "user-123"));
    let problem = Problem::from(err);
    assert_eq!(
        problem.problem_type,
        "gts.cf.core.errors.err.v1~cf.core.err.not_found.v1~"
    );
    assert_eq!(problem.title, "Not Found");
    assert_eq!(problem.status, 404);
    assert_eq!(problem.detail, "Resource not found");
    assert_eq!(
        problem.context["resource_type"],
        "gts.cf.core.users.user.v1"
    );
    assert_eq!(problem.context["resource_name"], "user-123");
}

#[test]
fn problem_json_excludes_none_fields() {
    let err = CanonicalError::service_unavailable(ServiceUnavailable::new(30));
    let problem = Problem::from(err);
    let json = serde_json::to_value(&problem).unwrap();
    assert!(json.get("trace_id").is_none());
}

#[test]
fn direct_constructor_has_no_resource_type() {
    let err = CanonicalError::service_unavailable(ServiceUnavailable::new(30));
    assert_eq!(err.resource_type(), None);
    let _problem = Problem::from(err);
}

#[test]
fn problem_json_excludes_resource_type_when_none() {
    let err = CanonicalError::unknown(Unknown::new("some error"));
    let problem = Problem::from(err);
    let json = serde_json::to_value(&problem).unwrap();
    assert!(json["context"].get("resource_type").is_none());
}

