//! Behavioral contract for the `PrismModel` developer surface.
//!
//! Per the UOR-Framework wiki ADR-020, `PrismModel` codifies the application
//! author's typed-iso contract: an `Input` feature type, an `Output` label
//! type, and a type-level `Route` witness of the term tree mapping one to
//! the other. The `Route` associated type is bound by `FoundationClosed`
//! — closure under foundation vocabulary, enforced at the application's
//! compile time per UORassembly (TC-04, ADR-006). Per ADR-019, `forward`
//! is the catamorphism into `pipeline::run`'s runtime carrier; together
//! with the `Trace`-witnessed anamorphism through
//! `replay::certify_from_trace` it forms the verifiable round-trip the
//! architecture commits to.
//!
//! This test pins:
//!
//! 1. The `PrismModel` trait is reachable through `pipeline::PrismModel`.
//! 2. The `FoundationClosed` marker is reachable through
//!    `pipeline::FoundationClosed`.
//! 3. The trait carries the three associated types the wiki specifies
//!    (`Input`, `Output`, `Route`) with their respective bounds.
//! 4. The `forward` method signature returns
//!    `Result<Grounded<Self::Output>, PipelineFailure>`.
//! 5. `FoundationClosed` is reachable as a trait bound in user code, and
//!    foundation's sanctioned identity route satisfies it.

use uor_foundation::enforcement::{ConstrainedTypeInput, Grounded};
use uor_foundation::pipeline::{FoundationClosed, PrismModel};
use uor_foundation::PipelineFailure;

/// `ConstrainedTypeInput` is foundation's identity route: the default
/// empty shape carrying no constraints. Foundation sanctions its
/// `FoundationClosed` impl directly so test code (and trivial real
/// applications) can declare a `PrismModel` without going through the
/// `prism_model!` macro. The macro is the canonical producer of impls
/// for non-trivial routes.
fn _identity_route_is_foundation_closed() {
    fn _accepts<R: FoundationClosed>() {}
    _accepts::<ConstrainedTypeInput>();
}

/// A trivial model: the input type is also the output type, the route is
/// foundation's identity. `forward()` returns a synthetic preflight
/// failure — the catamorphism is exercised by the `prism_model!` macro
/// integration tests downstream, not here. This test pins the trait
/// surface compiles.
struct IdentityModel;

impl PrismModel for IdentityModel {
    type Input = ConstrainedTypeInput;
    type Output = ConstrainedTypeInput;
    type Route = ConstrainedTypeInput;

    fn forward(_input: Self::Input) -> Result<Grounded<Self::Output>, PipelineFailure> {
        Err(PipelineFailure::ContradictionDetected {
            at_step: 0,
            trace_iri: "https://uor.foundation/test/behavior_prism_model/identity",
        })
    }
}

#[test]
fn prism_model_surface_resolves_at_crate_root() {
    fn _accepts_prism_model<M: PrismModel>() {}
    fn _accepts_foundation_closed<R: FoundationClosed>() {}
    _accepts_prism_model::<IdentityModel>();
    _accepts_foundation_closed::<ConstrainedTypeInput>();

    // Pin the associated-type identity: a trivial model carries the
    // foundation-empty shape on every position.
    let input_name = core::any::type_name::<<IdentityModel as PrismModel>::Input>();
    let output_name = core::any::type_name::<<IdentityModel as PrismModel>::Output>();
    let route_name = core::any::type_name::<<IdentityModel as PrismModel>::Route>();
    assert!(input_name.ends_with("ConstrainedTypeInput"));
    assert!(output_name.ends_with("ConstrainedTypeInput"));
    assert!(route_name.ends_with("ConstrainedTypeInput"));
}

#[test]
fn prism_model_route_bound_is_foundation_closed() {
    // Parametric assertion: any `M: PrismModel` has its `Route` type
    // bound by `FoundationClosed`. This is what enforces wiki ADR-020's
    // closure-under-foundation-vocabulary check.
    fn _route_is_foundation_closed<M: PrismModel>() {
        fn _check<R: FoundationClosed>() {}
        _check::<M::Route>();
    }
    _route_is_foundation_closed::<IdentityModel>();

    // Pin behaviorally: the witnessing impl exists, observable via
    // `core::any::type_name`.
    let route_name = core::any::type_name::<<IdentityModel as PrismModel>::Route>();
    assert_eq!(
        route_name,
        core::any::type_name::<ConstrainedTypeInput>(),
        "IdentityModel's Route is foundation's identity route",
    );
}

#[test]
fn prism_model_forward_returns_grounded_result() {
    // The wiki specifies `forward(input: Input) → Result<Grounded<Output>, PipelineFailure>`.
    // Pin that signature shape via a runtime call.
    let result = IdentityModel::forward(ConstrainedTypeInput::default());
    assert!(matches!(
        result,
        Err(PipelineFailure::ContradictionDetected { .. })
    ));
}
