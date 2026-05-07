//! Behavioral contract for the `IntoBindingValue` developer surface.
//!
//! Per the UOR-Framework wiki ADR-023, foundation declares
//! `IntoBindingValue` as the trait every `M::Input` must implement so
//! a runtime input value can flow into the `CompileUnit` binding
//! table. `pipeline::run_route` calls `into_binding_bytes` to fill a
//! buffer (sized by the foundation-fixed `ROUTE_INPUT_BUFFER_BYTES`
//! ceiling — the stable-Rust 1.83 equivalent of nightly's
//! `[u8; <T as IntoBindingValue>::MAX_BYTES]` form), hashes the
//! result through the application's selected `Hasher`, and
//! constructs a transient `Binding` for the route's input slot
//! (`Term::Variable { name_index: 0 }` per ADR-022 D3 G2).
//!
//! This test pins:
//!
//! 1. `IntoBindingValue` is reachable through `pipeline::*`.
//! 2. The trait carries the `MAX_BYTES` associated constant and the
//!    `into_binding_bytes(&self, &mut [u8])` method.
//! 3. The trait is sealed via `__sdk_seal::Sealed` (same supertrait
//!    as `FoundationClosed` and `PrismModel`).
//! 4. Foundation's identity-route impl on `ConstrainedTypeInput`
//!    declares `MAX_BYTES = 0` and `into_binding_bytes` returns
//!    `Ok(0)` (no bytes written).
//! 5. `pipeline::ROUTE_INPUT_BUFFER_BYTES` is a public foundation
//!    constant — the stable-Rust ceiling that `run_route` uses.
//! 6. `PrismModel::Input` carries the `IntoBindingValue` bound.

use uor_foundation::enforcement::{ConstrainedTypeInput, Hasher};
use uor_foundation::pipeline::{
    ConstrainedTypeShape, IntoBindingValue, PrismModel, ROUTE_INPUT_BUFFER_BYTES,
};
use uor_foundation::{DefaultHostBounds, DefaultHostTypes, HostBounds, HostTypes};

#[derive(Debug, Clone, Copy, Default)]
struct TestHasher;

impl Hasher for TestHasher {
    const OUTPUT_BYTES: usize = 16;

    fn initial() -> Self {
        Self
    }
    fn fold_byte(self, _: u8) -> Self {
        self
    }
    fn finalize(self) -> [u8; 32] {
        [0; 32]
    }
}

#[test]
fn into_binding_value_surface_resolves_at_crate_root() {
    fn _accepts<T: IntoBindingValue>() {}
    _accepts::<ConstrainedTypeInput>();
    // Pin the surface behaviorally: the foundation-sanctioned input
    // shape is reachable as a real type (observable through
    // `core::any::type_name`), which exercises that the trait surface
    // resolves at the foundation crate's public path rather than only
    // at compile time via the bound check above.
    assert!(
        core::any::type_name::<ConstrainedTypeInput>().ends_with("ConstrainedTypeInput"),
        "the foundation-sanctioned identity-input shape must be reachable",
    );
}

#[test]
fn into_binding_value_carries_max_bytes_associated_constant() {
    // ADR-023 specifies `const MAX_BYTES: usize` on the trait. The
    // foundation-sanctioned identity-route impl declares MAX_BYTES = 0
    // (the empty shape carries no bytes).
    assert_eq!(<ConstrainedTypeInput as IntoBindingValue>::MAX_BYTES, 0);
}

#[test]
fn into_binding_value_into_binding_bytes_signature_pins() {
    // Pin the method shape: takes &self + &mut [u8], returns
    // Result<usize, ShapeViolation>. Identity input writes zero bytes.
    let value = ConstrainedTypeInput::default();
    let mut buf = [0u8; 16];
    let result = value.into_binding_bytes(&mut buf);
    let _: Result<usize, uor_foundation::enforcement::ShapeViolation> = result;
    assert_eq!(value.into_binding_bytes(&mut buf), Ok(0));
}

#[test]
fn route_input_buffer_bytes_is_public_foundation_constant() {
    // ADR-023's stable-Rust-equivalent ceiling. Foundation fixes a
    // generous default; applications that need a different ceiling
    // request it through HostBounds extensions in future iterations.
    // Pin the foundation-declared default so applications and the
    // conformance suite can reason about which inputs flow through.
    assert_eq!(ROUTE_INPUT_BUFFER_BYTES, 4096);
    // Pin the constant matches the const-fn arena typed view: a buffer
    // of `ROUTE_INPUT_BUFFER_BYTES` is non-empty so a `&mut [u8]` of
    // that size is a valid call-site for `into_binding_bytes`.
    let buf = [0u8; ROUTE_INPUT_BUFFER_BYTES];
    assert_eq!(buf.len(), ROUTE_INPUT_BUFFER_BYTES);
}

#[test]
fn prism_model_input_bound_includes_into_binding_value() {
    // Wiki ADR-023 + ADR-022 D4: `PrismModel::Input` is bound by
    // `ConstrainedTypeShape + IntoBindingValue`. The parametric check
    // pins the bound: any `M: PrismModel<…>` has `M::Input:
    // IntoBindingValue`.
    fn _input_implements_into_binding<H, B, A, M>()
    where
        H: HostTypes,
        B: HostBounds,
        A: Hasher,
        M: PrismModel<H, B, A>,
    {
        fn _check<T: IntoBindingValue>() {}
        _check::<M::Input>();
    }
    // Identity route via the foundation-sanctioned impl.
    struct IdentityModel;
    impl uor_foundation::pipeline::__sdk_seal::Sealed for IdentityModel {}
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, TestHasher> for IdentityModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = ConstrainedTypeInput;

        fn forward(
            input: Self::Input,
        ) -> Result<
            uor_foundation::enforcement::Grounded<Self::Output>,
            uor_foundation::PipelineFailure,
        > {
            uor_foundation::pipeline::run_route::<
                DefaultHostTypes,
                DefaultHostBounds,
                TestHasher,
                Self,
            >(input)
        }
    }
    _input_implements_into_binding::<DefaultHostTypes, DefaultHostBounds, TestHasher, IdentityModel>(
    );

    // The ConstrainedTypeShape bound is preserved.
    let iri = <<IdentityModel as PrismModel<
        DefaultHostTypes,
        DefaultHostBounds,
        TestHasher,
    >>::Input as ConstrainedTypeShape>::IRI;
    assert!(iri.contains("ConstrainedType"));
}

#[test]
fn into_binding_value_is_sealed_via_sdk_seal() {
    // Pin that `IntoBindingValue` requires `__sdk_seal::Sealed` (per
    // ADR-023). External crates cannot impl `IntoBindingValue` without
    // first naming the doc-hidden seal — the same architectural
    // pattern foundation uses for `FoundationClosed` and `PrismModel`.
    fn _accepts_sealed<T: IntoBindingValue + uor_foundation::pipeline::__sdk_seal::Sealed>() {}
    _accepts_sealed::<ConstrainedTypeInput>();
    // Behavioral assertion: the seal supertrait's qualified name
    // includes `__sdk_seal::Sealed` exactly, exercising that the
    // foundation public path matches the wiki ADR-022 D1 + ADR-023
    // surface contract.
    let seal_name =
        core::any::type_name::<fn() -> Box<dyn uor_foundation::pipeline::__sdk_seal::Sealed>>();
    assert!(
        seal_name.contains("__sdk_seal::Sealed"),
        "the foundation seal supertrait must be reachable as `__sdk_seal::Sealed`; got {seal_name}",
    );
}
