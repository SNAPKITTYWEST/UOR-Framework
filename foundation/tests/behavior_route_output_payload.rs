//! Behavioral contract for the route output payload (wiki ADR-028).
//!
//! Per ADR-028, `Grounded<T>` carries the catamorphism's evaluation
//! result as a fixed-capacity output payload alongside the metadata
//! fingerprint. `pipeline::ROUTE_OUTPUT_BUFFER_BYTES` is the
//! foundation-side ceiling (parallel to `ROUTE_INPUT_BUFFER_BYTES`
//! from ADR-023). `Grounded::output_bytes()` exposes the active prefix.

use uor_foundation::enforcement::ConstrainedTypeInput;
use uor_foundation::pipeline::ROUTE_OUTPUT_BUFFER_BYTES;

#[test]
fn output_buffer_ceiling_is_public_foundation_constant() {
    // Pin the foundation-declared default. ADR-028 requires the value
    // exists; the specific size is a foundation parameter (currently 4096
    // bytes, matching ROUTE_INPUT_BUFFER_BYTES from ADR-023).
    assert_eq!(ROUTE_OUTPUT_BUFFER_BYTES, 4096);
}

#[test]
fn grounded_output_bytes_accessor_is_public() {
    // The accessor exists on the `Grounded<T>` carrier per ADR-028. The
    // identity-route invocation that returns a `Grounded` lives behind
    // `pipeline::run_route`; this test pins the surface.
    fn _accepts_output_bytes<T: uor_foundation::enforcement::GroundedShape>(
        g: &uor_foundation::enforcement::Grounded<T>,
    ) -> &[u8] {
        g.output_bytes()
    }
    // Reference the function pointer to ensure compilation.
    let _: fn(&uor_foundation::enforcement::Grounded<ConstrainedTypeInput>) -> &[u8] =
        _accepts_output_bytes::<ConstrainedTypeInput>;

    // Pin the constant relationship between input and output buffer
    // ceilings: ADR-028 names them parallel architectural commitments.
    assert_eq!(
        ROUTE_OUTPUT_BUFFER_BYTES,
        uor_foundation::pipeline::ROUTE_INPUT_BUFFER_BYTES
    );
}
