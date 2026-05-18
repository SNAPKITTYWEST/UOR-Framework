//! ADR-057 bounded recursive structural typing.
//!
//! Pins the foundation surface ADR-057 commits:
//!
//! 1. `ConstraintRef::Recurse { shape_iri, descent_bound }` exists as a
//!    variant of `uor_foundation::pipeline::ConstraintRef` carrying a
//!    content-addressed shape IRI and a descent bound.
//! 2. `LeafConstraintRef::Recurse { shape_iri, descent_bound }` exists
//!    as the leaf-level parallel and round-trips through `as_leaf`/
//!    `into_constraint`.
//! 3. `shift_constraint` and `shift_leaf_constraint` pass Recurse through
//!    unchanged (no site references to shift).
//! 4. `pipeline::shape_iri_registry::RegisteredShape` carries the four
//!    fields the wiki spec names: iri, site_count, constraints, cycle_size.
//! 5. `pipeline::shape_iri_registry::lookup_shape` is publicly callable
//!    and returns `None` on an unregistered IRI.
//! 6. The wire-format discriminant byte for Recurse is 10 (one more than
//!    Conjunction = 9), per ADR-057's wire-format integration rule.

use uor_foundation::enforcement::Hasher;
use uor_foundation::pipeline::shape_iri_registry::RegisteredShape;
use uor_foundation::pipeline::{
    shape_iri_registry, shift_constraint, shift_leaf_constraint, ConstraintRef, LeafConstraintRef,
};

#[test]
fn constraint_ref_recurse_variant_carries_shape_iri_and_descent_bound() {
    let c = ConstraintRef::Recurse {
        shape_iri: "urn:test:json_value",
        descent_bound: 32,
    };
    match c {
        ConstraintRef::Recurse {
            shape_iri,
            descent_bound,
        } => {
            assert_eq!(shape_iri, "urn:test:json_value");
            assert_eq!(descent_bound, 32);
        }
        other => panic!("expected Recurse, got {other:?}"),
    }
}

#[test]
fn leaf_constraint_ref_recurse_round_trips_via_as_leaf_into_constraint() {
    let c = ConstraintRef::Recurse {
        shape_iri: "urn:test:xml_node",
        descent_bound: 16,
    };
    let leaf = c.as_leaf();
    match leaf {
        LeafConstraintRef::Recurse {
            shape_iri,
            descent_bound,
        } => {
            assert_eq!(shape_iri, "urn:test:xml_node");
            assert_eq!(descent_bound, 16);
        }
        other => panic!("expected LeafConstraintRef::Recurse, got {other:?}"),
    }
    let back = leaf.into_constraint();
    match back {
        ConstraintRef::Recurse {
            shape_iri,
            descent_bound,
        } => {
            assert_eq!(shape_iri, "urn:test:xml_node");
            assert_eq!(descent_bound, 16);
        }
        other => panic!("expected ConstraintRef::Recurse round-trip, got {other:?}"),
    }
}

#[test]
fn shift_constraint_passes_recurse_through_unchanged() {
    // Recurse references a shape by IRI — no site positions to shift.
    // The shift_constraint helper should pass Recurse through unchanged
    // regardless of offset.
    let c = ConstraintRef::Recurse {
        shape_iri: "urn:test:sexpr",
        descent_bound: 64,
    };
    let shifted = shift_constraint(c, 42);
    match shifted {
        ConstraintRef::Recurse {
            shape_iri,
            descent_bound,
        } => {
            assert_eq!(shape_iri, "urn:test:sexpr");
            assert_eq!(descent_bound, 64);
        }
        other => panic!("expected Recurse pass-through, got {other:?}"),
    }
}

#[test]
fn shift_leaf_constraint_passes_recurse_through_unchanged() {
    let c = LeafConstraintRef::Recurse {
        shape_iri: "urn:test:protobuf_msg",
        descent_bound: 8,
    };
    let shifted = shift_leaf_constraint(c, 100);
    match shifted {
        LeafConstraintRef::Recurse {
            shape_iri,
            descent_bound,
        } => {
            assert_eq!(shape_iri, "urn:test:protobuf_msg");
            assert_eq!(descent_bound, 8);
        }
        other => panic!("expected LeafConstraintRef::Recurse pass-through, got {other:?}"),
    }
}

#[test]
fn shape_iri_registry_registered_shape_carries_canonical_fields() {
    // Verify the RegisteredShape struct has the four fields the wiki
    // spec names. Construct one by hand and read each accessor.
    static EMPTY_CONSTRAINTS: &[ConstraintRef] = &[];
    let entry = RegisteredShape {
        iri: "urn:test:registered_shape_1",
        site_count: 7,
        constraints: EMPTY_CONSTRAINTS,
        cycle_size: u64::MAX,
    };
    assert_eq!(entry.iri, "urn:test:registered_shape_1");
    assert_eq!(entry.site_count, 7);
    assert!(entry.constraints.is_empty());
    assert_eq!(entry.cycle_size, u64::MAX);
}

#[test]
fn shape_iri_registry_lookup_returns_none_for_unregistered_iri() {
    // The MVP foundation registry is empty (applications register via
    // the SDK `register_shape!` macro in a future release). Lookup of any
    // IRI should return None.
    assert!(shape_iri_registry::lookup_shape("urn:nonexistent:shape").is_none());
}

// ── Wire-format discriminant byte for Recurse ─────────────────────────

/// Minimal Hasher that records folded bytes so we can pin the discriminant.
#[derive(Debug, Clone, Copy, Default)]
struct ByteRecorder {
    first_byte: Option<u8>,
}
impl Hasher for ByteRecorder {
    const OUTPUT_BYTES: usize = 1;
    fn initial() -> Self {
        Self::default()
    }
    fn fold_byte(self, b: u8) -> Self {
        if self.first_byte.is_none() {
            Self {
                first_byte: Some(b),
            }
        } else {
            self
        }
    }
    fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let Some(b) = self.first_byte {
            out[0] = b;
        }
        out
    }
}

#[test]
fn fold_constraint_ref_emits_discriminant_byte_10_for_recurse() {
    // ADR-057 wire-format: Recurse is discriminant byte 10 (one more
    // than Conjunction = 9).
    let c = ConstraintRef::Recurse {
        shape_iri: "urn:test:ast",
        descent_bound: 4,
    };
    let hasher = ByteRecorder::default();
    let folded = uor_foundation::enforcement::fold_constraint_ref(hasher, &c);
    assert_eq!(
        folded.first_byte,
        Some(10),
        "ADR-057 Recurse must emit discriminant byte 10"
    );
}
