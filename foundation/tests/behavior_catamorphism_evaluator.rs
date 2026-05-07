//! Behavioral contract for the catamorphism evaluator (wiki ADR-029).
//!
//! Per ADR-029, `pipeline::run` evaluates the route's Term tree as a
//! structural fold with per-variant fold-rules. Foundation exposes
//! `evaluate_term_tree` as the catamorphism's evaluation entry point;
//! `pipeline::run_route` calls it after validating the `CompileUnit`,
//! and the resulting bytes flow into the `Grounded`'s output payload
//! (per ADR-028).
//!
//! This test pins:
//!
//! 1. `evaluate_term_tree` is reachable through `pipeline::*`.
//! 2. The empty arena (identity route) returns the input bytes.
//! 3. `Term::Literal` evaluates to its literal value's big-endian bytes.
//! 4. `Term::Application` over `PrimitiveOp::Add` adds the args' values.
//! 5. `Term::HasherProjection` folds the input through the selected Hasher.
//! 6. `TERM_VALUE_MAX_BYTES` is the foundation-fixed per-value ceiling.

use uor_foundation::enforcement::{Hasher, Term, TermList};
use uor_foundation::pipeline::{evaluate_term_tree, TermValue, TERM_VALUE_MAX_BYTES};
use uor_foundation::{PrimitiveOp, WittLevel};

#[derive(Debug, Clone, Copy, Default)]
struct ZeroHasher;

impl Hasher for ZeroHasher {
    const OUTPUT_BYTES: usize = 4;
    fn initial() -> Self {
        Self
    }
    fn fold_byte(self, _: u8) -> Self {
        self
    }
    fn finalize(self) -> [u8; 32] {
        // Deterministic, distinguishable digest so the assertion below can
        // distinguish the hasher's output from the input bytes.
        let mut out = [0u8; 32];
        out[0] = 0xab;
        out[1] = 0xcd;
        out[2] = 0xef;
        out[3] = 0x01;
        out
    }
}

#[test]
fn evaluator_surface_resolves_at_crate_root() {
    // The function exists at the foundation public path.
    let _: fn(&[Term], &[u8]) -> _ = evaluate_term_tree::<ZeroHasher>;
    // Pin the constant carries a sensible, > 0 width. Must hold the
    // hasher's 32-byte digest plus arithmetic operands; the foundation
    // commits to 32 bytes per ADR-029's per-value ceiling.
    assert_eq!(TERM_VALUE_MAX_BYTES, 32);
}

#[test]
fn empty_arena_evaluates_to_input_bytes() {
    // ADR-029 / wiki ADR-022 D5 corner case: the foundation-sanctioned
    // identity route has an empty term arena. The catamorphism must
    // pass the input through to the output unchanged.
    let input = [0xde, 0xad, 0xbe, 0xef];
    let result = evaluate_term_tree::<ZeroHasher>(&[], &input).expect("identity route succeeds");
    assert_eq!(result.bytes(), &input[..]);
}

#[test]
fn literal_term_evaluates_to_value_bytes() {
    // Term::Literal { value: 0x42, level: W8 } → single-byte 0x42.
    let arena = [Term::Literal {
        value: 0x42,
        level: WittLevel::W8,
    }];
    let result = evaluate_term_tree::<ZeroHasher>(&arena, &[]).expect("literal evaluates");
    assert_eq!(result.bytes(), &[0x42][..]);
}

#[test]
fn application_add_combines_args() {
    // [Literal(2), Literal(3), Application(Add, [0..2])] → 5 (1 byte).
    let arena = [
        Term::Literal {
            value: 2,
            level: WittLevel::W8,
        },
        Term::Literal {
            value: 3,
            level: WittLevel::W8,
        },
        Term::Application {
            operator: PrimitiveOp::Add,
            args: TermList { start: 0, len: 2 },
        },
    ];
    let result = evaluate_term_tree::<ZeroHasher>(&arena, &[]).expect("addition evaluates");
    assert_eq!(result.bytes(), &[5u8][..]);
}

#[test]
fn hasher_projection_delegates_to_substitution_axis() {
    // Term::HasherProjection { input_index: 0 } applied to a Variable
    // input — the catamorphism reaches the Hasher axis and emits the
    // digest. ZeroHasher returns a fixed pattern so the assertion is
    // distinguishable from input bytes.
    let arena = [
        Term::Variable { name_index: 0 },
        Term::HasherProjection { input_index: 0 },
    ];
    let input = [0x11, 0x22, 0x33];
    let result =
        evaluate_term_tree::<ZeroHasher>(&arena, &input).expect("hash projection evaluates");
    // Per ADR-029, the hasher's OUTPUT_BYTES width prefix is taken.
    assert_eq!(result.bytes(), &[0xab, 0xcd, 0xef, 0x01][..]);
}

#[test]
fn term_value_carries_active_prefix_only() {
    // `TermValue::from_slice` copies up to `TERM_VALUE_MAX_BYTES` bytes
    // and reports the active prefix length via `bytes()`.
    let v = TermValue::from_slice(&[1, 2, 3, 4, 5]);
    assert_eq!(v.bytes(), &[1, 2, 3, 4, 5][..]);
    assert_eq!(v.bytes().len(), 5);
    let empty = TermValue::empty();
    assert_eq!(empty.bytes().len(), 0);
}
