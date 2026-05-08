//! Behavioral contract for the catamorphism's evaluation depth limit
//! (wiki ADR-024 verb-graph acyclicity, runtime expression).
//!
//! Per ADR-024 the verb-reference graph through non-`Recurse` operators
//! MUST be acyclic. The `verb!` SDK macro performs a local
//! self-reference check at expansion time; cross-verb cycles bottom out
//! at the catamorphism's `EVALUATE_TERM_TREE_DEPTH_LIMIT` bound,
//! surfacing a typed `PipelineFailure::ShapeViolation` rather than
//! overflowing the host stack.

use uor_foundation::enforcement::{Hasher, Term, TermList};
use uor_foundation::pipeline::{evaluate_term_tree, EVALUATE_TERM_TREE_DEPTH_LIMIT};
use uor_foundation::{PipelineFailure, PrimitiveOp};

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
        [0u8; 32]
    }
}

#[test]
fn depth_limit_is_public_foundation_constant() {
    // ADR-024's runtime expression of verb-graph acyclicity. The
    // specific value is a foundation parameter; the architectural
    // commitment is that the constant exists and is enforced.
    assert_eq!(EVALUATE_TERM_TREE_DEPTH_LIMIT, 256);
}

#[test]
fn evaluator_rejects_cyclic_term_arena() {
    // Build a cyclic term arena: a `Term::Application { Succ, [0..1] }`
    // whose arg index points to itself (index 0). The catamorphism
    // descends into the application's arg, which is the same node, ad
    // infinitum. The depth limit bounds the descent and returns a
    // typed ShapeViolation rather than overflowing the host stack.
    let arena = [Term::Application {
        operator: PrimitiveOp::Succ,
        args: TermList { start: 0, len: 1 },
    }];
    let result = evaluate_term_tree::<ZeroHasher>(&arena, b"input");
    match result {
        Err(PipelineFailure::ShapeViolation { report }) => {
            assert!(
                report.shape_iri.contains("EvaluationDepth"),
                "expected EvaluationDepthShape violation, got {}",
                report.shape_iri,
            );
            assert_eq!(
                report.max_count as usize, EVALUATE_TERM_TREE_DEPTH_LIMIT,
                "violation report carries the depth-limit ceiling",
            );
        }
        Ok(value) => panic!(
            "expected depth-limit violation, got Ok({:?})",
            value.bytes()
        ),
        Err(other) => panic!("expected ShapeViolation, got {other:?}"),
    }
}
