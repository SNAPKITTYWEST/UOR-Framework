//! Smoke tests for the three SDK shape-constructor macros.
//!
//! Each test constructs a combined shape from two simple leaf shapes and
//! verifies the resulting `ConstrainedTypeShape` impl matches the amendment's
//! site-count / site-budget arithmetic.

use uor_foundation::pipeline::{
    CartesianProductShape, ConstrainedTypeShape, ConstraintRef, FoundationClosed, PrismModel,
    AFFINE_MAX_COEFFS,
};
use uor_foundation_sdk::{cartesian_product_shape, coproduct_shape, prism_model, product_shape};

// Leaf shapes — Phase 17 expanded the SDK operand-support catalogue
// to every ConstraintRef variant. Affine and Conjunction now compose
// correctly through the macros because the variants store fixed-size
// arrays the const-eval can build inline.

pub struct LeafA;
impl ConstrainedTypeShape for LeafA {
    const IRI: &'static str = "https://example.org/sdk-smoke/LeafA";
    const SITE_COUNT: usize = 2;
    // SITE_BUDGET defaults to SITE_COUNT.
    const CONSTRAINTS: &'static [ConstraintRef] = &[
        ConstraintRef::Site { position: 0 },
        ConstraintRef::Site { position: 1 },
    ];
}

pub struct LeafB;
impl ConstrainedTypeShape for LeafB {
    const IRI: &'static str = "https://example.org/sdk-smoke/LeafB";
    const SITE_COUNT: usize = 3;
    const CONSTRAINTS: &'static [ConstraintRef] = &[
        ConstraintRef::Site { position: 0 },
        ConstraintRef::Carry { site: 1 },
        ConstraintRef::Site { position: 2 },
    ];
}

// --- product_shape! -------------------------------------------------------

product_shape!(LeafATimesLeafB, LeafA, LeafB);

#[test]
fn product_shape_site_budgets_add() {
    // PT_1: siteBudget(A × B) = siteBudget(A) + siteBudget(B).
    assert_eq!(<LeafATimesLeafB as ConstrainedTypeShape>::SITE_BUDGET, 5);
    // Layout invariant ProductLayoutWidth: SITE_COUNTs add.
    assert_eq!(<LeafATimesLeafB as ConstrainedTypeShape>::SITE_COUNT, 5);
}

#[test]
fn product_shape_constraints_splice_with_shift() {
    let constraints = <LeafATimesLeafB as ConstrainedTypeShape>::CONSTRAINTS;
    assert_eq!(constraints.len(), 5);
    // A's constraints copied verbatim.
    assert!(matches!(
        constraints[0],
        ConstraintRef::Site { position: 0 }
    ));
    assert!(matches!(
        constraints[1],
        ConstraintRef::Site { position: 1 }
    ));
    // B's constraints shifted by A::SITE_COUNT = 2.
    assert!(matches!(
        constraints[2],
        ConstraintRef::Site { position: 2 }
    ));
    assert!(matches!(constraints[3], ConstraintRef::Carry { site: 3 }));
    assert!(matches!(
        constraints[4],
        ConstraintRef::Site { position: 4 }
    ));
}

#[test]
fn product_shape_canonicalized_iri() {
    // Operand canonicalization sorts by token string: LeafA < LeafB.
    assert_eq!(
        <LeafATimesLeafB as ConstrainedTypeShape>::IRI,
        "urn:uor:product:LeafA:LeafB"
    );
}

// --- coproduct_shape! -----------------------------------------------------

coproduct_shape!(LeafAPlusLeafB, LeafA, LeafB);

#[test]
fn coproduct_shape_site_budget_maxes() {
    // ST_1: siteBudget(A + B) = max(siteBudget(A), siteBudget(B)).
    assert_eq!(<LeafAPlusLeafB as ConstrainedTypeShape>::SITE_BUDGET, 3);
    // CoproductLayoutWidth: SITE_COUNT = max(SITE_COUNT(A), SITE_COUNT(B)) + 1.
    assert_eq!(<LeafAPlusLeafB as ConstrainedTypeShape>::SITE_COUNT, 4);
}

#[test]
fn coproduct_shape_emits_two_tag_pinners() {
    let constraints = <LeafAPlusLeafB as ConstrainedTypeShape>::CONSTRAINTS;
    // A's constraints (2) + A's tag-pinner (1) + B's constraints (3) + B's tag-pinner (1) = 7.
    assert_eq!(constraints.len(), 7);

    // Tag site is at max(SITE_COUNT(A), SITE_COUNT(B)) = 3.
    // A's tag-pinner comes after A's constraints at index 2.
    match constraints[2] {
        ConstraintRef::Affine {
            coefficients,
            coefficient_count: _,
            bias,
        } => {
            assert_eq!(bias, 0, "left variant tag-pinner carries bias 0");
            assert_eq!(coefficients[3], 1, "coefficient at tag_site = 1");
        }
        _ => panic!(
            "expected Affine tag-pinner at index 2, got {:?}",
            constraints[2]
        ),
    }

    // B's tag-pinner comes after B's constraints at index 6.
    match constraints[6] {
        ConstraintRef::Affine {
            coefficients,
            coefficient_count: _,
            bias,
        } => {
            assert_eq!(bias, -1, "right variant tag-pinner carries bias -1");
            assert_eq!(coefficients[3], 1, "coefficient at tag_site = 1");
        }
        _ => panic!(
            "expected Affine tag-pinner at index 6, got {:?}",
            constraints[6]
        ),
    }
}

#[test]
fn coproduct_shape_canonicalized_iri() {
    assert_eq!(
        <LeafAPlusLeafB as ConstrainedTypeShape>::IRI,
        "urn:uor:coproduct:LeafA:LeafB"
    );
}

// --- cartesian_product_shape! ---------------------------------------------

cartesian_product_shape!(LeafATensorLeafB, LeafA, LeafB);

#[test]
fn cartesian_product_shape_site_budgets_add() {
    // CPT_1: siteBudget(A ⊠ B) = siteBudget(A) + siteBudget(B).
    assert_eq!(<LeafATensorLeafB as ConstrainedTypeShape>::SITE_BUDGET, 5);
    // CartesianLayoutWidth: SITE_COUNTs add.
    assert_eq!(<LeafATensorLeafB as ConstrainedTypeShape>::SITE_COUNT, 5);
}

#[test]
fn cartesian_product_shape_implements_marker() {
    // The macro emits the CartesianProductShape marker impl so the
    // Künneth-Betti primitive is selected.
    fn require_marker<S: CartesianProductShape>() {}
    require_marker::<LeafATensorLeafB>();
}

#[test]
fn cartesian_product_shape_canonicalized_iri() {
    assert_eq!(
        <LeafATensorLeafB as ConstrainedTypeShape>::IRI,
        "urn:uor:cartesian:LeafA:LeafB"
    );
}

// --- Phase 17: Affine + Conjunction operand support ----------------------

const AFFINE_TWO_PLUS_THREE: ([i64; AFFINE_MAX_COEFFS], u32) = {
    let mut a = [0i64; AFFINE_MAX_COEFFS];
    a[0] = 2;
    a[1] = 3;
    (a, 2)
};

/// Leaf shape carrying an `Affine` constraint — pre-Phase-17 this would
/// have been unsupported by the SDK macros.
pub struct LeafAffine;
impl ConstrainedTypeShape for LeafAffine {
    const IRI: &'static str = "https://example.org/sdk-smoke/LeafAffine";
    const SITE_COUNT: usize = 2;
    const CONSTRAINTS: &'static [ConstraintRef] = &[ConstraintRef::Affine {
        coefficients: AFFINE_TWO_PLUS_THREE.0,
        coefficient_count: AFFINE_TWO_PLUS_THREE.1,
        bias: 0,
    }];
}

product_shape!(LeafAffineTimesLeafB, LeafAffine, LeafB);

#[test]
fn product_shape_supports_affine_operand() {
    // Pre-Phase-17 this expansion produced a `Site { position: u32::MAX }`
    // sentinel for the Affine constraint and the combined shape's
    // `validate_const()` rejected it. Post-Phase-17 the const-eval builds
    // a real shifted Affine — assert the constraint count covers L's
    // Affine + R's three constraints.
    let constraints = <LeafAffineTimesLeafB as ConstrainedTypeShape>::CONSTRAINTS;
    assert_eq!(constraints.len(), 4, "1 (L Affine) + 3 (R) = 4");
    // L's Affine pass-through (no shift since it's the first operand).
    match constraints[0] {
        ConstraintRef::Affine {
            coefficient_count, ..
        } => {
            assert_eq!(coefficient_count, 2, "L's affine prefix length preserved");
        }
        _ => panic!("expected Affine at index 0"),
    }
}

coproduct_shape!(LeafAffinePlusLeafB, LeafAffine, LeafB);

#[test]
fn coproduct_shape_supports_affine_operand() {
    let constraints = <LeafAffinePlusLeafB as ConstrainedTypeShape>::CONSTRAINTS;
    // L's Affine + L's tag-pinner + R's 3 + R's tag-pinner = 6.
    assert_eq!(constraints.len(), 6);
    match constraints[0] {
        ConstraintRef::Affine {
            coefficient_count, ..
        } => {
            assert_eq!(coefficient_count, 2, "L's Affine prefix length preserved");
        }
        _ => panic!("expected Affine at index 0"),
    }
    // L's tag-pinner at index 1.
    match constraints[1] {
        ConstraintRef::Affine {
            coefficient_count,
            bias,
            ..
        } => {
            assert!(coefficient_count > 0, "tag-pinner has non-zero prefix");
            assert_eq!(bias, 0, "L tag-pinner bias 0");
        }
        _ => panic!("expected Affine tag-pinner at index 1"),
    }
}

// =====================================================================
// `prism_model!` smoke tests — wiki ADR-020 + ADR-022 D3.
//
// These tests exercise the closure-bodied form: the macro parses the
// route function body as a Rust expression tree, maps recognised
// PrimitiveOp function calls to `Term::Application`, integer literals
// to `Term::Literal`, and the route's `input` parameter to
// `Term::Variable`. Anything else fails to compile (a closure violation
// per ADR-020).
//
// The test verifies the macro emits the four binding impls (D1 +
// D4 + D5) and that the parsed term arena is the value-level slice
// returned by `<Route as FoundationClosed>::arena_slice()`.

use uor_foundation::enforcement::{ConstrainedTypeInput, Hasher, Term};
use uor_foundation::{DefaultHostBounds, DefaultHostTypes, PrimitiveOp};

#[derive(Debug, Clone, Copy, Default)]
pub struct SmokeHasher;
impl Hasher for SmokeHasher {
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

prism_model! {
    pub struct AddTwoLiterals;
    pub struct AddTwoLiteralsRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for AddTwoLiterals {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = AddTwoLiteralsRoute;
        fn route(input: Self::Input) -> Self::Output {
            add(2, 3)
        }
    }
}

#[test]
fn prism_model_macro_emits_term_arena_for_simple_addition() {
    let arena = <AddTwoLiteralsRoute as FoundationClosed>::arena_slice();
    // `add(2, 3)` → [Literal(2), Literal(3), Application{Add, [0..2]}]
    assert_eq!(
        arena.len(),
        3,
        "three terms: two literals + one application"
    );
    match arena[0] {
        Term::Literal { value, .. } => assert_eq!(value, 2),
        other => panic!("expected Literal(2) at index 0, got {other:?}"),
    }
    match arena[1] {
        Term::Literal { value, .. } => assert_eq!(value, 3),
        other => panic!("expected Literal(3) at index 1, got {other:?}"),
    }
    match arena[2] {
        Term::Application { operator, args } => {
            assert!(matches!(operator, PrimitiveOp::Add));
            assert_eq!(args.start, 0);
            assert_eq!(args.len, 2);
        }
        other => panic!("expected Application{{Add, [0..2]}} at index 2, got {other:?}"),
    }
}

prism_model! {
    pub struct VariableThenSucc;
    pub struct VariableThenSuccRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for VariableThenSucc {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = VariableThenSuccRoute;
        fn route(input: Self::Input) -> Self::Output {
            succ(input)
        }
    }
}

#[test]
fn prism_model_macro_recognises_input_variable_and_unary_op() {
    let arena = <VariableThenSuccRoute as FoundationClosed>::arena_slice();
    // `succ(input)` → [Variable(0), Application{Succ, [0..1]}]
    assert_eq!(arena.len(), 2);
    match arena[0] {
        Term::Variable { name_index } => assert_eq!(name_index, 0),
        other => panic!("expected Variable at index 0, got {other:?}"),
    }
    match arena[1] {
        Term::Application { operator, args } => {
            assert!(matches!(operator, PrimitiveOp::Succ));
            assert_eq!(args.start, 0);
            assert_eq!(args.len, 1);
        }
        other => panic!("expected Application{{Succ, …}} at index 1, got {other:?}"),
    }
}

#[test]
fn prism_model_macro_satisfies_prism_model_bound() {
    // The macro emitted `impl PrismModel<H, B, A> for AddTwoLiterals` —
    // pin that the impl resolves at compile time.
    fn _accepts<M: PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher>>() {}
    _accepts::<AddTwoLiterals>();
    _accepts::<VariableThenSucc>();
    // Surface assertion: the bound check above is itself the test.
    assert_eq!(
        core::any::type_name::<
            <AddTwoLiterals as PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher>>::Route,
        >(),
        core::any::type_name::<AddTwoLiteralsRoute>(),
    );
}

// =====================================================================
// `output_shape!` smoke tests — wiki ADR-027.
//
// The macro emits the four sealed-trait impls (`__sdk_seal::Sealed`,
// `ConstrainedTypeShape`, `GroundedShape`, `IntoBindingValue`) so a
// custom Output shape qualifies as a `PrismModel::Output`.

use uor_foundation::enforcement::GroundedShape;
use uor_foundation::pipeline::IntoBindingValue;
use uor_foundation_sdk::output_shape;

output_shape! {
    pub struct OutputHashSmoke;
    impl ConstrainedTypeShape for OutputHashSmoke {
        const IRI: &'static str = "https://example.org/sdk-smoke/OutputHash";
        const SITE_COUNT: usize = 32;
        const CONSTRAINTS: &'static [ConstraintRef] = &[];
    }
}

#[test]
fn output_shape_emits_constrained_type_shape_impl() {
    assert_eq!(<OutputHashSmoke as ConstrainedTypeShape>::SITE_COUNT, 32);
    assert!(<OutputHashSmoke as ConstrainedTypeShape>::IRI.contains("OutputHash"));
}

#[test]
fn output_shape_emits_grounded_shape_impl() {
    fn _accepts<T: GroundedShape>() {}
    _accepts::<OutputHashSmoke>();
}

#[test]
fn output_shape_emits_into_binding_value_with_max_bytes_equals_site_count() {
    assert_eq!(<OutputHashSmoke as IntoBindingValue>::MAX_BYTES, 32);
}

#[test]
fn output_shape_qualifies_as_prism_model_output() {
    fn _accepts<T: ConstrainedTypeShape + GroundedShape + IntoBindingValue>() {}
    _accepts::<OutputHashSmoke>();
}

// =====================================================================
// `verb!` smoke tests — wiki ADR-024 Layer-3 implementation closure.
//
// The macro emits a const term-tree fragment (`VERB_TERMS_<NAME>`), a
// public accessor (`<name>_term_arena`), and a marker function
// (`<name>(input)`). When `prism_model!` invokes the verb by name in
// a route's closure body, the macro inlines the verb's fragment into
// the host arena at compile time via foundation's
// `inline_verb_fragment` const-fn helper — verb-graph acyclicity is
// a compile-time commitment, not a runtime guard.

use uor_foundation_sdk::verb;

verb! {
    pub fn smoke_succ(input: ConstrainedTypeInput) -> ConstrainedTypeInput {
        succ(input)
    }
}

#[test]
fn verb_macro_emits_term_arena_const() {
    let arena = smoke_succ_term_arena();
    // `succ(input)` → [Variable, Application{Succ, [0..1]}]
    assert_eq!(arena.len(), 2);
    assert!(matches!(arena[0], Term::Variable { name_index: 0 }));
    match arena[1] {
        Term::Application { operator, args } => {
            assert!(matches!(operator, PrimitiveOp::Succ));
            assert_eq!(args.start, 0);
            assert_eq!(args.len, 1);
        }
        other => panic!("expected Application(Succ) at index 1, got {other:?}"),
    }
}

#[test]
fn verb_macro_const_is_publicly_visible() {
    // The `pub const VERB_TERMS_SMOKE_SUCC` is exported so prism_model!
    // can reference it when inlining via inline_verb_fragment (ADR-024).
    let arena = VERB_TERMS_SMOKE_SUCC;
    assert_eq!(arena.len(), 2);
}

// `prism_model!` inlines the verb's term-tree fragment into the host
// arena at compile time when the closure body invokes a verb declared
// in the same module (wiki ADR-024).
prism_model! {
    pub struct VerbInvokingModel;
    pub struct VerbInvokingRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for VerbInvokingModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = VerbInvokingRoute;
        fn route(input: Self::Input) -> Self::Output {
            smoke_succ(input)
        }
    }
}

#[test]
fn prism_model_inlines_verb_fragment_for_local_verb_call() {
    let arena = <VerbInvokingRoute as FoundationClosed>::arena_slice();
    // After ADR-024 reconciliation, the route's arena is fully flat:
    // the verb's fragment is inlined at compile time. `smoke_succ(input)`
    // builds:
    //   [0] Variable(0)              (host's emission of `input`, the verb's argument)
    //   [1] Variable(0)              (verb's body Variable, spliced + shifted)
    //   [2] Application(Succ,[1..2]) (verb's body Application, with args.start shifted)
    //
    // The arena contains exactly 10-Term-variant nodes — no
    // `Term::VerbReference` (eleventh variant was removed).
    assert_eq!(arena.len(), 1 + VERB_TERMS_SMOKE_SUCC.len());
    // No VerbReference in the arena: every entry is one of the ten
    // ADR-029 variants.
    for (i, t) in arena.iter().enumerate() {
        match t {
            Term::Literal { .. }
            | Term::Variable { .. }
            | Term::Application { .. }
            | Term::Lift { .. }
            | Term::Project { .. }
            | Term::Match { .. }
            | Term::Recurse { .. }
            | Term::Unfold { .. }
            | Term::Try { .. }
            | Term::HasherProjection { .. } => {}
        }
        let _ = i;
    }
    // The verb's last term (Application(Succ)) is the route's tail —
    // it sits at the arena's last position as the route's evaluation
    // root. Its args.start references the spliced Variable at the
    // host's offset (= 1, after the host's `input` emission).
    match arena.last().expect("non-empty arena") {
        Term::Application { operator, args } => {
            assert!(matches!(operator, PrimitiveOp::Succ));
            assert_eq!(args.start, 1u32, "verb's args.start shifted by host offset");
            assert_eq!(args.len, 1);
        }
        other => panic!("expected Application(Succ) as arena tail, got {other:?}"),
    }
}

// =====================================================================
// Closure-body grammar extensions G4 (Lift), G5 (Project), G10 (let).

use uor_foundation::WittLevel;

prism_model! {
    pub struct LiftToW16Model;
    pub struct LiftToW16Route;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for LiftToW16Model {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = LiftToW16Route;
        fn route(input: Self::Input) -> Self::Output {
            lift::<WittLevel::W16>(input)
        }
    }
}

#[test]
fn prism_model_emits_lift_term_for_g4_lift_form() {
    let arena = <LiftToW16Route as FoundationClosed>::arena_slice();
    // `lift::<W16>(input)` → [Variable, Lift { operand: 0, target: W16 }]
    assert_eq!(arena.len(), 2);
    assert!(matches!(arena[0], Term::Variable { name_index: 0 }));
    match arena[1] {
        Term::Lift {
            operand_index,
            target,
        } => {
            assert_eq!(operand_index, 0);
            assert!(
                matches!(target, WittLevel::W16),
                "expected target W16, got {target:?}",
            );
        }
        other => panic!("expected Term::Lift at index 1, got {other:?}"),
    }
}

prism_model! {
    pub struct ProjectToW8Model;
    pub struct ProjectToW8Route;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for ProjectToW8Model {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = ProjectToW8Route;
        fn route(input: Self::Input) -> Self::Output {
            project::<WittLevel::W8>(input)
        }
    }
}

#[test]
fn prism_model_emits_project_term_for_g5_project_form() {
    let arena = <ProjectToW8Route as FoundationClosed>::arena_slice();
    assert_eq!(arena.len(), 2);
    match arena[1] {
        Term::Project {
            operand_index,
            target,
        } => {
            assert_eq!(operand_index, 0);
            assert!(matches!(target, WittLevel::W8));
        }
        other => panic!("expected Term::Project at index 1, got {other:?}"),
    }
}

prism_model! {
    pub struct LetBindingModel;
    pub struct LetBindingRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for LetBindingModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = LetBindingRoute;
        fn route(input: Self::Input) -> Self::Output {
            let two = 2;
            add(two, 3)
        }
    }
}

#[test]
fn prism_model_emits_term_arena_for_g10_let_binding() {
    let arena = <LetBindingRoute as FoundationClosed>::arena_slice();
    // `let two = 2; add(two, 3)` → [Literal(2), Literal(3), Application(Add, [0..2])]
    // The let-binding doesn't emit its own Term node; references to
    // `two` resolve to the Literal(2) root via the binding scope (G10).
    assert_eq!(arena.len(), 3);
    match arena[0] {
        Term::Literal { value, .. } => assert_eq!(value, 2),
        other => panic!("expected Literal(2) at index 0, got {other:?}"),
    }
    match arena[1] {
        Term::Literal { value, .. } => assert_eq!(value, 3),
        other => panic!("expected Literal(3) at index 1, got {other:?}"),
    }
    match arena[2] {
        Term::Application { operator, args } => {
            assert!(matches!(operator, PrimitiveOp::Add));
            assert_eq!(args.start, 0);
            assert_eq!(args.len, 2);
        }
        other => panic!("expected Application(Add) at index 2, got {other:?}"),
    }
}

// =====================================================================
// Closure-body grammar G6 (match), G7 (recurse), G8 (unfold), G9 (?).

prism_model! {
    pub struct TryPropagateModel;
    pub struct TryPropagateRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for TryPropagateModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = TryPropagateRoute;
        fn route(input: Self::Input) -> Self::Output {
            succ(input)?
        }
    }
}

#[test]
fn prism_model_emits_try_term_for_g9_postfix_question() {
    let arena = <TryPropagateRoute as FoundationClosed>::arena_slice();
    // `succ(input)?` → [Variable, Application(Succ), Try{body=1, handler=u32::MAX}]
    assert_eq!(arena.len(), 3);
    match arena[2] {
        Term::Try {
            body_index,
            handler_index,
        } => {
            assert_eq!(body_index, 1);
            assert_eq!(handler_index, u32::MAX);
        }
        other => panic!("expected Try at index 2, got {other:?}"),
    }
}

prism_model! {
    pub struct RecurseModel;
    pub struct RecurseRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for RecurseModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = RecurseRoute;
        fn route(input: Self::Input) -> Self::Output {
            recurse(input, 0, |self_call| succ(self_call))
        }
    }
}

#[test]
fn prism_model_emits_recurse_term_for_g7_form() {
    let arena = <RecurseRoute as FoundationClosed>::arena_slice();
    // The arena ends with Term::Recurse pointing at the measure, base, and step roots.
    let last = arena.last().expect("non-empty arena");
    assert!(matches!(last, Term::Recurse { .. }));
}

prism_model! {
    pub struct UnfoldModel;
    pub struct UnfoldRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for UnfoldModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = UnfoldRoute;
        fn route(input: Self::Input) -> Self::Output {
            unfold(input, |state| succ(state))
        }
    }
}

#[test]
fn prism_model_emits_unfold_term_for_g8_form() {
    let arena = <UnfoldRoute as FoundationClosed>::arena_slice();
    assert!(matches!(arena.last(), Some(Term::Unfold { .. })));
}

prism_model! {
    pub struct FoldNUnrolledModel;
    pub struct FoldNUnrolledRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for FoldNUnrolledModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = FoldNUnrolledRoute;
        fn route(input: Self::Input) -> Self::Output {
            fold_n(3, input, |state, idx| add(state, idx))
        }
    }
}

#[test]
fn prism_model_unrolls_fold_n_for_const_count_below_threshold() {
    let arena = <FoldNUnrolledRoute as FoundationClosed>::arena_slice();
    // fold_n(3, input, |state, idx| add(state, idx)) unrolls into:
    //   iter 0: add(input, 0)
    //   iter 1: add(<iter 0 result>, 1)
    //   iter 2: add(<iter 1 result>, 2)
    // The arena ends with the iter-2 Application(Add).
    assert!(matches!(
        arena.last(),
        Some(Term::Application {
            operator: PrimitiveOp::Add,
            ..
        })
    ));
    // Three Application(Add) entries — one per iteration.
    let add_count = arena
        .iter()
        .filter(|t| {
            matches!(
                t,
                Term::Application {
                    operator: PrimitiveOp::Add,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        add_count, 3,
        "fold_n(3, …) unrolls into 3 Application(Add) chains"
    );
}

prism_model! {
    pub struct MatchModel;
    pub struct MatchRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for MatchModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = MatchRoute;
        fn route(input: Self::Input) -> Self::Output {
            match input {
                0 => 1,
                _ => succ(input),
            }
        }
    }
}

#[test]
fn prism_model_emits_match_term_for_g6_form() {
    let arena = <MatchRoute as FoundationClosed>::arena_slice();
    let last = arena.last().expect("non-empty arena");
    match last {
        Term::Match { arms, .. } => {
            // Two arms × 2 entries each = 4 entries in the arms span.
            assert_eq!(
                arms.len, 4,
                "expected 4 arms entries (2 arms × pattern+body)"
            );
        }
        other => panic!("expected Term::Match as root, got {other:?}"),
    }
}

// =====================================================================
// `use_verbs!` smoke test.

mod inner_verb_module {
    use uor_foundation::enforcement::ConstrainedTypeInput;
    use uor_foundation_sdk::verb;

    verb! {
        pub fn inner_verb(input: ConstrainedTypeInput) -> ConstrainedTypeInput {
            succ(input)
        }
    }
}

uor_foundation_sdk::use_verbs! {
    from inner_verb_module {
        inner_verb,
    };
}

// =====================================================================
// Closure-body grammar G13 (parallel), G15 (tree_fold), G16 (first_admit).

prism_model! {
    pub struct ParallelComposeModel;
    pub struct ParallelComposeRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for ParallelComposeModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = ParallelComposeRoute;
        fn route(input: Self::Input) -> Self::Output {
            parallel(succ(input), pred(input))
        }
    }
}

#[test]
fn prism_model_emits_parallel_term_for_g13_form() {
    let arena = <ParallelComposeRoute as FoundationClosed>::arena_slice();
    // `parallel(succ(input), pred(input))` lowers to a binary
    // Application(Or, [succ(input), pred(input)]) — the partition-product
    // structural combine per ADR-026 G13.
    let last = arena.last().expect("non-empty arena");
    match last {
        Term::Application { operator, args } => {
            assert!(matches!(operator, PrimitiveOp::Or));
            assert_eq!(args.len, 2, "parallel emits 2-arg structural combine");
        }
        other => panic!("expected Application(Or) as parallel root, got {other:?}"),
    }
}

prism_model! {
    pub struct TreeFoldModel;
    pub struct TreeFoldRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for TreeFoldModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = TreeFoldRoute;
        fn route(input: Self::Input) -> Self::Output {
            tree_fold(add, [1, 2, 3, 4])
        }
    }
}

#[test]
fn prism_model_emits_tree_fold_pairwise_chain_for_g15_form() {
    let arena = <TreeFoldRoute as FoundationClosed>::arena_slice();
    // tree_fold(add, [1, 2, 3, 4]) → balanced tree of depth 2:
    //   add(add(1, 2), add(3, 4))
    // Three Application(Add) entries (two leaf-level + one root).
    let add_count = arena
        .iter()
        .filter(|t| {
            matches!(
                t,
                Term::Application {
                    operator: PrimitiveOp::Add,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        add_count, 3,
        "tree_fold(add, [a,b,c,d]) → 3 Application(Add) entries"
    );
    // Last term is the root reducer Application.
    assert!(matches!(
        arena.last(),
        Some(Term::Application {
            operator: PrimitiveOp::Add,
            ..
        })
    ));
}

prism_model! {
    pub struct FirstAdmitModel;
    pub struct FirstAdmitRoute;
    impl PrismModel<DefaultHostTypes, DefaultHostBounds, SmokeHasher> for FirstAdmitModel {
        type Input = ConstrainedTypeInput;
        type Output = ConstrainedTypeInput;
        type Route = FirstAdmitRoute;
        fn route(input: Self::Input) -> Self::Output {
            first_admit(W8, |i| succ(i))
        }
    }
}

#[test]
fn prism_model_emits_recurse_term_for_g16_first_admit() {
    let arena = <FirstAdmitRoute as FoundationClosed>::arena_slice();
    // first_admit(W8, |i| succ(i)) → Term::Recurse with measure (Literal),
    // base (Literal(0)), and step (predicate body).
    let last = arena.last().expect("non-empty arena");
    assert!(matches!(last, Term::Recurse { .. }));
}

// =====================================================================
// `partition_product!` and `partition_coproduct!` smoke tests
// — wiki ADR-026 G17/G18 architectural-name macros (variadic, named
// stable-Rust form per CLAUDE.md mapping).

use uor_foundation_sdk::{partition_coproduct, partition_product};

partition_product!(LeafAPpLeafB, LeafA, LeafB);

#[test]
fn partition_product_macro_matches_pt3_canonical_join() {
    // partition_product!(N, A, B) emits the same structure as
    // product_shape!(N, A, B) — PT_3 canonical-joined CONSTRAINTS,
    // SITE_COUNT = A::SITE_COUNT + B::SITE_COUNT.
    assert_eq!(<LeafAPpLeafB as ConstrainedTypeShape>::SITE_BUDGET, 5);
    assert_eq!(<LeafAPpLeafB as ConstrainedTypeShape>::SITE_COUNT, 5);
    assert!(<LeafAPpLeafB as ConstrainedTypeShape>::IRI.starts_with("urn:uor:product:"));
}

partition_coproduct!(LeafAPcLeafB, LeafA, LeafB);

#[test]
fn partition_coproduct_macro_matches_st10_structure() {
    assert_eq!(<LeafAPcLeafB as ConstrainedTypeShape>::SITE_BUDGET, 3);
    assert_eq!(<LeafAPcLeafB as ConstrainedTypeShape>::SITE_COUNT, 4);
    assert!(<LeafAPcLeafB as ConstrainedTypeShape>::IRI.starts_with("urn:uor:coproduct:"));
}

#[test]
fn partition_product_macro_emits_grounded_shape_and_into_binding_value() {
    fn _accepts<T: ConstrainedTypeShape + GroundedShape + IntoBindingValue>() {}
    _accepts::<LeafAPpLeafB>();
    _accepts::<LeafAPcLeafB>();
}

// Variadic 3-operand form folds left-associatively.
partition_product!(LeafThreeWayPp, LeafA, LeafB, LeafA);

#[test]
fn partition_product_variadic_3_operands_folds_left_associatively() {
    // ((A × B) × A) → SITE_COUNT = (2 + 3) + 2 = 7.
    assert_eq!(<LeafThreeWayPp as ConstrainedTypeShape>::SITE_COUNT, 7);
}

// =====================================================================
// `use_verbs!` smoke test (continued).

#[test]
fn use_verbs_re_exports_verb_const_and_accessor() {
    // The re-exported const matches the original module's const.
    assert_eq!(
        VERB_TERMS_INNER_VERB.len(),
        inner_verb_module::VERB_TERMS_INNER_VERB.len(),
    );
    // The re-exported accessor returns the same fragment.
    let arena = inner_verb_term_arena();
    assert_eq!(arena.len(), 2);
    assert!(matches!(arena[0], Term::Variable { name_index: 0 }));
}
