# CLAUDE.md — UOR-Framework

## Project overview

Rust workspace encoding the UOR Foundation ontology as typed data structures, a generated `#![no_std]` trait crate (`uor-foundation`), and validated serializations (JSON-LD, Turtle, N-Triples, OWL RDF/XML, JSON Schema, SHACL Shapes, EBNF). All source code, documentation, and web artifacts are machine-generated from the authoritative ontology defined in `spec/`.

## Authoritative source

The authoritative source for `uor-foundation` is the project wiki: <https://github.com/UOR-Foundation/UOR-Framework/wiki>. Consult it for canonical definitions, design rationale, and ontology semantics; treat it as the source of truth when wiki content and other docs disagree.

The wiki specifies **Prism**, realized by three crates: `uor-foundation` (substrate), `prism` (runtime), `prism-verify` (replay surface). The current workspace co-locates substrate + runtime inside `uor-foundation` and exposes the replay surface as `uor-foundation-verify` (the wiki's `prism-verify` under a legacy name). When evolving the implementation toward the wiki, prefer making `uor-foundation` *scalable along the wiki's substitution axes* over the cosmetic crate-renaming.

## Substitution axes (wiki §2 + ADR-007 + ADR-018)

The wiki names three substitution axes the application author selects against:

| Axis | Trait (in `uor-foundation`) | What the application varies |
|---|---|---|
| `HostTypes` | `pub trait HostTypes` ([foundation/src/lib.rs](foundation/src/lib.rs)) | Host-environment representations: `Decimal`, `HostString`, `WitnessBytes`. Default impl: `DefaultHostTypes`. |
| `HostBounds` | `pub trait HostBounds` ([foundation/src/lib.rs](foundation/src/lib.rs)) | Every capacity bound that varies along the principal data path (wiki ADR-018): fingerprint output width range, trace event-count ceiling, algebraic-level bit-width ceiling. Default impl: `DefaultHostBounds` (16/32/256/64). |
| `Hasher` | `pub trait Hasher<const FP_MAX: usize = 32>` ([foundation/src/enforcement.rs](foundation/src/enforcement.rs)) | Content-addressing function; the const-generic carries the application's selected `HostBounds::FINGERPRINT_MAX_BYTES`. No default impl — application supplies a substrate (BLAKE3 recommended). |

### How `HostBounds` flows through the type system (stable Rust 1.83)

ADR-018 mandates that "every signature in `prism`'s and `uor-foundation`'s public API that admits a value with a capacity-bounded width parameterizes that width through the application's selected `HostBounds`." The wiki's example pattern `[u8; H::FINGERPRINT_MAX_BYTES]` requires nightly `generic_const_exprs`. On stable Rust 1.83 (the workspace MSRV, matching the sibling [`UOR-Foundation/prism`](https://github.com/UOR-Foundation/prism) repo), the equivalent is **min-const-generics**: capacity-bearing types carry a `<const N: usize>` parameter, and applications populate it with `<MyBounds as HostBounds>::CONST` at instantiation sites.

The carriers:

| Type | Const-generic | Default | Sourced from |
|---|---|---|---|
| `Hasher<const FP_MAX: usize = 32>` | fingerprint output buffer width | 32 | `<DefaultHostBounds as HostBounds>::FINGERPRINT_MAX_BYTES` |
| `ContentFingerprint<const FP_MAX: usize = 32>` | inline fingerprint buffer width | 32 | same |
| `Trace<const TR_MAX: usize = 256>` | inline event-count ceiling | 256 | `<DefaultHostBounds as HostBounds>::TRACE_MAX_EVENTS` |

Applications using `DefaultHostBounds` reach these types under their default const-generic and never write turbofish. Applications selecting a different `HostBounds` impl write e.g. `ContentFingerprint::<64>` or `Trace::<1024>` and the type system propagates. Capacity-bearing functions (`Derivation::replay`, `replay::certify_from_trace`, `unit_address_from_buffer`, the `__test_helpers::trace_*` ctors) carry the matching const-generic on the function itself; type-annotated bindings or turbofish populate the parameter from the application's `HostBounds`.

`TRACE_REPLAY_FORMAT_VERSION` stays foundation-fixed (wiki ADR-018 carve-out for wire-format identifiers — cross-implementation interop requires a single shared value).

There are no free-standing `FINGERPRINT_MIN_BYTES` / `FINGERPRINT_MAX_BYTES` / `TRACE_MAX_EVENTS` constants on `uor-foundation`'s public surface — collapsing the substitution axis is exactly what ADR-018's "Rejected alternative 1" rules out. Applications and downstream crates (including [`uor-prism`](https://github.com/UOR-Foundation/prism)) read capacities through `<MyBounds as HostBounds>::CONST`.

## Categorical structure (wiki ADR-019)

`uor-foundation`'s vocabulary is the **signature category** of Prism's typed routes. The vocabulary names the structure explicitly:

| Concept | Realization |
|---|---|
| Signature endofunctor F | The nine [`enforcement::Term`](foundation/src/enforcement.rs) variants — `Literal`, `Application`, `Lift`, `Project`, `Variable`, `Match`, `Recurse`, `Unfold`, `Try` |
| Initial algebra of F | [`enforcement::Term`](foundation/src/enforcement.rs) itself — the free term language F generates |
| Catamorphism into the runtime carrier | [`pipeline::run`](foundation/src/pipeline.rs) — unique homomorphism induced by initiality |
| Anamorphism's witness object | `Trace` — produced by [`enforcement::Derivation::replay`](foundation/src/enforcement.rs) and consumed by [`enforcement::replay::certify_from_trace`](foundation/src/enforcement.rs) |
| Fixed points of the typed pipeline endofunctor | The four UOR-domain sealed types (`Datum`, `Triad`, `Derivation`, `FreeRank`) and three Prism-mechanism sealed types (`Validated`, `Grounded`, `Certified`) |

Initiality and uniqueness of the catamorphism hold *within each fixed choice of the three substitution axes* (`HostTypes`, `HostBounds`, `Hasher`). ADR-018's capacity-completeness — "the indexing of carriers is total over `HostBounds`" — is the categorical statement that every capacity-bounded width is part of the index. Closure (ADR-013) and zero-cost runtime (TC-01) are two halves of the same theorem: closure is the precondition that makes F's signature complete; completeness lets the catamorphism be discharged at the application's compile time, with no runtime indirection.

## `PrismModel` — the application author's typed iso (wiki ADR-020)

[`pipeline::PrismModel`](foundation/src/pipeline.rs) codifies the application author's typed-iso contract:

```rust
pub trait PrismModel {
    type Input: ConstrainedTypeShape;
    type Output: ConstrainedTypeShape + GroundedShape;
    type Route: FoundationClosed;
    fn forward(input: Self::Input) -> Result<Grounded<Self::Output>, PipelineFailure>;
}
```

`Route` is a type-level witness of the term tree mapping `Input` to `Output`; the `FoundationClosed` bound enforces closure under foundation vocabulary at the application's compile time per UORassembly (TC-04, ADR-006). [`pipeline::FoundationClosed`](foundation/src/pipeline.rs) is sealed via a private super-trait — only foundation itself sanctions impls (e.g., `ConstrainedTypeInput` as the identity route) and the `prism_model!` proc-macro from [`uor-foundation-sdk`](uor-foundation-sdk/) emits impls on the witness it generates iff every node is a foundation-vocabulary item. A hand-rolled composition that escapes foundation vocabulary fails to compile with an unsatisfied bound on `Route`.

`forward()` is the catamorphism into [`pipeline::run`](foundation/src/pipeline.rs)'s runtime carrier (per ADR-019); together with the trace-witnessed anamorphism through [`enforcement::replay::certify_from_trace`](foundation/src/enforcement.rs) it forms the verifiable round-trip described in the wiki. Application authors do not write `forward`'s body — the `prism_model!` macro derives it from the syntactic Route declaration via initiality of `Term`.

## Workspace layout

| Crate | Path | Published | Purpose |
|---|---|---|---|
| `uor-ontology` | `spec/` | no | Ontology source of truth (classes, properties, individuals, serializers) |
| `uor-codegen` | `codegen/` | no | Ontology-to-Rust trait generator |
| `uor-foundation` | `foundation/` | **crates.io** | Generated `#![no_std]` trait library — never edit manually |
| `uor-foundation-sdk` | `uor-foundation-sdk/` | **crates.io** (pending first release) | Procedural-macro ergonomics (`product_shape!`, `coproduct_shape!`, `cartesian_product_shape!`) for composing `ConstrainedTypeShape` operands — emitted by `uor-crate` from `codegen/src/sdk_macros.rs`. |
| `uor-foundation-verify` | `uor-foundation-verify/` | **crates.io** (pending) | Trace-replay verifier — thin façade re-exporting `certify_from_trace`, `Certified`, the wire-format types, and the `HostBounds` substitution axis. Wiki name: `prism-verify`. |
| `uor-conformance` | `conformance/` | no | Conformance suite (OWL, SHACL, RDF, Rust API, docs, website) — check count in `spec/src/counts.rs` |
| `uor-docs` | `docs/` | no | Documentation generator |
| `uor-website` | `website/` | no | Static site generator |
| `uor-lean-codegen` | `lean-codegen/` | no | Ontology-to-Lean 4 structure generator |
| `uor-clients` | `clients/` | no | CLI binaries: `uor-build`, `uor-crate`, `uor-lean`, `uor-docs`, `uor-website`, `uor-conformance` |
| `cargo-uor` | `cargo-uor/` | no | Cargo subcommand binary for UOR tooling |

## Critical rules

- **Never hand-edit `foundation/src/` or `lean4/`** — they are regenerated from `spec/` by `uor-crate` and `uor-lean`. CI enforces `git diff --exit-code` on both.
  - **Exception (Phase 11):** `foundation/src/blanket_impls.rs` is hand-written and starts with `// @codegen-exempt`. The codegen `emit::write_file` preserves files carrying that banner; the `rust/blanket_impls_exempt` conformance gate enforces both the banner and the required Path-3 blanket impls.
- **On release**, Lean 4 cloud release builds are uploaded via `lake upload`. Lean Reservoir indexes this repo directly (root `lakefile.lean` + `lake-manifest.json`).
- **All clippy warnings are errors.** CI runs `cargo clippy --all-targets -- -D warnings`.
- **Every crate denies:** `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `missing_docs`, `clippy::missing_errors_doc`.
- **Formatting is enforced.** CI runs `cargo fmt --check`.
- **The conformance suite must pass.** `cargo run --bin uor-conformance` — zero failures allowed (check count in `spec/src/counts.rs`).
- **No `unsafe` code.** The `uor-foundation` crate is `#![no_std]` with zero dependencies.
- **Bracket-escape doc comments.** Use `normalize_comment()` to prevent rustdoc intra-doc link warnings on `[text]` in comments.

## Build commands

```sh
cargo fmt --check                    # Format check
cargo clippy --all-targets -- -D warnings  # Lint
cargo test                           # Unit + integration tests
cargo run --bin uor-crate            # Regenerate foundation/src/ from spec/
cargo run --bin uor-lean             # Regenerate lean4/ from spec/
cargo run --bin uor-build            # Emit JSON-LD, Turtle, N-Triples to public/
cargo run --bin uor-docs             # Generate documentation site
cargo run --bin uor-website          # Generate website
cargo run --bin uor-conformance      # Run full conformance suite
```

Docs/website/conformance binaries accept `PUBLIC_BASE_PATH` env var for URL prefixing.

## CI pipeline (in order)

`cargo fmt --check` → `cargo clippy` → `cargo test` → `cargo run --bin uor-crate` → `git diff --exit-code foundation/src/ uor-foundation-sdk/src/` → `cargo check -p uor-foundation --no-default-features` → `cargo publish --dry-run` (uor-foundation + uor-foundation-sdk) → `uor-lean` → `git diff --exit-code lean4/` → `uor-build` → `uor-docs` → `uor-website` → `uor-conformance` → deploy pages

## Ontology architecture

Counts below are mirrored from `spec/src/counts.rs`, which is the single source of truth.

- **34 namespaces**, assembly order: `u → schema → op → query → resolver → type → partition → foundation → observable → carry → homology → cohomology → proof → derivation → trace → cert → morphism → state → reduction → convergence → division → interaction → monoidal → operad → effect → predicate → parallel → stream → failure → linear → recursion → region → boundary → conformance`
- **Space classification:** Kernel (17: `u`, `schema`, `op`, `carry`, `reduction`, `convergence`, `division`, `monoidal`, `operad`, `effect`, `predicate`, `parallel`, `stream`, `failure`, `linear`, `recursion`, `region`), Bridge (14: `query`, `resolver`, `partition`, `foundation`, `observable`, `homology`, `cohomology`, `proof`, `derivation`, `trace`, `cert`, `interaction`, `boundary`, `conformance`), User (`type`, `morphism`, `state`)
- **471 classes** → 452 traits + 19 enum classes (includes WittLevel newtype struct)
- **948 properties** → 911 trait methods (generic over `P: Primitives`)
- **3554 named individuals** → 3541 constant modules
- **19 enum classes:** `AchievabilityStatus`, `ComplexityClass`, `ExecutionPolicyKind`, `GeometricCharacter`, `GroundingPhase`, `MeasurementUnit`, `MetricAxis`, `PartitionComponent`, `PhaseBoundaryType`, `ProofStrategy`, `QuantifierKind`, `RewriteRule`, `SessionBoundaryType`, `TriadProjection`, `ValidityScopeKind`, `VarianceAnnotation`, `VerificationDomain`, `ViolationKind`, `WittLevel`

## Code generation patterns

- All traits are generic over `P: Primitives` (no hardcoded XSD types)
- Enum classes are detected by `detect_vocabulary_enum()` and skip trait generation; WittLevel is a struct (not enum) but also skips trait generation
- `object_property_enum_override()` maps ObjectProperties to enum/struct return types (delegates to `enum_class_names()`)
- Multi-value IriRef properties on individuals → `&[&str]` slices via `BTreeMap` grouping
- `RustFile::finish()` trims trailing whitespace to match `cargo fmt`
- Module declarations in `mod.rs` are sorted alphabetically
- Cross-namespace domain properties and enum-class domain properties are not generated

## Lean 4 code generation patterns

- All structures are parametric over `(P : Primitives)` — mirrors the Rust `<P: Primitives>` generic
- OWL classes → `structure` (not `class`); only `Primitives` uses `class` (genuine typeclass)
- Enum classes → `inductive` with `deriving DecidableEq, Repr, BEq, Hashable, Inhabited`
- WittLevel → `structure` (open-world, not `inductive`)
- Self-referential properties → `Option` wrapping for functional, `Array` for non-functional
- Inheritance → `extends ParentA P, ParentB P`; cross-namespace uses qualified `UOR.Space.Module.ClassName P`
- Non-functional properties → `Array` type (idiomatic Lean 4)
- Lean keyword escaping → guillemets `«keyword»` (e.g., `«type»`)
- Individual constants → `namespace name ... end name` blocks with `def` constants
- Cross-namespace domain properties are NOT generated (same rule as Rust codegen)
- Import DAG follows the ontology assembly order (acyclic)
- `autoImplicit = false` in lakefile prevents implicit variable surprises

## Conformance categories

1. **Rust source** — formatting, line width, public API surface
2. **Ontology inventory** — exact namespace/class/property/individual counts
3. **JSON-LD 1.1** — `@context`, `@graph`, non-functional property arrays
4. **OWL 2 DL** — disjointness, functionality, domain/range constraints
5. **RDF / Turtle** — serialization format, prefixes, IRIs
6. **SHACL** — shapes (1:1 with classes), instance test graphs (counts in `spec/src/counts.rs`)
7. **Generated crate** — trait/method/enum/constant counts, `#![no_std]` build
8. **Documentation + Website** — completeness, accessibility, broken links
9. **Lean 4 formalization** — structure/field/enum/individual completeness, sorry audit

## Centralized counts

All inventory counts are in **`spec/src/counts.rs`** — the single file to update when ontology terms change. All crates import from `uor_ontology::counts`. Enum class names are centralized in `Ontology::enum_class_names()` in `spec/src/model.rs`. The version string is auto-derived from `Cargo.toml` via `env!("CARGO_PKG_VERSION")`.

## Editing workflow

1. Modify the ontology in `spec/src/namespaces/`
2. Update counts in `spec/src/counts.rs` (single file)
3. Run `cargo run --bin uor-crate` to regenerate `foundation/src/`
4. Run `cargo fmt`
5. Run `cargo clippy --all-targets -- -D warnings`
6. Run `cargo test`
7. Run `cargo run --bin uor-conformance` (full validation)

## Release process

See `RELEASING.md`. Summary: bump version in root `Cargo.toml`, regenerate, commit, tag `vX.Y.Z`, push. CI publishes to crates.io and GitHub Pages.

## Toolchain

- Rust stable (edition 2021, MSRV 1.81 — bumped from 1.70 in v0.2.2 Tier 5 to unlock `core::error::Error` on `no_std`)
- Components: `rustfmt`, `clippy`
- `clippy.toml`: `too-many-lines-threshold = 100`, `avoid-breaking-exported-api = false`
- License: Apache-2.0
