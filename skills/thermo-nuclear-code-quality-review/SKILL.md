---
name: thermo-nuclear-code-quality-review
description: Run an extremely strict maintainability review for abstraction quality, giant files, and spaghetti-condition growth.
---

# Thermo-Nuclear Code Quality Review

Use this skill for an unusually strict review focused on implementation quality,
maintainability, abstraction quality, and codebase health.

Above all, be ambitious about code structure. Do not merely identify local
cleanup opportunities. Search for “code judo” moves: restructurings that
preserve behavior while making the implementation dramatically simpler,
smaller, more direct, and more elegant.

## Core Prompt

> Perform a deep code quality audit of the current branch's changes.
> Rethink how to structure / implement the changes to meaningfully improve code quality without impacting behavior.
> Work to improve abstractions, modularity, reduce Spaghetti code, improve succinctness and legibility.
> Be ambitious, if there is a clear path to improving the implementation that involves restructuring some of the codebase, go for it.
> Be extremely thorough and rigorous. Measure twice, cut once.

## Non-Negotiable Standards

0. **Be ambitious about structural simplification.**
   - Look for reframings that let whole branches, helpers, modes, conditionals,
     or layers disappear.
   - Prefer deleting complexity to rearranging it.
   - Prefer the solution that feels inevitable in hindsight.

1. **Do not let a PR push a file from under 1,000 lines to over 1,000 lines
   without a very strong reason.**
   - Treat the threshold crossing as a strong smell.
   - Explicitly ask whether the code should be decomposed first.

2. **Do not allow random spaghetti growth in existing code.**
   - Treat ad-hoc conditionals, scattered special cases, and one-off branches
     inserted into unrelated flows as design problems, not style nits.
   - Prefer a dedicated abstraction, pure helper, state machine, policy object,
     or separate module.

3. **Bias toward cleaning the design, not merely accepting working code.**
   - Do not rubber-stamp behaviorally correct changes that make the codebase
     harder to reason about.
   - Prefer simplifications that remove moving pieces.

4. **Prefer direct, boring, maintainable code over hacky or magical code.**
   - Flag thin wrappers and pass-through abstractions that add indirection
     without buying clarity.
   - Be skeptical of generic mechanisms that hide simple data-shape assumptions.

5. **Push hard on type and boundary cleanliness.**
   - Question unnecessary optionality, `unknown`, `any`, casts, and silent
     fallback when a clearer invariant can be expressed.

6. **Keep logic in the canonical layer and reuse existing helpers.**
   - Call out feature logic leaking into shared paths or implementation details
     leaking through APIs.
   - Prefer canonical utilities over bespoke near-duplicates.

7. **Treat unnecessary sequential orchestration and non-atomic updates as
   design smells when the cleaner structure is obvious.**
   - Parallelize independent work when that also simplifies orchestration.
   - Prefer atomic state changes when partial application is risky.

## Primary Review Questions

- Is there a code-judo move that makes this dramatically simpler?
- Can the change be reframed so fewer concepts, branches, or helper layers are needed?
- Does this improve or worsen the local architecture?
- Did branching complexity grow where a better abstraction should exist?
- Is the logic in the canonical file, package, and layer?
- Did a file cross a healthy size boundary?
- Are repeated conditionals signaling a missing model or helper?
- Is the abstraction earning its keep?
- Did optionality, casting, or ad-hoc shapes obscure the real invariant?
- Is orchestration more sequential or less atomic than necessary?

## What to Flag Aggressively

- A complicated implementation where a cleaner reframing can delete complexity.
- A refactor that moves complexity but does not reduce concepts.
- A file crossing 1,000 lines because of the PR.
- Special-case conditionals bolted onto unrelated paths.
- One-off booleans or nullable modes that complicate control flow.
- Feature-specific logic leaking into general-purpose modules.
- Magical handling that hides simple structure.
- Thin wrappers, identity abstractions, and unnecessary casts.
- Copy-pasted logic instead of canonical helpers.
- Edge-case handling placed in an already busy function.
- “Temporary” branching likely to become permanent debt.
- Avoidable sequential work or partial-update behavior.

## Preferred Remedies

- Delete a layer of indirection rather than polishing it.
- Reframe the state model so conditionals disappear.
- Change ownership boundaries so the feature naturally extends an existing abstraction.
- Turn special cases into a simpler default flow.
- Extract a pure function or split a large file into focused modules.
- Separate orchestration from business logic.
- Replace condition chains with an explicit model or dispatcher.
- Collapse duplicate branches.
- Reuse canonical helpers.
- Make type boundaries explicit.
- Parallelize independent work where it simplifies the flow.
- Make related state updates atomic.

Do not settle for naming feedback when the real issue is structural. Do not
settle for a cleaner version of the same messy idea when a materially simpler
model is plausible.

## Tone and Output

Be direct, serious, and demanding without being rude. Prefer a small number of
high-conviction, actionable findings over cosmetic nits. Prioritize:

1. Structural regressions.
2. Missed dramatic simplifications.
3. Spaghetti and branching growth.
4. Boundary, abstraction, and type-contract problems.
5. File-size and decomposition concerns.
6. Modularity and legibility.

## Approval Bar

Do not approve merely because behavior seems correct. Approval requires:

- no clear structural regression;
- no obvious missed simplification;
- no unjustified file-size explosion;
- no spaghetti growth from special-case branching;
- no hacky or magical abstraction;
- no wrapper, cast, or optionality churn obscuring the design;
- no architecture-boundary leak or canonical-helper duplication; and
- no missed decomposition that would materially improve maintainability.

Treat failures of these conditions as presumptive blockers. Leave explicit,
actionable feedback and push for a cleaner decomposition.
