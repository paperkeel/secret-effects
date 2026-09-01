# Method signatures

Add one method signature to each callable implementation with a block body and a
stable source location. Coverage includes:

- function declarations
- generator functions (`function*`)
- class methods and constructors
- accessors
- named function expressions with a block body
- arrow functions or function expressions assigned to a variable or property when the
  body is a block
- object methods
- callbacks with a block body
- hooks and exported callables with a block body

Expression-bodied arrow functions and single-expression callbacks are out of scope for
`scripts/check-semark.mjs` in this repository. Repositories with a different validator
may enforce them.

Do not add a separate signature to an overload declaration without a body. The
implementation signature documents the complete overload behavior. Exclude ambient
declarations and call signatures that contain no implementation.

Put the signature immediately before the callable. Put it before callable decorators.
Do not place other comments between the signature and callable.

Use this structure and omit sections that do not apply:

```ts
/**
 * Creates a session for an authenticated identity.
 *
 * @remarks
 * Side effects: Persists the session before this function returns.
 *
 * Invariant: The identity is verified before this function receives it.
 *
 * @typeParam TIdentity - The verified identity type.
 * @param identity - The identity that owns the session.
 * @param options - The session lifetime and persistence options.
 * @returns The persisted session.
 * @throws {@link SessionPersistenceError} When the repository rejects the write.
 */
```

State concrete behavior in the summary. Use `@remarks` only for important facts that
the summary and structural signature do not show.

Use only these remarks labels and keep this order:

1. `Side effects:`
2. `Invariant:`
3. `Constraint:`
4. `Assumption:`
5. `Interaction:`

Use only applicable tags and keep this order:

1. `@typeParam`
2. `@param`
3. `@returns`
4. `@throws`
5. `@deprecated`
6. `@example`
7. `@see`

Document each type parameter and runtime parameter. Omit `@returns` for constructors,
setters, and callables that return `void` or `never`. Add one `@throws` tag for each
intentional failure category that can cross the callable boundary.

Apply these limits:

- Keep the summary to one sentence and at most 25 words.
- Keep each remarks paragraph to two sentences and 50 words at most.
- Keep each parameter, return, or failure description to 30 words at most.
- Keep the complete signature to 200 words at most.

Describe behavior, input meaning, result meaning, side effects, failures, invariants,
constraints, assumptions, and non-obvious interactions only when they apply.
