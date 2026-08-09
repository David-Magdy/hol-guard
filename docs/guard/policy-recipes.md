# Public policy recipes

HOL Guard policy recipes are inert JSON starting points for common policy decisions. A recipe does not change local Guard state merely because it is downloaded or validated.

## Validation

The `policy_recipe` module validates:

- schema version and strict field set;
- bounded recipe IDs, slugs, titles, summaries, matchers, limitations, and tests;
- exact matcher kinds and policy actions;
- absence of wildcard matchers;
- every included synthetic fixture against the recipe decision;
- the SHA-256 digest of the canonical downloaded artifact when the caller compares it with the published hash.

Unknown fields are rejected. The public format has no command-to-run, auto-apply, credential, workspace-path, or token field.

## Applying a recipe

A recipe should be reviewed in Guard Policy Studio before rollout. The recipe itself is not the enforcement bundle.

Guard Cloud compiles saved policy state through the existing policy-bundle compiler. When policy-bundle signing is configured, the compiler produces an RSA-PSS-SHA256 signature and embeds the public verification key. Local Guard verifies that bundle through the existing policy bundle parser before accepting the synchronized policy.

This preserves one enforcement path: public recipe → reviewed policy → existing signed policy bundle → local Guard verification.

## Emergency recipes

Campaign-specific recipe suggestions must remain conservative and evidence-linked. They are starting points selected from the same reviewed recipe registry, not automatically applied incident-response controls. Operators must replace example identifiers, confirm affected scope, and review current campaign evidence before rollout.
