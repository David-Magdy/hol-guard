# Contributing to Canary Commons

Every corpus change requires human review for both safety and expected-outcome quality.

A proposed case or template must be synthetic, clearly defanged, reproducible without network access, and limited to the minimum excerpt needed to exercise the intended behavior. Use `.invalid`, `example.*`, fictional package/tool identities, and placeholder secrets. Do not submit live secrets, malware, exploit payloads, real victim data, live command-and-control infrastructure, or runnable destructive instructions.

Reviewers must verify that the expected outcome follows from the exact excerpt, the reason code is specific, limitations are accurate, benchmark-family metadata does not imply a benchmark was run, and the change does not accidentally move cases between train and held-out sets without an explicit split review.

Negative, benign, ambiguous, and null-result cases are welcome. Contributions are never conditioned on making HOL Guard look favorable. If a valid case exposes a false positive, false negative, unsupported surface, or inconsistent policy expectation, preserve that result and fix the product or expectation separately.

Before merge, run the Canary Commons tests. They enforce total/category/split counts, unique IDs, schema shape, safe markers, defanged infrastructure, and absence of obvious live-secret patterns.
