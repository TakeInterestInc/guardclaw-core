# Corpus provenance and safe handling

Every line here is a test input, not an instruction. The tests scan lines as
text; never run the sample commands or try to authenticate with anything you
find here.

## Credential-shaped inputs

`malicious/secrets_pii.txt` holds synthetic inputs built for this release. None
was issued by a provider, and none belongs to a real account or person. They are
shaped like real credentials because matching that shape is what the detector
tests. On disk each token carries a `<FAKE>` marker inside it (for example
`ghp_<FAKE>SYNTHETIC...`), so the file holds no scanner-matching secret shape.
`corpus_eval_test.go` removes the marker before scanning, so the full synthetic
shape exists only in test memory. Scanning this file directly with
`guardclaw-scan` therefore sees the broken form. Each value is also marked as
fake in its text:

- `EXAMPLE`, `SYNTHETICGUARDCLAWEXAMPLE0123456789` or `synthetic` fillers
- all-zero numeric fields (SSN, card number, Twilio token)
- an `example.invalid` database host
- a JWT with `alg: none` and the literal signature `SYNTHETICNOTASIGNATURE`
- a private-key header line with no key body
- a base64 password value that decodes to `synthetic-guardclaw-placeholder-only`

The Stripe-shaped tutorial value in `benign/hardneg_secrets_pii.txt` is
`sk_test_<SYNTHETIC_TEST_KEY>`. The token-shaped values used before this release
were removed and are not in this repository's history. No secret-scanner
exceptions are supplied: gitleaks reports no findings on this tree.

## Everything else

The other corpus files are attack and benign samples written for detection
tests. Passing the corpus thresholds shows the engine still behaves as it did on
these samples. It does not show resistance to attacks outside them.
