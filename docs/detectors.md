# How the detectors work

Everything described here lives in [`src/clipguard/detectors.py`](../src/clipguard/detectors.py). The module has no dependencies and doesn't touch the clipboard. It takes a string and returns a list of findings, which makes it easy to test and reuse (the `clipguard scan` command uses it directly).

## The pipeline

Calling `scan(text)` runs five steps:

```
text ──► truncate ──► pattern detectors ──► password heuristic ──► de-duplicate ──► findings
        (200k chars)   (regex + validator)    (whole clipboard)      (keep the most
                                                                       severe match)
```

1. **Truncate.** Only the first 200,000 characters are scanned, so copying a huge log file can't freeze the app.
2. **Pattern detectors.** Each entry in the `PATTERNS` table is a regular expression, sometimes paired with a validation function. Every regex match is checked against its validator, and only matches that pass become findings.
3. **Password heuristic.** A separate check decides whether the *entire* clipboard is a single random-looking secret (see [below](#the-password-heuristic)).
4. **Filtering.** Detectors below `min_severity` or listed in `disabled_detectors` are skipped before they run.
5. **De-duplication.** Findings are sorted by severity (highest first). Any finding that sits entirely inside another finding of equal or higher severity is dropped. A database URL like `postgres://admin:hunter2@host/db` therefore produces one "Database URL with password" finding, not that plus a separate "Password in text".

Each finding records the detector id, a human-readable label, the severity, the matched text and its position. The matched text stays in memory and is only shown masked (see [Masking](#masking)).

## Severity levels

| Level | Meaning | Alerts by default? |
|---|---|---|
| **high** | Leaking this gives someone direct access or money: credentials, keys, card numbers, national ID numbers. | Yes |
| **medium** | Sensitive, but less immediately exploitable or less certain to be a secret: IBANs, JWTs, webhooks, random-looking strings. | Yes |
| **low** | Personal data you'd usually rather not paste into the wrong place: emails, phone numbers. | No (set `min_severity = "low"`) |

## Detector reference

### Credentials and API keys

Most of these rely on a **fixed prefix** that the provider puts on every key. That prefix is why they're reliable: random text almost never starts with `AKIA` followed by exactly 16 uppercase characters.

| Id | Severity | What it matches |
|---|---|---|
| `aws_access_key` | high | `AKIA`, `ASIA`, `ABIA` or `ACCA` followed by 16 uppercase letters or digits |
| `aws_secret_key` | high | A 40-character base64-like string that appears within about 20 characters of the words "aws" and "secret" or "private". The secret alone has no prefix, so context is required. |
| `github_token` | high | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 or more characters, or `github_pat_…` |
| `gitlab_token` | high | `glpat-` + 20 or more characters |
| `openai_key` | high | `sk-…` keys containing OpenAI's `T3BlbkFJ` marker, or `sk-proj-` + 40 or more characters |
| `anthropic_key` | high | `sk-ant-api03-…` / `sk-ant-admin01-…` with 80 or more characters after the prefix |
| `google_api_key` | high | `AIza` + exactly 35 characters |
| `stripe_key` | high | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` + 24 or more characters |
| `slack_token` | high | `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-` + 10 or more characters |
| `slack_webhook` | medium | `https://hooks.slack.com/services/T…/B…/…` |
| `twilio_key` | high | `SK` + 32 hex characters |
| `sendgrid_key` | high | `SG.` + 22 characters + `.` + 43 characters |
| `npm_token` | high | `npm_` + 36 characters |
| `hf_token` | high | `hf_` + 34 letters |
| `private_key` | high | A PEM header such as `-----BEGIN RSA PRIVATE KEY-----` (also EC, DSA, OPENSSH, PGP, ENCRYPTED and generic) |
| `jwt` | medium | Three dot-separated base64url segments, where the first two start with `eyJ`, which is how `{"` looks when base64-encoded |
| `db_url` | high | A `postgres://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://` or `amqp://` URL containing `user:password@` |
| `password_assignment` | high | The words `password`, `passwd`, `pwd`, `pass`, `secret`, `api_key`/`apikey`, or `token`, followed by `:` or `=` and a value of 6 or more non-space characters. Only the value is reported. |

### Financial

These use **checksums**, which is what keeps false positives low. A random 16-digit number has only about a 1-in-10 chance of passing the Luhn test, and a random IBAN-shaped string about 1 in 97 of passing mod-97.

| Id | Severity | Pattern | Validation |
|---|---|---|---|
| `credit_card` | high | 13–19 digits, optionally separated by spaces or dashes | **Luhn checksum.** Starting from the rightmost digit, double every second digit, subtract 9 from any result over 9, and add everything up. Valid card numbers sum to a multiple of 10. |
| `iban` | medium | 2 letters + 2 digits + 11–30 letters or digits, with optional spaces in groups of 4 | **ISO 13616 mod-97.** Remove spaces, move the first four characters to the end, replace letters with numbers (A=10 … Z=35). The resulting integer mod 97 must equal 1. |

That's why `4111 1111 1111 1111` is flagged but `4111 1111 1111 1112` isn't.

### Personal identifiers

| Id | Severity | What it matches |
|---|---|---|
| `us_ssn` | high | `NNN-NN-NNNN`, excluding numbers the US never issues (area `000`, `666` or `9xx`, group `00`, serial `0000`). The dashes are required. |
| `fr_nir` | high | French social security number: sex digit (1 or 2), year, month (01–12 or 20–99 for special cases), department (2 digits or `2A`/`2B` for Corsica), commune, order number and 2-digit key, with optional spaces. The key is **not** checked yet. |
| `email` | low | `name@domain.tld` |
| `phone` | low | Digit groups separated by spaces, dots or dashes, optionally starting with `+country` or wrapped in parentheses. The match must contain **9–15 digits**, which excludes dates like `2026-10-27` (8 digits) and short numbers. |

## The password heuristic

Passwords have no fixed format, so the `high_entropy` detector (medium severity) uses a heuristic instead of a regex. It only looks at the clipboard **as a whole**, because a password is usually copied by itself, and scanning every word in a document this way would produce constant false alarms.

The clipboard is flagged when **all** of these are true:

1. **One token.** After trimming, it contains no spaces or line breaks.
2. **Length 12–128 characters.**
3. **At least 3 of 4 character classes:** lowercase, uppercase, digits, symbols.
4. **Not obviously something else.** It doesn't start with `http://`, `https://`, `www.`, `/`, `~/` or a Windows drive like `C:\`, and it isn't an email address.
5. **Shannon entropy of at least 3.5 bits per character.** This measures how evenly the characters are spread, computed as −Σ p·log₂(p) over each distinct character's frequency. Repeated characters pull it down.

Some examples:

| Clipboard | Result | Why |
|---|---|---|
| `Xq9#vL2!mZ7@pR4$` | flagged | 16 chars, 4 classes, entropy 4.0 |
| `Password1234!` | flagged | 13 chars, 4 classes, entropy 3.55 (it really is a password) |
| `hello123ABC!` | not flagged | entropy under 3.5 because `l` repeats |
| `Supercalifragilistic` | not flagged | only 2 character classes |
| `correct horse battery staple` | not flagged | contains spaces, so it's not treated as a single token |

## Masking

Alerts and the `scan` command never show the full value. `mask()` keeps the first 4 characters, adds `…`, then up to 8 asterisks. For example, `sk_live_abcdefghijklmnop` is shown as `sk_l…********`. Values of 6 characters or fewer are fully replaced with asterisks.

The detection log (`detections.jsonl`) stores only detector ids and severity, never the value or a masked form of it.

## Tuning from the config file

| Setting | Effect on detection |
|---|---|
| `min_severity` | Detectors below this level don't run at all. |
| `disabled_detectors` | Detector ids listed here are skipped. Use `high_entropy` to disable the password heuristic. |
| `ignore_values` | Exact strings that never alert, either the whole clipboard or a single matched value. Handy for a public test key you copy often. |

`clipguard detectors` lists every id with its severity.

## Known limitations

- **`password_assignment` is broad.** It matches the keyword followed by `:`, so ordinary text like `pass: tomorrow` triggers a high-severity alert. If this happens often, disable it or tighten the regex. (Requiring the value to contain a digit or symbol would fix most cases.)
- **The `fr_nir` key isn't verified.** The last two digits of a NIR are a checksum (97 minus the first 13 digits mod 97). Adding that check would remove most false matches on long numbers.
- **SSNs without dashes aren't detected.** Matching plain 9-digit numbers would flag too much.
- **Passphrases with spaces aren't detected** by the password heuristic.
- **Secrets without a prefix,** like generic hex tokens or most internal API keys, are only caught if the password heuristic or a `password=`/`token=` context picks them up.
- **Unknown providers aren't covered.** Each new key format needs its own entry.

## Adding a detector

1. Add an entry to `PATTERNS` in `detectors.py`:

   ```python
   _p("my_service_key", "My Service API key", HIGH,
      r"\bmsk_[A-Za-z0-9]{32}\b"),
   ```

   Optional arguments:
   - `validate=fn` takes the matched string and returns `True` to keep the match (see `luhn_valid` and `iban_valid`).
   - `group=1` reports only a capture group, for when the regex needs surrounding context like `aws_secret_key`.
   - `flags=re.IGNORECASE`.

2. Add a positive and a negative case to `tests/test_detectors.py`. Build fake keys with `j("msk_", "…")` rather than writing them out whole, so GitHub's secret scanning doesn't flag the test file.

3. Run `pytest`.

Guidelines that keep false positives low:
- Prefer a **fixed prefix** or a **checksum** over shape alone.
- Wrap patterns in `\b` word boundaries so they don't match inside longer strings.
- When a secret has no recognizable format, require **context** (a nearby keyword) and report only the secret with `group=`.
