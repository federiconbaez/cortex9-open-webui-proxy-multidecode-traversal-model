# cortex9-open-webui-proxy-multidecode-traversal-model

Offline model of **CVE-2026-54017** (GHSA-r2wg-2mcr-66rv, CWE-22/CWE-918):
Open WebUI's terminal proxy sanitized the path with a single
`urllib.parse.unquote()`, then `posixpath.normpath()` and a `..` check, and
forwarded the *decoded* result to `{base_url}/p/{policy_id}/{safe_path}`. A
double-encoded `%252e%252e` became `%2e%2e` after one decode, passed the
check, and (per the GHSA) the terminal server decoded it again into `..`.
Fix 0354775 (in v0.9.6) decodes until stable, at most 8 passes; later
commit 05098d2 (first in v0.10.0) fails closed when the cap is reached and
the value would still decode.
Educational, deterministic, C11 checked with ASan/UBSan. **Open WebUI is
not run, no request is made and nothing touches the network.**

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What is modelled (tied to the code)

`backend/open_webui/routers/terminals.py`, `_sanitize_proxy_path()`:

| Version | Lines | Code | Model |
|---|---|---|---|
| `pre` d4030a8 (= v0.9.5 body) | 38 (diff 0354775 old 38) | `decoded = unquote(path)` | one pass |
| `post` 0354775 (= v0.9.6 body) | 40-45 (diff new 38-45) | `for _ in range(8): once = unquote(decoded); if once == decoded: break` | until stable, cap 8 |
| `post2` 05098d2 (= v0.10.0 body) | 46-48 (diff new 46-48) | `if unquote(decoded) != decoded: return None` | fail closed |
| all | pre 39-48 / post 46-55 / post2 49-58 | `endswith('/')`, `normpath`, `lstrip('/')`, `startswith('..') or == '.'`, trailing `/` | same in C and Python |
| all | pre 103 / post 110 / post2 113 | `f'{base_url}/p/{policy_id}/{safe_path}'` | scope `/p/pol` |

The terminal server is **not** code from these sources. Two assumptions are
evaluated side by side: `U1`, it percent-decodes once (what the GHSA
describes), and `UINF`, it decodes until stable (a stricter what-if). Then
dot segments are resolved and the result is `IN_SCOPE` (under `/p/pol`) or
`ESCAPES`.

## Differential evidence (`results/`)

`results/sweep.csv` encodes `../admin` 0 to 12 times:

| Encoding depth | pre U1 | post U1 | post2 U1 | pre UINF | post UINF | post2 UINF |
|---|---|---|---|---|---|---|
| 0, 1 | REJECTED | REJECTED | REJECTED | REJECTED | REJECTED | REJECTED |
| 2 (`%252e%252e`) | **ESCAPES** | REJECTED | REJECTED | **ESCAPES** | REJECTED | REJECTED |
| 3-8 | IN_SCOPE | REJECTED | REJECTED | **ESCAPES** | REJECTED | REJECTED |
| 9 | IN_SCOPE | **ESCAPES** | REJECTED | **ESCAPES** | **ESCAPES** | REJECTED |
| 10-12 | IN_SCOPE | IN_SCOPE | REJECTED | **ESCAPES** | **ESCAPES** | REJECTED |

So under the GHSA's own assumption the CVE fix closes depth 2, and the cap
leaves depth 9 open until 05098d2. `tests/test_model.c` checks these rows
for depths 0-40 and, on 30,000 random paths, that `post2` never escapes,
that `post` only escapes after 8 passes, and that `pre` only escapes when
the forwarded path still holds an escape.

## Build and check

```sh
sh scripts/build.sh test                    # strict C11, ASan/UBSan
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/owui case pre '%252e%252e/admin' u1
```

`scripts/derive_expected.py` uses CPython's own `urllib.parse.unquote` and
`posixpath.normpath`, written from the upstream files, not from the C code.

Sources: [SOURCES.md](SOURCES.md). Limits: [LIMITATIONS.md](LIMITATIONS.md).
License: Apache-2.0.
