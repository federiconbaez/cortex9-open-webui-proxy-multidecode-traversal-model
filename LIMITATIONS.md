# Limitations

- **A model, not a finding.** Nothing here was reproduced against Open
  WebUI or a terminal server. It restates the advisory and three upstream
  versions of one function.
- **The terminal server is an assumption.** That it percent-decodes the
  forwarded path once (`U1`) comes from the GHSA text; `UINF` is a what-if.
  Real servers may decode zero, one or more times, may reject `%2e`, or may
  route on the raw path. **Not verified.**
- **aiohttp/yarl not modelled.** The proxy passes `target_url` as a string
  to aiohttp; how yarl re-quotes or normalizes it before sending (including
  dot segments) is **not verified** and could change the outcome either way.
- **Commit-to-CVE link.** GHSA, NVD and cve.org name no commit. 0354775 is
  attributed by title, tag (v0.9.6, the patched version) and the 05098d2
  message. 05098d2 is **not** in v0.9.6: by this model, v0.9.6 still lets a
  path encoded 9 times escape under `U1`; the 05098d2 message describes
  the same residual. The GHSA still lists 0.9.6 as patched.
- **Second sink not modelled.** 05098d2 also changes
  `_safe_static_redirect_path` in `routers/models.py` (cap 2, new lines
  63-65). Only the terminal proxy is modelled.
- **Query string and fragments.** `?query` appended by the proxy and
  decoded `?`/`#` inside the path are treated as path bytes.
- **Input domain:** ASCII; any decode that would yield NUL or a byte
  `>= 0x80` (UTF-8 with `errors='replace'` upstream) is `BAD_INPUT`;
  paths and the joined upstream path must be shorter than 4096 bytes.
- **`posixpath.normpath`** follows CPython 3.13 (two leading slashes kept,
  then removed by `lstrip('/')`). Windows paths are not modelled.
- **False positives** like `..hidden/x` (rejected by `startswith('..')`)
  are shown as edges, not as bugs.
- Sweeps and random tests are grids, not proofs.
