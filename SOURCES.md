# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only (GitHub API GET, raw.githubusercontent.com); the
SHA-256 of each copy is listed in that directory's `SHA256SUMS` and was
re-checked on 2026-11-09.

| Source | URL | Used for | SHA-256 of copy |
|---|---|---|---|
| Commit 03547759179672d216d2e1376dd1ae4fdad76a94 diff ("fix: decode terminal proxy path until stable to block multi-encoded traversal (#25157)", 2026-05-31, 1 file +8/-1, parent d4030a8) | https://github.com/open-webui/open-webui/commit/03547759179672d216d2e1376dd1ae4fdad76a94 | old 38, new 38-45, context 39-40/46-47 | 000d183b783a6ab24959578d83bdb2ae1c00c4511822b08b7889b0ba8ff4989b |
| Commit 05098d25a58d03738e01c4e85e8852c3b4ad849c diff ("Fail closed when the proxy/redirect path decode cap is exceeded (#26050)", 2026-06-16, 2 files +6/-0) | https://github.com/open-webui/open-webui/commit/05098d25a58d03738e01c4e85e8852c3b4ad849c | terminals.py new 46-48 (models.py new 63-65 not modelled) | 47bb666a16629ec0cc3bc986deb1c859078f366fb7e55ad97b88d0155070bc3a |
| `terminals.py` at d4030a8aa5d48c2a1cb06c461566844aca2530ab (blob d2ef5f0ea318) | https://github.com/open-webui/open-webui/blob/d4030a8aa5d48c2a1cb06c461566844aca2530ab/backend/open_webui/routers/terminals.py | `pre`: lines 31-49, 94-103 | a86406c41580f4e0cf75def84cfc1a48e28897071bcd1653280c3c9b11f7aaf3 |
| `terminals.py` at 0354775 (blob 4c61d6ec1d81) | https://github.com/open-webui/open-webui/blob/03547759179672d216d2e1376dd1ae4fdad76a94/backend/open_webui/routers/terminals.py | `post`: lines 31-56, 101-110 | 1ccfecae751181f77ece36ad7e0a339a24a3a69cbb24db23a3ed0c0f62bf2def |
| `terminals.py` at 05098d2 (blob 4c71322bfbfc) | https://github.com/open-webui/open-webui/blob/05098d25a58d03738e01c4e85e8852c3b4ad849c/backend/open_webui/routers/terminals.py | `post2`: lines 31-59, 104-113 | c400cfb70fac5e0ac817f924f5c5ce0037bed5c65f0ce1dfe75f66c612a4e609 |
| Tag containment (compare API) and function-body hashes | `tags_CVE-2026-54017.txt` | 0354775 in v0.9.6, not v0.9.5; 05098d2 not in v0.9.6, in v0.10.0; function in v0.9.5/v0.9.6/v0.10.0 = pre/post/post2 | a2e514a93b5b060dfd73be9b6b253653604824149ae508da26e18be22c647675 |
| GHSA-r2wg-2mcr-66rv (GitHub advisory JSON) | https://github.com/advisories/GHSA-r2wg-2mcr-66rv | quoted pre function, `%252e%252e` vector, upstream decodes again, `<= 0.9.5` -> 0.9.6, CWE-22/918 | bfe2f495324e262625f7c05159013679acc9dfd73455831047e1f698771a3cb4 |
| NVD CVE-2026-54017 (Analyzed, published 2026-06-18) | https://nvd.nist.gov/vuln/detail/CVE-2026-54017 | description, references | 9bc587738a55cc574b42407ae01d9b5dc2ef95e227bcf19766d27e6d6a6661ae |
| cve.org CVE-2026-54017 (PUBLISHED, CNA GitHub_M) | https://www.cve.org/CVERecord?id=CVE-2026-54017 | record state | df601bca2c3e3edcf2097e5cf61e986db54dbeae2fd110f7ae553530c551a11b |

Neither the GHSA, NVD nor cve.org names a commit. 0354775 is tied to the
CVE by its title, its tag (first in v0.9.6, the patched version) and the
05098d2 message, which calls itself "the residual of the decode-until-stable
hardening added for CVE-2026-54017".

`urllib.parse.unquote` and `posixpath.normpath` are CPython 3.13.5 on the
build box (`scripts/derive_expected.py` calls them directly).

No source contained instructions addressed to a tool or agent. Commit
trailers and advisory credits name people; they were not copied.
