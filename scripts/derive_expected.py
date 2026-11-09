#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv.

Written from the three upstream versions of _sanitize_proxy_path() in
backend/open_webui/routers/terminals.py (d4030a8 lines 38-49, 0354775
lines 40-56, 05098d2 lines 40-59), not from the C model. It calls Python's
own urllib.parse.unquote and posixpath.normpath, as upstream does. The only
additions are the model's domain (ASCII without NUL, shorter than 4096) and
the upstream assumption from GHSA-r2wg-2mcr-66rv (the terminal server
percent-decodes once, U1, or until stable, UINF).
"""
import posixpath
import sys
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cx9_util import escape, read_cases, unescape  # noqa: E402

MAX = 4096
SCOPE = "/p/pol"


class Bad(Exception):
    pass


def uq(s):
    out = unquote(s)
    if any(ord(c) == 0 or ord(c) >= 0x80 for c in out):
        raise Bad()
    return out


def sanitize(version, path):
    if len(path) >= MAX:
        raise Bad()
    if version == "pre":
        decoded = uq(path)
    else:
        decoded = path
        for _ in range(8):
            once = uq(decoded)
            if once == decoded:
                break
            decoded = once
        if version == "post2" and uq(decoded) != decoded:
            return None
    had_trailing_slash = decoded.endswith("/")
    normalized = posixpath.normpath(decoded)
    cleaned = normalized.lstrip("/")
    if cleaned.startswith("..") or cleaned == ".":
        return None
    if len(cleaned) + 2 > MAX:
        raise Bad()
    if had_trailing_slash and cleaned and not cleaned.endswith("/"):
        cleaned += "/"
    return cleaned


def evaluate(version, path, mode):
    try:
        safe = sanitize(version, path)
        if safe is None:
            return "REJECTED", None, None
        a = uq(safe)
        if mode == "UINF":
            while True:
                b = uq(a)
                if b == a:
                    break
                a = b
        joined = SCOPE + "/" + a
        if len(joined) >= MAX:
            raise Bad()
        up = posixpath.normpath(joined)
    except Bad:
        return "BAD_INPUT", None, None
    inside = up == SCOPE or up.startswith(SCOPE + "/")
    return ("IN_SCOPE" if inside else "ESCAPES"), safe, up


def main():
    root = Path(__file__).resolve().parent.parent
    print("id\tversion\tverdict_u1\tverdict_uinf\tsafe_path\tupstream_u1")
    for row in read_cases(root / "fixtures" / "cases.tsv"):
        cid, path = row[0], unescape(row[2])
        for version in ("pre", "post", "post2"):
            v1, safe, up = evaluate(version, path, "U1")
            vinf, _, _ = evaluate(version, path, "UINF")
            s = "-" if safe is None else escape(safe)
            u = "-" if up is None else escape(up)
            print(f"{cid}\t{version}\t{v1}\t{vinf}\t{s}\t{u}")


if __name__ == "__main__":
    main()
