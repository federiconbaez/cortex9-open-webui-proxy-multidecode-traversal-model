#include "owui_model.h"
#include <stdio.h>
#include <string.h>

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

long ow_unquote(const char *in, char *out, size_t outsz) {
  size_t i = 0, o = 0, n = strlen(in);
  while (i < n) {
    unsigned char c = (unsigned char)in[i];
    int hi, lo;
    if (c == '%' && i + 2 < n && (hi = hexval(in[i + 1])) >= 0 &&
        (lo = hexval(in[i + 2])) >= 0) {
      c = (unsigned char)(hi * 16 + lo);
      i += 3;
    } else {
      i += 1;
    }
    if (c == 0 || c >= 0x80) return -1;
    if (o + 1 >= outsz) return -1;
    out[o++] = (char)c;
  }
  if (o >= outsz) return -1;
  out[o] = '\0';
  return (long)o;
}

long ow_normpath(const char *in, char *out, size_t outsz) {
  static const char *cs[OW_MAX];
  static size_t cl[OW_MAX];
  size_t n = strlen(in), i = 0, nc = 0, o = 0, k;
  int slashes = 0;
  if (n >= OW_MAX) return -1;
  if (n == 0) {
    if (outsz < 2) return -1;
    strcpy(out, ".");
    return 1;
  }
  if (in[0] == '/') slashes = (n >= 2 && in[1] == '/' && !(n >= 3 && in[2] == '/')) ? 2 : 1;
  while (i <= n) {
    size_t j = i;
    while (j < n && in[j] != '/') ++j;
    {
      const char *c = in + i;
      size_t len = j - i;
      if (len == 0 || (len == 1 && c[0] == '.')) {
        /* skip */
      } else if (!(len == 2 && c[0] == '.' && c[1] == '.') || (!slashes && nc == 0) ||
                 (nc > 0 && cl[nc - 1] == 2 && cs[nc - 1][0] == '.' && cs[nc - 1][1] == '.')) {
        cs[nc] = c;
        cl[nc] = len;
        nc++;
      } else if (nc > 0) {
        nc--;
      }
    }
    i = j + 1;
  }
  for (k = 0; k < (size_t)slashes; ++k) {
    if (o + 1 >= outsz) return -1;
    out[o++] = '/';
  }
  for (k = 0; k < nc; ++k) {
    if (k > 0) {
      if (o + 1 >= outsz) return -1;
      out[o++] = '/';
    }
    if (o + cl[k] >= outsz) return -1;
    memcpy(out + o, cs[k], cl[k]);
    o += cl[k];
  }
  if (o == 0) {
    if (outsz < 2) return -1;
    out[o++] = '.';
  }
  out[o] = '\0';
  return (long)o;
}

ow_sanitized ow_sanitize(ow_version v, const char *path) {
  ow_sanitized r;
  static char decoded[OW_MAX], once[OW_MAX], norm[OW_MAX];
  const char *cleaned;
  size_t len;
  int had_trailing, k;
  memset(&r, 0, sizeof r);
  if (strlen(path) >= OW_MAX) return r;
  if (v == OW_PRE) {
    /* pre line 38: decoded = unquote(path) */
    if (ow_unquote(path, decoded, sizeof decoded) < 0) return r;
    r.passes = strcmp(decoded, path) != 0;
  } else {
    /* post lines 40-45: decode until stable, range(8) */
    strcpy(decoded, path);
    for (k = 0; k < 8; ++k) {
      if (ow_unquote(decoded, once, sizeof once) < 0) return r;
      if (strcmp(once, decoded) == 0) break;
      strcpy(decoded, once);
      r.passes++;
    }
    /* post2 lines 46-48: if unquote(decoded) != decoded: return None */
    if (v == OW_POST2) {
      if (ow_unquote(decoded, once, sizeof once) < 0) return r;
      if (strcmp(once, decoded) != 0) {
        r.ok = 1;
        r.rejected = 1;
        return r;
      }
    }
  }
  len = strlen(decoded);
  had_trailing = len > 0 && decoded[len - 1] == '/';
  if (ow_normpath(decoded, norm, sizeof norm) < 0) return r;
  cleaned = norm;
  while (*cleaned == '/') ++cleaned; /* lstrip('/') */
  r.ok = 1;
  if (strncmp(cleaned, "..", 2) == 0 || strcmp(cleaned, ".") == 0) {
    r.rejected = 1;
    return r;
  }
  len = strlen(cleaned);
  if (len + 2 > sizeof r.safe) {
    r.ok = 0;
    return r;
  }
  memcpy(r.safe, cleaned, len + 1);
  if (had_trailing && len > 0 && cleaned[len - 1] != '/') strcat(r.safe, "/");
  return r;
}

ow_eval ow_evaluate(ow_version v, const char *path, ow_upstream u) {
  ow_eval e;
  static char a[OW_MAX], b[OW_MAX], joined[OW_MAX + 16];
  size_t sl = strlen(OW_SCOPE);
  memset(&e, 0, sizeof e);
  e.s = ow_sanitize(v, path);
  if (!e.s.ok) {
    e.verdict = OW_BAD_INPUT;
    return e;
  }
  if (e.s.rejected) {
    e.verdict = OW_REJECTED;
    return e;
  }
  /* assumption from the GHSA: the terminal server decodes the path */
  if (ow_unquote(e.s.safe, a, sizeof a) < 0) {
    e.verdict = OW_BAD_INPUT;
    return e;
  }
  if (u == OW_UINF) {
    for (;;) {
      if (ow_unquote(a, b, sizeof b) < 0) {
        e.verdict = OW_BAD_INPUT;
        return e;
      }
      if (strcmp(a, b) == 0) break;
      strcpy(a, b);
    }
  }
  if ((size_t)snprintf(joined, sizeof joined, "%s/%s", OW_SCOPE, a) >= sizeof joined ||
      ow_normpath(joined, e.upstream, sizeof e.upstream) < 0) {
    e.verdict = OW_BAD_INPUT;
    return e;
  }
  e.verdict = (strncmp(e.upstream, OW_SCOPE, sl) == 0 &&
               (e.upstream[sl] == '\0' || e.upstream[sl] == '/'))
                  ? OW_IN_SCOPE
                  : OW_ESCAPES;
  return e;
}

int ow_encode(const char *in, const char *set, int depth, char *out, size_t outsz) {
  static char tmp[OW_MAX];
  size_t o = 0, i;
  int d;
  if (strlen(in) >= outsz) return -1;
  strcpy(out, in);
  for (d = 1; d <= depth; ++d) {
    o = 0;
    for (i = 0; out[i]; ++i) {
      int enc = d == 1 ? strchr(set, out[i]) != NULL : out[i] == '%';
      if (enc) {
        if (o + 3 >= sizeof tmp) return -1;
        if (d == 1)
          snprintf(tmp + o, 4, "%%%02x", (unsigned char)out[i]);
        else
          memcpy(tmp + o, "%25", 3);
        o += 3;
      } else {
        if (o + 1 >= sizeof tmp) return -1;
        tmp[o++] = out[i];
      }
    }
    tmp[o] = '\0';
    if (o >= outsz) return -1;
    memcpy(out, tmp, o + 1);
  }
  return 0;
}

const char *ow_version_name(ow_version v) {
  return v == OW_PRE ? "pre" : v == OW_POST ? "post" : "post2";
}

const char *ow_verdict_name(ow_verdict v) {
  static const char *n[] = {"BAD_INPUT", "REJECTED", "IN_SCOPE", "ESCAPES"};
  return n[v];
}
