/* Model of Open WebUI's terminal proxy path sanitizer (CVE-2026-54017).
 * backend/open_webui/routers/terminals.py, _sanitize_proxy_path():
 *   pre   d4030a8 lines 38-49   one unquote() pass
 *   post  0354775 lines 40-56   unquote() until stable, at most 8 passes
 *   post2 05098d2 lines 40-59   same, plus fail closed (lines 47-48) if the
 *                               result would still decode
 * The proxied URL is f'{base_url}/p/{policy_id}/{safe_path}' (pre line 103).
 * The terminal server is NOT modelled from code: it is an assumption, taken
 * from GHSA-r2wg-2mcr-66rv, that it percent-decodes the path once (U1) or,
 * as a stricter what-if, until stable (UINF), then resolves dot segments. */
#ifndef OWUI_MODEL_H
#define OWUI_MODEL_H
#include <stddef.h>

#define OW_MAX 4096          /* paths are shorter than this */
#define OW_SCOPE "/p/pol"    /* stands for /p/{policy_id} on the upstream */

typedef enum { OW_PRE, OW_POST, OW_POST2 } ow_version;
typedef enum { OW_U1, OW_UINF } ow_upstream;
typedef enum { OW_BAD_INPUT, OW_REJECTED, OW_IN_SCOPE, OW_ESCAPES } ow_verdict;

/* urllib.parse.unquote() restricted to ASCII: %XX with two hex digits is
 * decoded, anything else is kept. Returns the length, or -1 if the result
 * would hold NUL or a byte >= 0x80 (outside the model) or does not fit. */
long ow_unquote(const char *in, char *out, size_t outsz);

/* posixpath.normpath(). Returns the length, -1 if it does not fit. */
long ow_normpath(const char *in, char *out, size_t outsz);

typedef struct {
  int ok;            /* 0: BAD_INPUT */
  int rejected;      /* the function returned None */
  int passes;        /* unquote passes that changed the string */
  char safe[OW_MAX]; /* returned path when not rejected */
} ow_sanitized;

ow_sanitized ow_sanitize(ow_version v, const char *path);

typedef struct {
  ow_verdict verdict;
  ow_sanitized s;
  char upstream[OW_MAX + 16]; /* path the terminal server resolves */
} ow_eval;

ow_eval ow_evaluate(ow_version v, const char *path, ow_upstream u);

/* Encode a string d times: d=1 turns each character of `set` into %XX
 * (lowercase hex); every further level turns each '%' into %25. */
int ow_encode(const char *in, const char *set, int depth, char *out, size_t outsz);

const char *ow_version_name(ow_version v);
const char *ow_verdict_name(ow_verdict v);
#endif
