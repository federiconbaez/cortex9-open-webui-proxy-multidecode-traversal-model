/* Tests for the Open WebUI terminal proxy path model. Run under ASan +
 * UBSan with -fno-sanitize-recover (scripts/build.sh test). */
#include "cx9_util.h"
#include "owui_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(c, what)                                                    \
  do {                                                                    \
    checks++;                                                             \
    if (!(c)) {                                                           \
      failures++;                                                         \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, what);               \
    }                                                                     \
  } while (0)

#define MAXCASES 64
typedef struct {
  char id[64], kind[16], path[CX9_FIELD_MAX], hand[3][16];
} tcase;
static tcase cases[MAXCASES];
static int ncases;

static void load_cases(const char *dir) {
  static char line[3 * CX9_FIELD_MAX];
  char fpath[512];
  FILE *f;
  snprintf(fpath, sizeof fpath, "%s/cases.tsv", dir);
  f = fopen(fpath, "r");
  CHECK(f != NULL, "open cases.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f) && ncases < MAXCASES) {
    char *fl[CX9_MAX_FIELDS];
    tcase *c = &cases[ncases];
    int k;
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, fl, CX9_MAX_FIELDS) != 6 || strlen(fl[0]) >= 64 ||
        strlen(fl[1]) >= 16 || strlen(fl[3]) >= 16 || strlen(fl[4]) >= 16 ||
        strlen(fl[5]) >= 16 || cx9_unescape(fl[2], c->path, sizeof c->path) < 0) {
      CHECK(0, "cases.tsv row");
      continue;
    }
    strcpy(c->id, fl[0]);
    strcpy(c->kind, fl[1]);
    for (k = 0; k < 3; ++k) strcpy(c->hand[k], fl[3 + k]);
    ncases++;
  }
  fclose(f);
  CHECK(ncases >= 25, "at least 25 fixture cases");
}

static ow_verdict ev(ow_version v, const char *p, ow_upstream u) {
  return ow_evaluate(v, p, u).verdict;
}

/* Hand-derived labels in fixtures/cases.tsv (pos / neg / edge / bad). */
static void test_hand_labels(void) {
  int i, v, pos = 0, neg = 0, bad = 0;
  for (i = 0; i < ncases; ++i) {
    ow_verdict r[3];
    for (v = 0; v < 3; ++v) {
      r[v] = ev((ow_version)v, cases[i].path, OW_U1);
      CHECK(strcmp(ow_verdict_name(r[v]), cases[i].hand[v]) == 0, cases[i].id);
    }
    if (strcmp(cases[i].kind, "pos") == 0) {
      CHECK((r[0] == OW_ESCAPES || r[1] == OW_ESCAPES) && r[2] == OW_REJECTED,
            "pos: escapes before a fix, rejected after 05098d2");
      pos++;
    }
    if (strcmp(cases[i].kind, "neg") == 0) {
      CHECK(r[0] == r[1] && r[1] == r[2] && r[0] != OW_ESCAPES && r[0] != OW_BAD_INPUT,
            "neg: same verdict in every version");
      neg++;
    }
    if (strcmp(cases[i].kind, "bad") == 0) {
      CHECK(r[0] == OW_BAD_INPUT && r[1] == OW_BAD_INPUT && r[2] == OW_BAD_INPUT, "bad");
      bad++;
    }
  }
  CHECK(pos >= 6 && neg >= 8 && bad >= 3, "enough positive, negative and bad fixtures");
}

/* fixtures/expected.tsv comes from scripts/derive_expected.py (Python's
 * urllib.parse.unquote and posixpath.normpath, not this C code). */
static void test_expected(const char *dir) {
  static char line[3 * CX9_FIELD_MAX], esc[4 * OW_MAX + 64];
  char fpath[512];
  FILE *f;
  int rows = 0, i;
  snprintf(fpath, sizeof fpath, "%s/expected.tsv", dir);
  f = fopen(fpath, "r");
  CHECK(f != NULL, "open expected.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f)) {
    char *fl[CX9_MAX_FIELDS];
    int n;
    if (strncmp(line, "id\t", 3) == 0) continue;
    n = cx9_split_tsv(line, fl, CX9_MAX_FIELDS);
    CHECK(n == 6, "expected.tsv row");
    if (n != 6) continue;
    for (i = 0; i < ncases; ++i) {
      ow_version v = strcmp(fl[1], "pre") == 0 ? OW_PRE : strcmp(fl[1], "post") == 0 ? OW_POST : OW_POST2;
      ow_eval a, b;
      if (strcmp(cases[i].id, fl[0]) != 0) continue;
      a = ow_evaluate(v, cases[i].path, OW_U1);
      b = ow_evaluate(v, cases[i].path, OW_UINF);
      rows++;
      CHECK(strcmp(fl[2], ow_verdict_name(a.verdict)) == 0, fl[0]);
      CHECK(strcmp(fl[3], ow_verdict_name(b.verdict)) == 0, fl[0]);
      if (a.verdict == OW_IN_SCOPE || a.verdict == OW_ESCAPES) {
        CHECK(cx9_escape(a.s.safe, strlen(a.s.safe), esc, sizeof esc) == 0 && strcmp(fl[4], esc) == 0, fl[0]);
        CHECK(cx9_escape(a.upstream, strlen(a.upstream), esc, sizeof esc) == 0 && strcmp(fl[5], esc) == 0, fl[0]);
      } else {
        CHECK(strcmp(fl[4], "-") == 0 && strcmp(fl[5], "-") == 0, fl[0]);
      }
    }
  }
  fclose(f);
  CHECK(rows == 3 * ncases, "every case has pre, post and post2 rows");
}

/* Small reference values, checked by hand against CPython 3.13. */
static void test_primitives(void) {
  static const char *uq[][2] = {
      {"%2e", "."}, {"%2E%2e", ".."}, {"%252e", "%2e"}, {"%", "%"}, {"%4", "%4"},
      {"%%32%65", "%2e"}, {"%zz", "%zz"}, {"a%20b", "a b"}, {"%41%", "A%"}, {"", ""}};
  static const char *np[][2] = {
      {"", "."}, {"/", "/"}, {"//", "//"}, {"///", "/"}, {"//a//b", "//a/b"}, {"a/./b/", "a/b"},
      {"../a", "../a"}, {"/../a", "/a"}, {"a/../..", ".."}, {"../../x/..", "../.."}, {".", "."},
      {"a/b/../../..", ".."}, {"/p/pol/../../admin", "/admin"}};
  char out[64];
  size_t i;
  for (i = 0; i < sizeof uq / sizeof uq[0]; ++i)
    CHECK(ow_unquote(uq[i][0], out, sizeof out) >= 0 && strcmp(out, uq[i][1]) == 0, uq[i][0]);
  CHECK(ow_unquote("%00", out, sizeof out) < 0, "NUL is outside the domain");
  CHECK(ow_unquote("%80", out, sizeof out) < 0, "non-ASCII is outside the domain");
  CHECK(ow_unquote("abcdef", out, 4) < 0, "small buffer refused");
  for (i = 0; i < sizeof np / sizeof np[0]; ++i)
    CHECK(ow_normpath(np[i][0], out, sizeof out) >= 0 && strcmp(out, np[i][1]) == 0, np[i][0]);
  CHECK(ow_normpath("abc/def", out, 3) < 0, "normpath small buffer refused");
  CHECK(ow_encode("..", ".", 1, out, sizeof out) == 0 && strcmp(out, "%2e%2e") == 0, "encode 1");
  CHECK(ow_encode("..", ".", 3, out, sizeof out) == 0 && strcmp(out, "%25252e%25252e") == 0, "encode 3");
  CHECK(ow_encode("../", "./", 2, out, sizeof out) == 0 && strcmp(out, "%252e%252e%252f") == 0, "encode slash");
}

/* The encoding-depth result, stated once and checked for every depth. */
static void test_depth(void) {
  static char enc[OW_MAX];
  int d, k;
  static const char *sets[] = {".", "./"};
  for (k = 0; k < 2; ++k)
    for (d = 0; d <= 40; ++d) {
      CHECK(ow_encode("../admin", sets[k], d, enc, sizeof enc) == 0, "encode");
      CHECK((ev(OW_PRE, enc, OW_U1) == OW_ESCAPES) == (d == 2), "pre U1 escapes only at depth 2");
      CHECK((ev(OW_POST, enc, OW_U1) == OW_ESCAPES) == (d == 9), "post U1 escapes only at depth 9");
      CHECK(ev(OW_POST2, enc, OW_U1) == OW_REJECTED, "post2 rejects every depth");
      CHECK((ev(OW_PRE, enc, OW_UINF) == OW_ESCAPES) == (d >= 2), "pre UINF escapes from depth 2");
      CHECK((ev(OW_POST, enc, OW_UINF) == OW_ESCAPES) == (d >= 9), "post UINF escapes from depth 9");
      CHECK(ev(OW_POST2, enc, OW_UINF) == OW_REJECTED, "post2 UINF rejects every depth");
    }
}

static unsigned long long rng = 0x9e3779b97f4a7c15ULL;
static unsigned next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return (unsigned)(rng >> 32);
}

/* Random paths built from encoding pieces: properties of each version. */
static void test_invariants(void) {
  static const char *tok[] = {"%", "25", "2e", "2E", "2f", ".", "/", "k", "%2e", "%252e",
                              "..", "%2f", "%25", "x", "%7e", "%%"};
  static char p[512], once[OW_MAX];
  int k, inside = 0;
  for (k = 0; k < 30000; ++k) {
    size_t n = 1 + next() % 24, j;
    ow_eval a[3], b[3];
    int v;
    p[0] = '\0';
    for (j = 0; j < n; ++j) strcat(p, tok[next() % (sizeof tok / sizeof tok[0])]);
    for (v = 0; v < 3; ++v) {
      a[v] = ow_evaluate((ow_version)v, p, OW_U1);
      b[v] = ow_evaluate((ow_version)v, p, OW_UINF);
      CHECK(a[v].verdict != OW_BAD_INPUT && b[v].verdict != OW_BAD_INPUT, "pieces stay in domain");
      if (a[v].s.ok && !a[v].s.rejected) {
        CHECK(a[v].s.safe[0] != '/' && strncmp(a[v].s.safe, "..", 2) != 0,
              "returned path never starts with / or ..");
      }
    }
    CHECK(a[2].verdict != OW_ESCAPES && b[2].verdict != OW_ESCAPES, "post2 never escapes");
    if (a[1].verdict == OW_ESCAPES || b[1].verdict == OW_ESCAPES)
      CHECK(a[1].s.passes == 8, "post escapes only when the 8-pass cap is reached");
    if (a[0].verdict == OW_ESCAPES)
      CHECK(ow_unquote(a[0].s.safe, once, sizeof once) >= 0 && strcmp(once, a[0].s.safe) != 0,
            "pre escapes only with encoding left in the forwarded path");
    if (!a[2].s.rejected)
      CHECK(!a[1].s.rejected && strcmp(a[1].s.safe, a[2].s.safe) == 0, "post2 accepts => post same");
    if (!a[1].s.rejected && a[1].s.passes < 8)
      CHECK(!a[2].s.rejected && strcmp(a[1].s.safe, a[2].s.safe) == 0, "below the cap post2 = post");
    if (a[2].verdict == OW_IN_SCOPE) {
      inside++;
      CHECK(b[2].verdict == OW_IN_SCOPE && strcmp(a[2].upstream, b[2].upstream) == 0,
            "post2 output is already stable");
    }
  }
  CHECK(inside > 1000, "the generator reaches accepted paths");
}

/* Adversarial inputs: lengths, slash runs, deep climbs, buffer limits. */
static void test_adversarial(void) {
  static char big[OW_MAX + 64];
  ow_eval e;
  size_t i;
  memset(big, 'a', OW_MAX - 1);
  big[OW_MAX - 1] = '\0';
  e = ow_evaluate(OW_POST2, big, OW_U1);
  CHECK(e.verdict == OW_BAD_INPUT, "4095 bytes: joined upstream path exceeds the domain");
  big[OW_MAX - 8] = '\0';
  e = ow_evaluate(OW_POST2, big, OW_U1);
  CHECK(e.verdict == OW_IN_SCOPE, "4088 bytes fit");
  memset(big, 'a', OW_MAX + 8);
  big[OW_MAX + 8] = '\0';
  CHECK(ow_evaluate(OW_PRE, big, OW_U1).verdict == OW_BAD_INPUT, "longer than the domain");
  for (i = 0; i + 3 < 3000; i += 3) memcpy(big + i, "../", 3);
  strcpy(big + 2997, "x");
  CHECK(ow_evaluate(OW_PRE, big, OW_U1).verdict == OW_REJECTED, "deep literal climb");
  memset(big, '/', 3000);
  big[3000] = '\0';
  e = ow_evaluate(OW_POST, big, OW_U1);
  CHECK(e.verdict == OW_IN_SCOPE && strcmp(e.s.safe, "") == 0, "slash run becomes empty");
  for (i = 0; i + 6 < 3000; i += 6) memcpy(big + i, "%252f", 5), big[i + 5] = 'a';
  big[i] = '\0';
  CHECK(ow_evaluate(OW_POST2, big, OW_UINF).verdict == OW_IN_SCOPE, "many encoded slashes");
  CHECK(ow_evaluate(OW_PRE, "%2", OW_U1).verdict == OW_IN_SCOPE, "truncated escape is literal");
  CHECK(ow_evaluate(OW_POST2, "%25", OW_U1).verdict == OW_IN_SCOPE, "lone percent after decode");
  CHECK(ow_evaluate(OW_POST2, "%2500", OW_U1).verdict == OW_BAD_INPUT, "NUL after two decodes");
}

/* PRACTICE.md levels: each answer is checked here. */
static void test_practice(void) {
  ow_eval e;
  e = ow_evaluate(OW_PRE, "files/report.txt", OW_U1);
  CHECK(e.verdict == OW_IN_SCOPE && strcmp(e.upstream, "/p/pol/files/report.txt") == 0, "practice_level_1");
  CHECK(ev(OW_PRE, "%2e%2e/admin", OW_U1) == OW_REJECTED, "practice_level_2");
  e = ow_evaluate(OW_PRE, "%252e%252e/admin", OW_U1);
  CHECK(e.verdict == OW_ESCAPES && strcmp(e.s.safe, "%2e%2e/admin") == 0 &&
            strcmp(e.upstream, "/p/admin") == 0, "practice_level_3");
  CHECK(ev(OW_POST, "%252e%252e/admin", OW_U1) == OW_REJECTED, "practice_level_4");
  e = ow_evaluate(OW_POST, "%25252525252525252e%25252525252525252e/admin", OW_U1);
  CHECK(e.verdict == OW_ESCAPES && e.s.passes == 8, "practice_level_5");
  CHECK(ev(OW_POST2, "%25252525252525252e%25252525252525252e/admin", OW_U1) == OW_REJECTED, "practice_level_6");
  CHECK(ev(OW_PRE, "%25252e%25252e/admin", OW_U1) == OW_IN_SCOPE &&
            ev(OW_PRE, "%25252e%25252e/admin", OW_UINF) == OW_ESCAPES, "practice_level_7");
  CHECK(ev(OW_POST2, "..hidden/x", OW_U1) == OW_REJECTED, "practice_level_8");
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "fixtures";
  load_cases(dir);
  test_hand_labels();
  test_expected(dir);
  test_primitives();
  test_depth();
  test_invariants();
  test_adversarial();
  test_practice();
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
