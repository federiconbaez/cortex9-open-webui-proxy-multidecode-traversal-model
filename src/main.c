/* CLI: regenerate results/ or inspect one case.
 *   owui results fixtures/cases.tsv <dir>
 *   owui case pre|post|post2 <path> u1|uinf      (path uses TSV escapes)
 * Nothing is sent anywhere: the proxied URL is only printed. */
#include "cx9_util.h"
#include "owui_model.h"
#include <stdio.h>
#include <string.h>

static void field(FILE *f, const char *s) {
  static char esc[4 * OW_MAX + 64];
  cx9_escape(s, strlen(s), esc, sizeof esc);
  cx9_csv_field(f, esc);
}

static int results(const char *cases, const char *dir) {
  static char line[3 * CX9_FIELD_MAX], p[CX9_FIELD_MAX], enc[OW_MAX];
  char path[1024];
  FILE *in = fopen(cases, "r"), *out, *sw;
  static const char *variants[][3] = {{"dots", "../admin", "."}, {"dots_slash", "../admin", "./"}};
  int v, d, k;
  if (!in) return 1;
  snprintf(path, sizeof path, "%s/cases.csv", dir);
  out = fopen(path, "w");
  if (!out) { fclose(in); return 1; }
  fputs("id,kind,version,verdict_u1,verdict_uinf,decode_passes,safe_path,upstream_u1\n", out);
  while (fgets(line, sizeof line, in)) {
    char *f[CX9_MAX_FIELDS];
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, f, CX9_MAX_FIELDS) != 6 || cx9_unescape(f[2], p, sizeof p) < 0) {
      fclose(in); fclose(out);
      return 1;
    }
    for (v = 0; v < 3; ++v) {
      ow_eval a = ow_evaluate((ow_version)v, p, OW_U1), b = ow_evaluate((ow_version)v, p, OW_UINF);
      fprintf(out, "%s,%s,%s,%s,%s,", f[0], f[1], ow_version_name((ow_version)v),
              ow_verdict_name(a.verdict), ow_verdict_name(b.verdict));
      if (a.s.ok) fprintf(out, "%d", a.s.passes);
      fputc(',', out);
      if (a.verdict == OW_IN_SCOPE || a.verdict == OW_ESCAPES) field(out, a.s.safe);
      fputc(',', out);
      if (a.verdict == OW_IN_SCOPE || a.verdict == OW_ESCAPES) field(out, a.upstream);
      fputc('\n', out);
    }
  }
  fclose(in);
  fclose(out);
  /* Encoding-depth sweep: "../admin" encoded 0..12 times. */
  snprintf(path, sizeof path, "%s/sweep.csv", dir);
  sw = fopen(path, "w");
  if (!sw) return 1;
  fputs("variant,depth,pre_u1,post_u1,post2_u1,pre_uinf,post_uinf,post2_uinf,payload\n", sw);
  for (k = 0; k < 2; ++k) {
    for (d = 0; d <= 12; ++d) {
      if (ow_encode(variants[k][1], variants[k][2], d, enc, sizeof enc) != 0) { fclose(sw); return 1; }
      fprintf(sw, "%s,%d", variants[k][0], d);
      for (v = 0; v < 6; ++v)
        fprintf(sw, ",%s", ow_verdict_name(ow_evaluate((ow_version)(v % 3), enc, v < 3 ? OW_U1 : OW_UINF).verdict));
      fputc(',', sw);
      field(sw, enc);
      fputc('\n', sw);
    }
  }
  fclose(sw);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "results") == 0) return results(argv[2], argv[3]);
  if (argc == 5 && strcmp(argv[1], "case") == 0) {
    static char p[CX9_FIELD_MAX], esc[4 * OW_MAX + 64];
    ow_version v;
    ow_eval e;
    if (strcmp(argv[2], "pre") == 0) v = OW_PRE;
    else if (strcmp(argv[2], "post") == 0) v = OW_POST;
    else if (strcmp(argv[2], "post2") == 0) v = OW_POST2;
    else { fputs("bad version\n", stderr); return 2; }
    if (cx9_unescape(argv[3], p, sizeof p) < 0 ||
        (strcmp(argv[4], "u1") != 0 && strcmp(argv[4], "uinf") != 0)) {
      fputs("bad arguments\n", stderr);
      return 2;
    }
    e = ow_evaluate(v, p, strcmp(argv[4], "u1") == 0 ? OW_U1 : OW_UINF);
    printf("verdict=%s\n", ow_verdict_name(e.verdict));
    if (e.verdict == OW_IN_SCOPE || e.verdict == OW_ESCAPES) {
      cx9_escape(e.s.safe, strlen(e.s.safe), esc, sizeof esc);
      printf("decode_passes=%d\nsafe_path=%s\nproxied (not sent): {base_url}/p/{policy_id}/%s\n",
             e.s.passes, esc, esc);
      cx9_escape(e.upstream, strlen(e.upstream), esc, sizeof esc);
      printf("upstream resolves (assumption %s): %s\n", argv[4], esc);
    }
    return 0;
  }
  fprintf(stderr, "usage: %s results <cases.tsv> <dir> | case pre|post|post2 <path> u1|uinf\n", argv[0]);
  return 2;
}
