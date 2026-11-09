# cortex9-open-webui-proxy-multidecode-traversal-model

Modelo offline de **CVE-2026-54017** (GHSA-r2wg-2mcr-66rv, CWE-22/CWE-918):
el proxy de terminales de Open WebUI sanitizaba la ruta con un solo
`urllib.parse.unquote()`, después `posixpath.normpath()` y un chequeo de
`..`, y reenviaba el resultado *decodificado* a
`{base_url}/p/{policy_id}/{safe_path}`. Un `%252e%252e` doblemente
codificado quedaba como `%2e%2e` tras una decodificación, pasaba el chequeo
y (según el GHSA) el servidor de terminales lo volvía a decodificar a `..`.
El fix 0354775 (en v0.9.6) decodifica hasta que no cambia, con un máximo de
8 pasadas; el commit posterior 05098d2 (primero en v0.10.0) falla cerrado
si al llegar al tope el valor todavía se decodificaría.
Educativo, determinista, C11 con ASan/UBSan. **No se ejecuta Open WebUI, no
se hace ningún request y nada toca la red.**

## Qué se modela

`backend/open_webui/routers/terminals.py`, `_sanitize_proxy_path()`:
`pre` d4030a8 línea 38 (una pasada), `post` 0354775 líneas 40-45 (hasta
estabilizar, tope 8), `post2` 05098d2 líneas 46-48 (falla cerrado). El resto
(`normpath`, `lstrip('/')`, `startswith('..')`, barra final) y la URL
`/p/{policy_id}/{safe_path}` son iguales en las tres versiones y se citan
con su línea en el README en inglés.

El servidor de terminales **no** sale de estas fuentes: se evalúan dos
supuestos, `U1` (decodifica una vez, lo que describe el GHSA) y `UINF`
(decodifica hasta estabilizar, un "qué pasaría si" más estricto).

## Evidencia diferencial

| Profundidad | pre U1 | post U1 | post2 U1 |
|---|---|---|---|
| 2 (`%252e%252e`) | **ESCAPES** | REJECTED | REJECTED |
| 9 | IN_SCOPE | **ESCAPES** | REJECTED |
| 10-12 | IN_SCOPE | IN_SCOPE | REJECTED |

Con `UINF`, `pre` escapa desde la profundidad 2 y `post` desde la 9;
`post2` nunca. Detalle en `results/sweep.csv` y `results/cases.csv`.

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/owui case post '%25252525252525252e%25252525252525252e/admin' u1
```

Fuentes: [SOURCES.md](SOURCES.md). Límites: [LIMITATIONS.md](LIMITATIONS.md).
Ejercicios: [PRACTICE.md](PRACTICE.md). Licencia: Apache-2.0.
