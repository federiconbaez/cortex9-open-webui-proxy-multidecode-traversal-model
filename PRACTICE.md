# Guía práctica (8 niveles)

Ejercicios **offline y locales** sobre decodificación múltiple de rutas en
un proxy. No se ejecuta Open WebUI ni se hace ningún request. Cada respuesta
está comprobada en `tests/test_model.c` (`practice_level_N`), compilado con
ASan/UBSan. Si querés probar con software real, hacelo solo en un lab
propio (una VM o contenedor tuyo, sin red, con un servidor de juguete que
registre la ruta recibida), nunca contra sistemas de terceros.

Comandos: `sh scripts/build.sh test`; después de `sh scripts/build.sh
results /tmp/r`: `./build/owui case pre|post|post2 '<ruta>' u1|uinf`.

**Básico**

1. **El camino normal.** `files/report.txt` en `pre`. ¿Qué ruta resuelve el
   servidor? (`practice_level_1`: `/p/pol/files/report.txt`, `IN_SCOPE`)
2. **Una codificación.** `%2e%2e/admin` en `pre`. (`practice_level_2`:
   `REJECTED`: una pasada ya da `..`)
3. **Dos codificaciones.** `%252e%252e/admin` en `pre`. ¿Qué se reenvía y
   qué resuelve el servidor con `U1`? (`practice_level_3`: reenvía
   `%2e%2e/admin`, resuelve `/p/admin`, `ESCAPES`)

**Intermedio**

4. **El fix.** Lo mismo en `post`. (`practice_level_4`: `REJECTED`)
5. **El tope.** `..` codificado 9 veces + `/admin` en `post`. ¿Cuántas
   pasadas hace y qué pasa? (`practice_level_5`: 8 pasadas, `ESCAPES`)
6. **Fallar cerrado.** La misma ruta en `post2`. (`practice_level_6`:
   `REJECTED`)

**Avanzado**

7. **El supuesto importa.** `%25252e%25252e/admin` en `pre` con `u1` y con
   `uinf`. (`practice_level_7`: `IN_SCOPE` con U1, `ESCAPES` con UINF)
8. **Falso positivo.** `..hidden/x` en `post2`. ¿Por qué se rechaza un
   nombre legítimo? (`practice_level_8`: `REJECTED` por `startswith('..')`)

Más allá: agregá un caso a `fixtures/cases.tsv` con su etiqueta a mano,
regenerá `fixtures/expected.tsv` con `scripts/derive_expected.py` y
comprobá que el modelo en C coincide. Pensá en tu propio código: ¿dónde
decodificás una ruta antes de validarla, y quién la decodifica después?
La regla de oro: validar exactamente lo que el siguiente salto va a
interpretar, o reenviar sin decodificar.
