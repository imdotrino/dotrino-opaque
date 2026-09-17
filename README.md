# @dotrino/opaque

**Comprobar una contraseña sin que el servidor la vea nunca**, y sin entregarle a nadie algo
con qué adivinarla desde fuera. Es OPAQUE ([RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html))
para el ecosistema [Dotrino](https://dotrino.com/). MIT.

Lo usan las tres versiones del vault —el binario, la pestaña y la extensión— y el gestor de
contraseñas, para el **aparato que se abre con usuario y contraseña**
([`dotrino-passmanager/docs/temporary-access.md`](../dotrino-passmanager/docs/temporary-access.md)).

## Qué hay dentro, y qué no

- **No hay criptografía escrita aquí.** El protocolo es
  [`opaque-ke`](https://github.com/facebook/opaque-ke) 4.0.1 (Meta, auditado por NCC Group en
  2021), compilado a WASM **desde su código fuente** en nuestro CI. Este paquete fija la suite,
  pone nombres a las funciones y comprueba lo que entra.
- **El WASM va dentro del JS** (`build/wasm-bytes.js`), porque el vault se distribuye como
  ejecutable único y ahí no se puede ir a buscar un archivo al lado.
- **Suite fija:** ristretto255 + SHA-512 + 3DH, con Argon2id a 64 MiB, 3 pasadas y 4 carriles
  (la segunda recomendación del RFC 9106; la primera, 2 GiB, no cabe en un navegador). Los
  parámetros están escritos en `wasm/src/lib.rs`, no tomados por defecto de la librería:
  cambiarlos cambia los registros guardados. `suiteId()` los nombra.

## Uso

Todo entra y sale en base64url.

```js
import { client, server } from '@dotrino/opaque'

// Una vez por bóveda. SECRETA.
const setup = server.createSetup()

// Registro
const r1 = client.registrationStart({ password })
const response = server.registrationResponse({ setup, request: r1.request, credentialId: 'ana' })
const r2 = client.registrationFinish({ state: r1.state, response, password, identifiers })
const record = server.registrationFinish({ upload: r2.upload })        // lo que se guarda
// r2.exportKey solo sale de la contraseña: con ella se cifran las llaves del aparato.

// Inicio de sesión
const l1 = client.loginStart({ password })
const s1 = server.loginStart({ setup, record /* o null */, request: l1.request, credentialId: 'ana', identifiers })
const l2 = client.loginFinish({ state: l1.state, response: s1.response, password, identifiers })
const s2 = server.loginFinish({ state: s1.state, finalization: l2.finalization, identifiers })
// l2.sessionKey === s2.sessionKey, y l2.exportKey === r2.exportKey
```

- **`record: null`** para un usuario que no existe: la respuesta es igual por fuera y falla
  igual. Omitirlo es un error (`bad-input`), no un «no existe» por defecto.
- **`identifiers`** (`{ client, server }`) se atan al intercambio; si las dos puntas no pasan
  los mismos, falla como una contraseña equivocada.

## Errores

`OpaqueError` con `code`:

| `code` | Cuándo |
|---|---|
| `login-failed` | contraseña equivocada, usuario inexistente, identificadores que no casan o un mensaje alterado — **el mismo código a propósito** |
| `bad-input` | falta un dato o no se puede leer |
| `protocol` | otro fallo del protocolo |
| `internal` | un fallo que no viene del protocolo |

## Lo que protege y lo que no

- Quien mira la red o se hace pasar por el servidor **no consigue nada con qué adivinar**.
- Quien tiene **la preparación del servidor y el registro** (una copia del disco de la bóveda)
  **sí puede probar contraseñas sin límite**. Cada intento cuesta el Argon2 de arriba: medido,
  unos **100 ms** por intento en Node con este WASM. Un atacante con hardware propio va más
  rápido. Lo que aguanta es la contraseña, así que tiene que ser larga.

## Desarrollo

Necesita Rust (lo fija `wasm/rust-toolchain.toml`) y `wasm-bindgen-cli` en la misma versión que
el crate:

```bash
cargo install wasm-bindgen-cli --version 0.2.100 --locked
npm run build          # WASM → build/
npm test               # la API, los errores y el registro v1 fijado
npm run test:vectors   # los vectores del RFC 9807 contra opaque-ke 4.0.1
```

**La compilación es reproducible**: `npm run build` da en cualquier máquina la misma huella
que CI (`build/wasm.sha256`; `a5a80de4…` para la 0.1.0), porque `scripts/build.mjs` reescribe
las rutas absolutas y el compilador está fijado. Así se comprueba que lo publicado sale de
este fuente.

`test/fixtures/v1.json` es un registro guardado con la 0.1.0. **Toda compilación posterior
tiene que abrirlo**: un registro que deja de abrir deja a alguien sin entrar.

Se publica **desde CI** con un tag `vX.Y.Z` (`.github/workflows/release.yml`), con el SBOM, la
procedencia y la huella del WASM en la release. Nunca `npm publish` a mano.
