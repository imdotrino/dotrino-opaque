//! OPAQUE (RFC 9807) para el ecosistema Dotrino.
//!
//! Aquí NO hay criptografía propia: todo el protocolo es de `opaque-ke` (Meta, auditado por
//! NCC Group). Este crate hace tres cosas y ninguna más:
//!
//!   1. fija UNA suite, para que las tres versiones del vault y el gestor hablen igual;
//!   2. fija los parámetros de Argon2 a mano, para que una versión nueva de la librería no
//!      cambie en silencio los bytes de un registro ya guardado;
//!   3. traduce cada mensaje y cada estado a base64url, que es lo que JS puede mover.
//!
//! Errores: cada `JsError` empieza por un código estable (`bad-input:`, `login-failed:`,
//! `protocol:`). El JS de `src/index.js` lo separa en `e.code`, porque un error que cruza
//! procesos se comprueba por su código y no por la frase.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use js_sys::{Object, Reflect};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::ProtocolError;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

/// La suite. Ristretto255 + SHA-512 + 3DH es la primera configuración del RFC 9807.
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

/// El nombre de la suite, parámetros incluidos. Va guardado junto a cada registro: si algún
/// día cambia, un registro viejo se reconoce en vez de fallar como «contraseña incorrecta».
pub const SUITE_ID: &str = "opaque-rfc9807/ristretto255-sha512-3dh/argon2id-m65536-t3-p4";

/// Argon2id con la segunda recomendación del RFC 9106 §4: 64 MiB, 3 pasadas, 4 carriles.
/// La primera (2 GiB) no cabe en un navegador. Fijado aquí y no por defecto de la librería.
fn ksf() -> argon2::Argon2<'static> {
    let params = argon2::Params::new(65_536, 3, 4, None).expect("fixed Argon2 parameters are valid");
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn err(code: &str, detail: impl std::fmt::Display) -> JsError {
    JsError::new(&format!("{code}: {detail}"))
}

fn protocol(e: ProtocolError) -> JsError {
    match e {
        ProtocolError::InvalidLoginError => err("login-failed", "the password or the server does not match"),
        other => err("protocol", format!("{other:?}")),
    }
}

fn dec(field: &str, s: &str) -> Result<Vec<u8>, JsError> {
    B64.decode(s).map_err(|e| err("bad-input", format!("{field} is not base64url: {e}")))
}

fn enc(bytes: &[u8]) -> JsValue {
    JsValue::from_str(&B64.encode(bytes))
}

fn obj(pairs: &[(&str, JsValue)]) -> Result<Object, JsError> {
    let o = Object::new();
    for (k, v) in pairs {
        Reflect::set(&o, &JsValue::from_str(k), v).map_err(|_| err("protocol", "could not build the result"))?;
    }
    Ok(o)
}

fn ids<'a>(client: &'a Option<String>, server: &'a Option<String>) -> Identifiers<'a> {
    Identifiers {
        client: client.as_deref().map(str::as_bytes),
        server: server.as_deref().map(str::as_bytes),
    }
}

#[wasm_bindgen(js_name = suiteId)]
pub fn suite_id() -> String {
    SUITE_ID.to_string()
}

// ---- servidor: la preparación, una vez por bóveda -----------------------------------------

/// Genera la preparación del servidor: la semilla del OPRF y su par de llaves. Es SECRETA.
#[wasm_bindgen(js_name = serverCreateSetup)]
pub fn server_create_setup() -> String {
    let setup = ServerSetup::<Suite>::new(&mut OsRng);
    B64.encode(setup.serialize())
}

#[wasm_bindgen(js_name = serverPublicKey)]
pub fn server_public_key(setup: &str) -> Result<String, JsError> {
    let setup = ServerSetup::<Suite>::deserialize(&dec("setup", setup)?).map_err(protocol)?;
    Ok(B64.encode(setup.keypair().public().serialize()))
}

// ---- registro -----------------------------------------------------------------------------

#[wasm_bindgen(js_name = clientRegistrationStart)]
pub fn client_registration_start(password: &str) -> Result<Object, JsError> {
    let r = ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(protocol)?;
    obj(&[("state", enc(&r.state.serialize())), ("request", enc(&r.message.serialize()))])
}

#[wasm_bindgen(js_name = serverRegistrationResponse)]
pub fn server_registration_response(setup: &str, request: &str, credential_id: &str) -> Result<String, JsError> {
    let setup = ServerSetup::<Suite>::deserialize(&dec("setup", setup)?).map_err(protocol)?;
    let request = RegistrationRequest::<Suite>::deserialize(&dec("request", request)?).map_err(protocol)?;
    let r = ServerRegistration::<Suite>::start(&setup, request, credential_id.as_bytes()).map_err(protocol)?;
    Ok(B64.encode(r.message.serialize()))
}

#[wasm_bindgen(js_name = clientRegistrationFinish)]
pub fn client_registration_finish(
    state: &str,
    response: &str,
    password: &str,
    client_identifier: Option<String>,
    server_identifier: Option<String>,
) -> Result<Object, JsError> {
    let state = ClientRegistration::<Suite>::deserialize(&dec("state", state)?).map_err(protocol)?;
    let response = RegistrationResponse::<Suite>::deserialize(&dec("response", response)?).map_err(protocol)?;
    let ksf = ksf();
    let params = ClientRegistrationFinishParameters::new(ids(&client_identifier, &server_identifier), Some(&ksf));
    let r = state.finish(&mut OsRng, password.as_bytes(), response, params).map_err(protocol)?;
    obj(&[
        ("upload", enc(&r.message.serialize())),
        ("exportKey", enc(&r.export_key)),
        ("serverPublicKey", enc(&r.server_s_pk.serialize())),
    ])
}

/// Lo que el servidor guarda de un usuario. No contiene la contraseña ni nada con qué
/// probarla sin la preparación del servidor.
#[wasm_bindgen(js_name = serverRegistrationFinish)]
pub fn server_registration_finish(upload: &str) -> Result<String, JsError> {
    let upload = RegistrationUpload::<Suite>::deserialize(&dec("upload", upload)?).map_err(protocol)?;
    Ok(B64.encode(ServerRegistration::<Suite>::finish(upload).serialize()))
}

// ---- inicio de sesión ---------------------------------------------------------------------

#[wasm_bindgen(js_name = clientLoginStart)]
pub fn client_login_start(password: &str) -> Result<Object, JsError> {
    let r = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).map_err(protocol)?;
    obj(&[("state", enc(&r.state.serialize())), ("request", enc(&r.message.serialize()))])
}

/// Sin registro (`record` ausente) responde igual, con uno inventado: desde fuera no se
/// distingue un usuario que no existe de una contraseña equivocada.
#[wasm_bindgen(js_name = serverLoginStart)]
pub fn server_login_start(
    setup: &str,
    record: Option<String>,
    request: &str,
    credential_id: &str,
    client_identifier: Option<String>,
    server_identifier: Option<String>,
) -> Result<Object, JsError> {
    let setup = ServerSetup::<Suite>::deserialize(&dec("setup", setup)?).map_err(protocol)?;
    let record = match record {
        Some(r) => Some(ServerRegistration::<Suite>::deserialize(&dec("record", &r)?).map_err(protocol)?),
        None => None,
    };
    let request = CredentialRequest::<Suite>::deserialize(&dec("request", request)?).map_err(protocol)?;
    let params = ServerLoginParameters { context: None, identifiers: ids(&client_identifier, &server_identifier) };
    let r = ServerLogin::start(&mut OsRng, &setup, record, request, credential_id.as_bytes(), params).map_err(protocol)?;
    obj(&[("state", enc(&r.state.serialize())), ("response", enc(&r.message.serialize()))])
}

#[wasm_bindgen(js_name = clientLoginFinish)]
pub fn client_login_finish(
    state: &str,
    response: &str,
    password: &str,
    client_identifier: Option<String>,
    server_identifier: Option<String>,
) -> Result<Object, JsError> {
    let state = ClientLogin::<Suite>::deserialize(&dec("state", state)?).map_err(protocol)?;
    let response = CredentialResponse::<Suite>::deserialize(&dec("response", response)?).map_err(protocol)?;
    let ksf = ksf();
    let params = ClientLoginFinishParameters::new(None, ids(&client_identifier, &server_identifier), Some(&ksf));
    let r = state.finish(&mut OsRng, password.as_bytes(), response, params).map_err(protocol)?;
    obj(&[
        ("finalization", enc(&r.message.serialize())),
        ("sessionKey", enc(&r.session_key)),
        ("exportKey", enc(&r.export_key)),
        ("serverPublicKey", enc(&r.server_s_pk.serialize())),
    ])
}

#[wasm_bindgen(js_name = serverLoginFinish)]
pub fn server_login_finish(
    state: &str,
    finalization: &str,
    client_identifier: Option<String>,
    server_identifier: Option<String>,
) -> Result<Object, JsError> {
    let state = ServerLogin::<Suite>::deserialize(&dec("state", state)?).map_err(protocol)?;
    let finalization = CredentialFinalization::<Suite>::deserialize(&dec("finalization", finalization)?).map_err(protocol)?;
    let params = ServerLoginParameters { context: None, identifiers: ids(&client_identifier, &server_identifier) };
    let r = state.finish(finalization, params).map_err(protocol)?;
    obj(&[("sessionKey", enc(&r.session_key))])
}
