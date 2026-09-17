// OPAQUE, visto desde fuera: lo que el vault y el gestor van a dar por hecho.
//
// El protocolo en sí lo prueban los vectores del RFC 9807 contra opaque-ke
// (`npm run test:vectors`). Aquí se prueba lo que añade este paquete: la suite fijada, los
// códigos de error, que un usuario inexistente no se distinga, y que un registro guardado
// siga abriendo con cada compilación nueva.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { client, server, suiteId, OpaqueError } from '../src/index.js'

const fixture = JSON.parse(readFileSync(new URL('./fixtures/v1.json', import.meta.url), 'utf8'))

function register ({ setup, password, credentialId, identifiers = {} }) {
  const start = client.registrationStart({ password })
  const response = server.registrationResponse({ setup, request: start.request, credentialId })
  const finish = client.registrationFinish({ state: start.state, response, password, identifiers })
  return { record: server.registrationFinish({ upload: finish.upload }), exportKey: finish.exportKey, serverPublicKey: finish.serverPublicKey }
}

function login ({ setup, record, password, credentialId, clientIds = {}, serverIds = clientIds }) {
  const start = client.loginStart({ password })
  const s = server.loginStart({ setup, record, request: start.request, credentialId, identifiers: serverIds })
  const c = client.loginFinish({ state: start.state, response: s.response, password, identifiers: clientIds })
  const f = server.loginFinish({ state: s.state, finalization: c.finalization, identifiers: serverIds })
  return { client: c, server: f }
}

const failsWith = (code, fn) => assert.throws(fn, (e) => e instanceof OpaqueError && e.code === code)

test('the suite is fixed, parameters included', () => {
  assert.equal(suiteId(), 'opaque-rfc9807/ristretto255-sha512-3dh/argon2id-m65536-t3-p4')
})

test('register then log in: both ends agree on the session key, and the export key is stable', () => {
  const setup = server.createSetup()
  const reg = register({ setup, password: 'correct horse', credentialId: 'ana' })
  const r = login({ setup, record: reg.record, password: 'correct horse', credentialId: 'ana' })
  assert.equal(r.client.sessionKey, r.server.sessionKey)
  assert.equal(r.client.exportKey, reg.exportKey, 'the export key only depends on the password and the record')
  assert.equal(r.client.serverPublicKey, server.publicKey({ setup }))
})

test('a wrong password fails as login-failed', () => {
  const setup = server.createSetup()
  const { record } = register({ setup, password: 'correct horse', credentialId: 'ana' })
  failsWith('login-failed', () => login({ setup, record, password: 'wrong horse', credentialId: 'ana' }))
})

test('an unknown user gets a response that looks the same, and fails the same way', () => {
  const setup = server.createSetup()
  const { record } = register({ setup, password: 'x', credentialId: 'ana' })
  const start = client.loginStart({ password: 'x' })
  const known = server.loginStart({ setup, record, request: start.request, credentialId: 'ana' })
  const unknown = server.loginStart({ setup, record: null, request: start.request, credentialId: 'nobody' })
  assert.equal(unknown.response.length, known.response.length, 'same size: nothing tells them apart')
  failsWith('login-failed', () => client.loginFinish({ state: start.state, response: unknown.response, password: 'x' }))
})

test('identifiers are bound: if the two ends disagree, it fails like a wrong password', () => {
  const setup = server.createSetup()
  const ids = { client: 'ana', server: 'AB12-CD34-EF56' }
  const { record } = register({ setup, password: 'p', credentialId: 'ana', identifiers: ids })
  const ok = login({ setup, record, password: 'p', credentialId: 'ana', clientIds: ids })
  assert.equal(ok.client.sessionKey, ok.server.sessionKey)
  failsWith('login-failed', () => login({ setup, record, password: 'p', credentialId: 'ana', clientIds: { client: 'ana', server: 'FFFF-FFFF-FFFF' }, serverIds: ids }))
})

test('a tampered finalization is rejected by the server', () => {
  const setup = server.createSetup()
  const { record } = register({ setup, password: 'p', credentialId: 'ana' })
  const start = client.loginStart({ password: 'p' })
  const s = server.loginStart({ setup, record, request: start.request, credentialId: 'ana' })
  const c = client.loginFinish({ state: start.state, response: s.response, password: 'p' })
  const bytes = Buffer.from(c.finalization, 'base64url')
  bytes[0] ^= 1
  failsWith('login-failed', () => server.loginFinish({ state: s.state, finalization: bytes.toString('base64url') }))
})

test('a record from another server setup does not open', () => {
  const a = server.createSetup()
  const b = server.createSetup()
  const { record } = register({ setup: a, password: 'p', credentialId: 'ana' })
  failsWith('login-failed', () => login({ setup: b, record, password: 'p', credentialId: 'ana' }))
})

test('missing or unreadable input is bad-input, never a silent default', () => {
  const setup = server.createSetup()
  failsWith('bad-input', () => client.loginStart({}))
  failsWith('bad-input', () => server.registrationResponse({ setup, request: '', credentialId: 'ana' }))
  failsWith('bad-input', () => server.publicKey({ setup: 'not base64url!' }))
  const start = client.loginStart({ password: 'p' })
  // `record` omitted is not the same as `null`: the caller has to say the user is unknown.
  failsWith('bad-input', () => server.loginStart({ setup, request: start.request, credentialId: 'ana' }))
  failsWith('bad-input', () => server.loginStart({ setup, record: null, request: start.request, credentialId: 'ana', identifiers: { client: '' } }))
})

test('the v1 fixture still opens with this build (records must survive upgrades)', () => {
  assert.equal(fixture.suite, suiteId(), 'if the suite changed, old records need a migration path first')
  const r = login({
    setup: fixture.setup,
    record: fixture.record,
    password: fixture.password,
    credentialId: fixture.credentialId,
    clientIds: fixture.identifiers,
  })
  assert.equal(r.client.sessionKey, r.server.sessionKey)
  assert.equal(r.client.exportKey, fixture.exportKey, 'same password + same record → same export key, forever')
  assert.equal(server.publicKey({ setup: fixture.setup }), fixture.serverPublicKey)
})
