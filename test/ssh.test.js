// Ingestion des journaux SSH : curseur, compteurs par jour, alertes de connexion.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeDockerTimestamp, ingestFail2banLines, parseLoginLine, ingestLogins, emptyStore, subnetOf } from '../lib/ssh.js'

test('normalizeDockerTimestamp complète la fraction à 9 chiffres pour un tri lexical correct', () => {
  assert.equal(normalizeDockerTimestamp('2026-10-26T10:15:02.8271Z'), '2026-10-26T10:15:02.827100000Z')
  assert.equal(normalizeDockerTimestamp('2026-10-26T10:15:02Z'), '2026-10-26T10:15:02.000000000Z')
  assert.equal(normalizeDockerTimestamp('pas une date'), null)
})

test('ingestFail2banLines compte tentatives et bannissements, et ne relit jamais avant le curseur', () => {
  const store = emptyStore()
  const lines = [
    '2026-10-26T10:00:00.1Z x fail2ban.filter [1]: INFO [sshd] Found 203.0.113.5',
    '2026-10-26T10:00:01.2Z x fail2ban.filter [1]: INFO [sshd] Found 203.0.113.5',
    '2026-10-26T10:00:02.3Z x fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.5',
  ]
  ingestFail2banLines(store, lines)
  const [day] = Object.values(store.days)
  assert.equal(day.attempts, 2)
  assert.equal(day.bans, 1)

  // Deuxième passage avec les mêmes lignes : rien ne doit être recompté.
  ingestFail2banLines(store, lines)
  assert.equal(Object.values(store.days)[0].attempts, 2)
})

test('parseLoginLine extrait méthode, compte, IP et empreinte de clé', () => {
  const login = parseLoginLine('2026-10-15T14:24:10.112566+00:00 vps sshd-session[2163834]: Accepted publickey for ubuntu from 192.0.2.10 port 51084 ssh2: ED25519 SHA256:abc')
  assert.deepEqual(login, { at: '2026-10-15T14:24:10.112Z', method: 'publickey', user: 'ubuntu', ip: '192.0.2.10', fingerprint: 'SHA256:abc' })
  assert.equal(parseLoginLine('Failed password for root from 203.0.113.9'), null)
})

test('ingestLogins : le premier passage apprend les IP sans alerter, une IP nouvelle ensuite alerte', () => {
  const now = Date.parse('2026-10-26T12:00:00Z')
  const store = emptyStore()
  const known = { at: '2026-10-26T08:00:00.000Z', method: 'publickey', user: 'ubuntu', ip: '192.0.2.10', fingerprint: 'SHA256:laptop' }
  ingestLogins(store, [known], { 'SHA256:laptop': 'laptop' }, now)
  assert.equal(store.loginAlerts.length, 0)

  const stranger = { ...known, at: '2026-10-26T11:00:00.000Z', ip: '198.51.100.66' }
  ingestLogins(store, [stranger], { 'SHA256:laptop': 'laptop' }, now)
  assert.equal(store.loginAlerts.length, 1)
  assert.equal(store.loginAlerts[0].reason, 'new-ip')
})

test('ingestLogins alerte toujours sur une connexion par mot de passe, même au premier passage', () => {
  const store = emptyStore()
  const login = { at: '2026-10-26T11:00:00.000Z', method: 'password', user: 'ubuntu', ip: '192.0.2.10', fingerprint: null }
  ingestLogins(store, [login], {}, Date.parse('2026-10-26T12:00:00Z'))
  assert.equal(store.loginAlerts[0].reason, 'password')
})

test('ingestLogins ignore une IP nouvelle pour une clé de CI, dont l\'IP change à chaque run', () => {
  const now = Date.parse('2026-10-26T12:00:00Z')
  const store = emptyStore()
  ingestLogins(store, [], {}, now)
  const ciLogin = { at: '2026-10-26T11:00:00.000Z', method: 'publickey', user: 'deploy', ip: '198.51.100.77', fingerprint: 'SHA256:ci' }
  ingestLogins(store, [ciLogin], { 'SHA256:ci': 'github-actions-deploy' }, now)
  assert.equal(store.loginAlerts.length, 0)
})

test('subnetOf regroupe une IPv4 par /24', () => {
  assert.equal(subnetOf('203.0.113.42'), '203.0.113.0/24')
})
