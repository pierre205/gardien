// Règles de détection et fenêtre glissante des redémarrages.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluate, restartsOverWindow, worstSeverity, THRESHOLDS } from '../lib/incidents.js'

const HOUR = 3600000

test('restartsOverWindow calcule un delta contre le plus vieil échantillon de la fenêtre', () => {
  const now = Date.now()
  const samples = [
    { at: new Date(now - 30 * HOUR).toISOString(), counts: { api: 10 } },
    { at: new Date(now - 20 * HOUR).toISOString(), counts: { api: 12 } },
    { at: new Date(now - 1 * HOUR).toISOString(), counts: { api: 19 } },
  ]
  assert.equal(restartsOverWindow(samples, 'api', 24), 7)
})

test('restartsOverWindow ne conclut rien si le cumul recule (pm2 redémarré)', () => {
  const now = Date.now()
  const samples = [
    { at: new Date(now - 10 * HOUR).toISOString(), counts: { api: 40 } },
    { at: new Date(now - 1 * HOUR).toISOString(), counts: { api: 2 } },
  ]
  assert.equal(restartsOverWindow(samples, 'api', 24), null)
})

test('evaluate ignore un service arrêté volontairement', () => {
  const findings = evaluate({ pm2: [{ name: 'bot', status: 'stopped', restarts: 0, ignored: true }] })
  assert.equal(findings.length, 0)
})

test('evaluate distingue avertissement et critique sur le disque', () => {
  const disk = (usePct) => ({ system: { disk: { usePct, freeBytes: 1, totalBytes: 2 } } })
  assert.equal(evaluate(disk(THRESHOLDS.diskWarnPct))[0].severity, 'warn')
  assert.equal(evaluate(disk(THRESHOLDS.diskCritPct))[0].severity, 'crit')
  assert.equal(evaluate(disk(THRESHOLDS.diskWarnPct - 1)).length, 0)
})

test('evaluate signale une boucle de redémarrage selon les seuils sur 24 h', () => {
  const restarts = (last24h) => ({ restarts: [{ name: 'scraper', last24h, last7d: last24h, ignored: false }] })
  assert.equal(evaluate(restarts(THRESHOLDS.restartsWarn24h))[0].severity, 'warn')
  assert.equal(evaluate(restarts(THRESHOLDS.restartsCrit24h))[0].severity, 'crit')
})

test('evaluate signale la connexion SSH par mot de passe encore ouverte', () => {
  const findings = evaluate({ ssh: { passwordAuth: true, authMethods: ['publickey', 'password'], loginAlerts: [] } })
  assert.equal(findings[0].key, 'ssh-password-auth')
})

test('worstSeverity retient la pire sévérité', () => {
  assert.equal(worstSeverity([{ severity: 'warn' }, { severity: 'crit' }, { severity: 'good' }]), 'crit')
  assert.equal(worstSeverity([]), 'good')
})
