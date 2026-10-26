// Stockage en fichiers JSON : un fichier = un morceau d'état. Pas de base : le
// Gardien n'a que quelques kilo-octets à retenir.
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// La démo écrit dans son propre dossier : elle ne mélange jamais ses fausses
// données avec celles d'une vraie machine.
const DATA_DIR = process.env.GARDIEN_DATA_DIR
  ? resolve(process.env.GARDIEN_DATA_DIR)
  : fileURLToPath(new URL('../data/', import.meta.url))
mkdirSync(DATA_DIR, { recursive: true })

const fileUrl = (name) => join(DATA_DIR, name)

export function resetDataDir() {
  rmSync(DATA_DIR, { recursive: true, force: true })
  mkdirSync(DATA_DIR, { recursive: true })
}

export function readJson(name, fallback) {
  try {
    return JSON.parse(readFileSync(fileUrl(name), 'utf8'))
  } catch (readError) {
    return fallback
  }
}

export function writeJson(name, data) {
  writeFileSync(fileUrl(name), JSON.stringify(data, null, 2))
}

// ─── Accès typés ─────────────────────────────────────────────────────────

// Dernier état collecté, servi tel quel au front entre deux collectes.
export const getState = () => readJson('state.json', null)
export const setState = (state) => writeJson('state.json', state)

// Incidents : [{ id, key, kind, severity, title, detail, firstSeenAt, lastSeenAt, resolvedAt }]
export const getIncidents = () => readJson('incidents.json', [])
export const setIncidents = (list) => writeJson('incidents.json', list)

// Journal du Gardien : [{ id, date, kind, body }]
export const getJournal = () => readJson('journal.json', [])
export const setJournal = (entries) => writeJson('journal.json', entries.slice(-300))

// Historique de la conversation.
export const getChatHistory = () => readJson('history.json', [])
export const setChatHistory = (messages) => writeJson('history.json', messages.slice(-100))

// Anti-spam des notifications : { [incidentKey]: isoDate du dernier push }
export const getPushState = () => readJson('pushed.json', {})
export const setPushState = (state) => writeJson('pushed.json', state)

// Échantillons de compteurs de redémarrage. pm2 ne donne qu'un cumul depuis le
// démarrage : pour savoir « combien de fois en 24 h », il faut nos propres
// points de mesure. [{ at: iso, counts: { 'scraper': 32, ... } }]
export const getSamples = () => readJson('samples.json', [])
export const setSamples = (samples) => writeJson('samples.json', samples.slice(-5000))

export function appendSample(counts) {
  const samples = getSamples()
  samples.push({ at: new Date().toISOString(), counts })
  // 15 jours à une collecte / 5 min = ~4300 points ; on garde large mais borné.
  writeJson('samples.json', samples.slice(-5000))
}

// SSH : curseur du journal fail2ban, compteurs par jour, connexions réussies
// connues et alertes en cours. Structure détaillée dans lib/ssh.js.
export const getSshStore = () => readJson('ssh.json', {})
export const setSshStore = (store) => writeJson('ssh.json', store)

// Cache des certificats (une poignée de handshakes TLS, rafraîchis 4x/jour).
export const getCertCache = () => readJson('certs.json', null)
export const setCertCache = (cache) => writeJson('certs.json', cache)
