// Tentatives de connexion SSH et connexions réussies, en LECTURE SEULE.
//
// Deux sources, lues par lib/probe.js (seul endroit qui lance des binaires) :
//  - le journal du conteneur fail2ban : une ligne « Found » par échec reconnu
//    par le filtre sshd, une ligne « Ban » par IP bannie. On l'ingère par
//    curseur (horodatage Docker) et on cumule par jour dans data/ssh.json : si
//    le conteneur est recréé, ses logs repartent de zéro, nos compteurs non ;
//  - les lignes « Accepted » de /var/log/auth.log, pour repérer une connexion
//    réussie depuis une IP jamais vue, ou par mot de passe.
//
// Rien de ce qui part vers le modèle n'est du texte brut de log : seulement des
// compteurs, des IP et des noms de clés. Un attaquant choisit l'identifiant
// qu'il essaie, mais cet identifiant n'apparaît ni dans les lignes « Found » ni
// dans les lignes « Accepted » (qui exigent un compte existant).
import { probeFail2banLog, probeFail2banBanned, probeSshLogins, probeSshAuthMethods, readAuthorizedKeyNames } from './probe.js'
import { getSshStore, setSshStore } from './store.js'

const DAYS_KEPT = 120
// Au-delà, le détail par IP d'un jour est résumé (nombre d'IP, sous-réseau le
// plus actif) pour que le fichier reste petit.
const IP_DETAIL_DAYS = 3
const LOGIN_ALERT_HOURS = 24
const KNOWN_LOGINS_KEPT = 200
const RECENT_LOGINS_KEPT = 10
const CHART_DAYS = 14
const AUTH_METHODS_TTL_MS = 3600 * 1000
// Pic : la veille dépasse SPIKE_FACTOR fois la médiane des 7 jours précédents.
const SPIKE_FACTOR = 3
const SPIKE_MIN_ATTEMPTS = 1000
// Clés dont l'IP change à chaque connexion (runners de CI) : une IP nouvelle
// n'y est pas un signal.
const ROTATING_KEY_PATTERN = /github-actions|deploy/i

// Jour calendaire à Paris, au format AAAA-MM-JJ.
export const parisDay = (date) => new Date(date).toLocaleDateString('en-CA', { timeZone: 'Europe/Paris' })

// Docker écrit ses horodatages en RFC3339Nano en retirant les zéros de fin
// (« .8271Z »). On complète à 9 chiffres pour que l'ordre des chaînes suive
// l'ordre chronologique, ce qui permet de comparer au curseur sans parser.
export function normalizeDockerTimestamp(stamp) {
  const parsed = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/.exec(stamp)
  if (!parsed) return null
  return `${parsed[1]}.${(parsed[2] || '').padEnd(9, '0').slice(0, 9)}Z`
}

export const subnetOf = (ip) => {
  const octets = ip.split('.')
  return octets.length === 4 ? `${octets.slice(0, 3).join('.')}.0/24` : ip
}

function dayBucket(store, day) {
  if (!store.days[day]) store.days[day] = { attempts: 0, bans: 0, ips: {} }
  return store.days[day]
}

export function emptyStore() {
  return { cursor: null, bansSince: null, days: {}, knownLogins: {}, loginAlerts: [], recentLogins: [], lastLoginAt: null, loginsSeeded: false, authMethods: null }
}

// ─── Journal fail2ban ────────────────────────────────────────────────────
export function ingestFail2banLines(store, lines) {
  const startCursor = store.cursor
  let newestStamp = startCursor
  for (const line of lines) {
    const separator = line.indexOf(' ')
    if (separator < 0) continue
    const stamp = normalizeDockerTimestamp(line.slice(0, separator))
    if (!stamp || (startCursor && stamp <= startCursor)) continue
    if (!newestStamp || stamp > newestStamp) newestStamp = stamp
    // Les jours d'avant ont été repris de auth.log : ils ont des tentatives,
    // mais aucun bannissement, puisque fail2ban n'existait pas encore.
    if (!store.bansSince) store.bansSince = stamp.slice(0, 19) + 'Z'

    const found = /\[sshd\] Found (\S+)/.exec(line)
    const banned = /\[sshd\] Ban (\S+)/.exec(line)
    if (!found && !banned) continue
    // Date() ne lit que les millisecondes : on coupe la fraction à 3 chiffres.
    const bucket = dayBucket(store, parisDay(stamp.slice(0, 23) + 'Z'))
    if (found) {
      bucket.attempts += 1
      if (bucket.ips) bucket.ips[found[1]] = (bucket.ips[found[1]] || 0) + 1
    }
    if (banned) bucket.bans += 1
  }
  store.cursor = newestStamp
}

function topSubnetOf(ips) {
  const bySubnet = {}
  for (const [ip, count] of Object.entries(ips)) bySubnet[subnetOf(ip)] = (bySubnet[subnetOf(ip)] || 0) + count
  const [subnet, count] = Object.entries(bySubnet).sort((first, second) => second[1] - first[1])[0] || []
  return subnet ? { subnet, count } : null
}

export function compactDays(store, now = Date.now()) {
  const detailCutoff = parisDay(now - IP_DETAIL_DAYS * 86400000)
  const keepCutoff = parisDay(now - DAYS_KEPT * 86400000)
  for (const [day, bucket] of Object.entries(store.days)) {
    if (day < keepCutoff) { delete store.days[day]; continue }
    if (day < detailCutoff && bucket.ips) {
      bucket.uniqueIps = Object.keys(bucket.ips).length
      bucket.topSubnet = topSubnetOf(bucket.ips)
      delete bucket.ips
    }
  }
}

// ─── Connexions réussies ─────────────────────────────────────────────────
// Ex. « 2026-10-15T14:24:10.112566+00:00 vps sshd-session[2163834]: Accepted
// publickey for ubuntu from 192.0.2.10 port 51084 ssh2: ED25519 SHA256:Tx… »
const ACCEPTED_PATTERN = /^(\S+)\s+\S+\s+sshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port \d+ \S+?(?:: \S+ (SHA256:\S+))?$/

export function parseLoginLine(line) {
  const parsed = ACCEPTED_PATTERN.exec(line.trim())
  if (!parsed) return null
  const at = new Date(parsed[1])
  if (Number.isNaN(at.getTime())) return null
  return { at: at.toISOString(), method: parsed[2], user: parsed[3], ip: parsed[4], fingerprint: parsed[5] || null }
}

export function ingestLogins(store, logins, keyNames, now = Date.now()) {
  // Premier passage : tout l'historique de auth.log devient « connu », sans
  // alerte, sauf une connexion par mot de passe, qui reste un signal.
  const firstRun = !store.loginsSeeded
  for (const login of logins) {
    if (store.lastLoginAt && login.at <= store.lastLoginAt) continue
    const keyName = login.fingerprint ? keyNames[login.fingerprint] || null : null
    const known = store.knownLogins[login.ip]
    const byPassword = login.method === 'password'
    const rotatingKey = keyName && ROTATING_KEY_PATTERN.test(keyName)
    if (byPassword || (!firstRun && !known && !rotatingKey)) {
      store.loginAlerts.push({ ...login, key: keyName, reason: byPassword ? 'password' : 'new-ip' })
    }
    store.knownLogins[login.ip] = { firstSeen: known?.firstSeen || login.at, lastSeen: login.at, user: login.user, key: keyName }
    // Une entrée par couple (IP, compte, clé) : une session de travail ouvre
    // des dizaines de connexions depuis la même machine, on garde la dernière.
    const sameOrigin = (entry) => entry.ip === login.ip && entry.user === login.user && entry.key === keyName && entry.method === login.method
    store.recentLogins = store.recentLogins.filter((entry) => !sameOrigin(entry))
    store.recentLogins.push({ at: login.at, ip: login.ip, user: login.user, method: login.method, key: keyName })
    store.lastLoginAt = login.at
  }
  store.loginsSeeded = true

  const alertCutoff = new Date(now - LOGIN_ALERT_HOURS * 3600000).toISOString()
  store.loginAlerts = store.loginAlerts.filter((alert) => alert.at >= alertCutoff)
  store.recentLogins = store.recentLogins.slice(-RECENT_LOGINS_KEPT)
  const knownEntries = Object.entries(store.knownLogins)
  if (knownEntries.length > KNOWN_LOGINS_KEPT) {
    store.knownLogins = Object.fromEntries(knownEntries
      .sort((first, second) => second[1].lastSeen.localeCompare(first[1].lastSeen))
      .slice(0, KNOWN_LOGINS_KEPT))
  }
}

// ─── Résumé servi au front et au modèle ──────────────────────────────────
const median = (values) => {
  const sorted = [...values].sort((first, second) => first - second)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
}

const parisTime = (iso) => new Date(iso).toLocaleString('fr-FR', { timeZone: 'Europe/Paris', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
// Heure de Paris déjà formatée : sinon le modèle lit l'ISO UTC comme une heure locale.
const withParisTime = (entry) => ({ ...entry, atParis: parisTime(entry.at) })

export function sshSummary(store, bannedNow, now = Date.now()) {
  const dayAt = (offset) => parisDay(now - offset * 86400000)
  const summarizeDay = (day) => {
    const bucket = store.days[day]
    if (!bucket) return null
    return {
      day,
      attempts: bucket.attempts,
      bans: bucket.bans,
      uniqueIps: bucket.ips ? Object.keys(bucket.ips).length : bucket.uniqueIps ?? null,
      topSubnet: bucket.ips ? topSubnetOf(bucket.ips) : bucket.topSubnet ?? null,
    }
  }

  const trackedDays = Object.keys(store.days).sort()
  const firstDay = trackedDays[0] || null
  const days = []
  for (let offset = CHART_DAYS - 1; offset >= 0; offset -= 1) {
    const day = dayAt(offset)
    if (firstDay && day < firstDay) continue
    // Aucun compteur pour ce jour = aucune mesure (machine éteinte, journal
    // perdu), pas zéro tentative : le front l'affiche comme un trou.
    days.push(summarizeDay(day) || { day, attempts: null, bans: null, uniqueIps: null, topSubnet: null })
  }

  const yesterday = summarizeDay(dayAt(1))
  const previous = []
  for (let offset = 2; offset <= 8; offset += 1) {
    const bucket = store.days[dayAt(offset)]
    if (bucket) previous.push(bucket.attempts)
  }
  let spike = null
  if (yesterday && previous.length === 7) {
    const typical = median(previous)
    if (yesterday.attempts >= SPIKE_MIN_ATTEMPTS && yesterday.attempts > SPIKE_FACTOR * typical) {
      spike = { day: yesterday.day, attempts: yesterday.attempts, median: typical }
    }
  }

  const methods = store.authMethods?.methods || null
  return {
    since: firstDay,
    bansSince: store.bansSince,
    today: summarizeDay(dayAt(0)),
    yesterday,
    bannedNow,
    days,
    spike,
    authMethods: methods,
    passwordAuth: methods ? methods.includes('password') || methods.includes('keyboard-interactive') : null,
    loginAlerts: store.loginAlerts.map(withParisTime),
    recentLogins: store.recentLogins.slice().reverse().map(withParisTime),
  }
}

// ─── Passage complet ─────────────────────────────────────────────────────
export async function collectSsh() {
  const store = { ...emptyStore(), ...getSshStore() }
  const [lines, bannedNow, loginLines, keyNames] = await Promise.all([
    probeFail2banLog(store.cursor),
    probeFail2banBanned().catch(() => null),
    probeSshLogins().catch(() => []),
    readAuthorizedKeyNames(),
  ])
  ingestFail2banLines(store, lines)
  ingestLogins(store, loginLines.map(parseLoginLine).filter(Boolean), keyNames)
  // Une sonde par heure suffit : la conf SSH ne change pas toutes les 5 min.
  if (!store.authMethods || Date.now() - Date.parse(store.authMethods.at) > AUTH_METHODS_TTL_MS) {
    try {
      store.authMethods = { at: new Date().toISOString(), methods: await probeSshAuthMethods() }
    } catch (probeError) {
      console.error('gardien ssh auth:', probeError.message)
    }
  }
  compactDays(store)
  setSshStore(store)
  return sshSummary(store, bannedNow)
}
