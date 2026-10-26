import { useEffect, useRef, useState } from 'react'
import { api } from './api.js'
import { richText } from './format.jsx'

const VIEWS = [
  { key: 'sante', label: 'Santé' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'chat', label: 'Gardien' },
  { key: 'journal', label: 'Journal' },
]

const gib = (bytes) => (bytes == null ? '—' : `${(bytes / 1024 ** 3).toFixed(1)} G`)
// Taille d'un fichier : en Mo sous le Go, sinon un dump de 48 Mo s'afficherait « 0.0 G ».
const fileSize = (bytes) => (bytes == null ? '—' : bytes < 1024 ** 3 ? `${Math.round(bytes / 1024 ** 2)} M` : gib(bytes))

const duration = (seconds) => {
  if (seconds == null) return '—'
  const days = Math.floor(seconds / 86400)
  if (days >= 1) return `${days} j`
  const hours = Math.floor(seconds / 3600)
  if (hours >= 1) return `${hours} h`
  return `${Math.max(1, Math.floor(seconds / 60))} min`
}

const shortDateTime = (iso) =>
  iso ? new Date(iso).toLocaleString('fr-FR', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : ''

const shortDate = (iso) =>
  iso ? new Date(iso).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long' }) : ''

const VERDICT = {
  crit: { label: 'Il faut agir', glyph: '■', className: 'verdict-crit' },
  warn: { label: 'Un point à surveiller', glyph: '!', className: 'verdict-warn' },
  good: { label: 'Tout est en ordre', glyph: '●', className: 'verdict-good' },
}

export default function Gardien() {
  const [view, setView] = useState('sante')
  return (
    <div className="agent">
      <div className="subnav">
        {VIEWS.map((entry) => (
          <button
            key={entry.key}
            className={'subnav-btn' + (view === entry.key ? ' on' : '')}
            onClick={() => setView(entry.key)}
          >
            {entry.label}
          </button>
        ))}
      </div>
      {view === 'sante' && <Sante />}
      {view === 'incidents' && <Incidents />}
      {view === 'chat' && <GardienChat />}
      {view === 'journal' && <Journal />}
    </div>
  )
}

/* ── Santé : verdict, chiffres clés, redémarrages, sauvegardes, certs ─── */
function Sante() {
  const [state, setState] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = (fresh = false) => {
    setError(null)
    if (fresh) setBusy(true)
    api.gardienState(fresh)
      .then(setState)
      .catch((loadError) => setError(loadError))
      .finally(() => setBusy(false))
  }
  useEffect(() => { load() }, [])

  if (error) return <div className="empty">{error.message}</div>
  if (!state) return <div className="empty">Collecte en cours…</div>

  const disk = state.system?.disk
  const memory = state.system?.memory
  const limits = state.thresholds || {}
  const verdict = VERDICT[state.severity] || VERDICT.good

  const diskTone = disk == null ? '' : disk.usePct >= (limits.diskCritPct ?? 85) ? 'tone-crit' : disk.usePct >= (limits.diskWarnPct ?? 75) ? 'tone-warn' : 'tone-good'
  const ramTone = memory == null ? '' : memory.usePct >= (limits.ramWarnPct ?? 90) ? 'tone-warn' : 'tone-good'

  const noisy = (state.restarts || [])
    .filter((entry) => !entry.ignored && (entry.total > 0 || entry.status !== 'online'))
    .sort((first, second) => (second.last24h ?? 0) - (first.last24h ?? 0) || second.total - first.total)
    .slice(0, 5)

  const calmCount = (state.restarts || []).filter((entry) => !entry.ignored && entry.total === 0).length
  const containers = state.docker || []
  const runningCount = containers.filter((container) => container.state === 'running').length
  const sickContainers = containers.filter((container) => container.state !== 'running' || container.health === 'unhealthy')
  const backups = state.backups || {}
  const certs = (state.certs || []).filter((cert) => cert.daysLeft != null)

  return (
    <div className="board">
      <div className={'verdict ' + verdict.className}>
        <span className="verdict-glyph" aria-hidden="true">{verdict.glyph}</span>
        <div>
          <p className="verdict-label">{verdict.label}</p>
          <p className="verdict-why">
            {state.openCount > 0
              ? `${state.openCount} incident${state.openCount > 1 ? 's' : ''} ouvert${state.openCount > 1 ? 's' : ''}. Détail dans l'onglet Incidents.`
              : `${runningCount} conteneurs et ${(state.pm2 || []).filter((entry) => entry.status === 'online').length} services en ligne, rien à signaler.`}
          </p>
        </div>
      </div>

      <div className="tiles">
        <div className="tile">
          <span className={'tile-val ' + diskTone}>{disk ? disk.usePct + ' %' : '—'}</span>
          <span className="tile-key">Disque</span>
          <span className="tile-delta">{disk ? gib(disk.freeBytes) + ' libres' : ''}</span>
        </div>
        <div className="tile">
          <span className={'tile-val ' + ramTone}>{memory ? memory.usePct + ' %' : '—'}</span>
          <span className="tile-key">RAM</span>
          <span className={'tile-delta' + (memory?.swapTotalBytes === 0 ? ' tone-warn' : '')}>
            {memory ? (memory.swapTotalBytes === 0 ? '0 swap' : 'swap ' + gib(memory.swapTotalBytes)) : ''}
          </span>
        </div>
        <div className="tile">
          <span className="tile-val">{state.system?.load?.[0] ?? '—'}</span>
          <span className="tile-key">Load</span>
          <span className="tile-delta">{state.system?.cpus ? state.system.cpus + ' vCPU' : ''}</span>
        </div>
        <div className="tile">
          <span className="tile-val">{duration(state.system?.uptimeSeconds)}</span>
          <span className="tile-key">Uptime</span>
          <span className="tile-delta">sans reboot</span>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <p className="eyebrow card-eyebrow">Collecte du {shortDateTime(state.at)}</p>
          <button className="card-action" onClick={() => load(true)} disabled={busy} aria-label="Relancer une collecte" title="Relancer une collecte">
            {busy ? '…' : '↻'}
          </button>
        </div>
        <p className="grd-note">
          {runningCount}/{containers.length} conteneurs Docker en marche
          {sickContainers.length ? ` (à problème : ${sickContainers.map((container) => container.name).join(', ')})` : ', tous sains'}.
          {(state.ignoredPm2 || []).length ? ` ${state.ignoredPm2.join(' et ')} ${state.ignoredPm2.length > 1 ? 'sont arrêtés' : 'est arrêté'} volontairement.` : ''}
        </p>
      </section>

      <section className="card">
        <p className="sec-title">Redémarrages</p>
        {noisy.length === 0 && <p className="grd-note">Aucun redémarrage au compteur. </p>}
        <div className="acts">
          {noisy.map((entry) => {
            const tone = entry.status !== 'online' ? 'crit'
              : entry.last24h >= (limits.restartsCrit24h ?? 15) ? 'crit'
              : entry.last24h >= (limits.restartsWarn24h ?? 5) ? 'warn' : ''
            return (
              <div className="act" key={entry.name}>
                <span className={'act-glyph ' + (tone || 'good')} aria-hidden="true">{entry.status === 'online' ? '↺' : '✕'}</span>
                <div>
                  <p className="act-name">{entry.name}</p>
                  <p className="act-meta">
                    {entry.status === 'online' ? `en ligne depuis ${duration(entry.uptimeSeconds)}` : `pm2 : ${entry.status}`}
                    {entry.last24h != null ? ` · ${entry.last24h} sur 24 h` : ''}
                  </p>
                </div>
                <p className={'act-tss ' + (tone ? 'tone-' + tone : '')}>
                  {entry.total}<span>↺ CUMUL</span>
                </p>
              </div>
            )
          })}
          {calmCount > 0 && (
            <div className="act">
              <span className="act-glyph good" aria-hidden="true">✓</span>
              <div>
                <p className="act-name">{calmCount} autre{calmCount > 1 ? 's' : ''} service{calmCount > 1 ? 's' : ''}</p>
                <p className="act-meta">aucun redémarrage</p>
              </div>
              <p className="act-tss tone-good">0<span>↺</span></p>
            </div>
          )}
        </div>
        <p className="grd-note">La fenêtre 24 h / 7 j se remplit à partir de la première collecte : au démarrage, seul le cumul pm2 est connu.</p>
      </section>

      <SshCard ssh={state.ssh} />

      <section className="card">
        <p className="sec-title">Sauvegardes</p>
        <div className="acts">
          {(backups.checked || []).map((backup) => (
            <div className="act" key={backup.key}>
              <span className={'act-glyph ' + (backup.status === 'ok' ? 'good' : 'crit')} aria-hidden="true">{backup.status === 'ok' ? '✓' : '✕'}</span>
              <div>
                <p className="act-name">{backup.label}</p>
                <p className="act-meta">
                  {backup.detail}
                  {backup.lastAt ? ` · il y a ${Math.round(backup.ageHours)} h · ${fileSize(backup.sizeBytes)}` : ''}
                </p>
              </div>
              <p className={'act-tss ' + (backup.status === 'ok' ? 'tone-good' : 'tone-crit')}>
                {backup.status === 'ok' ? 'OK' : backup.status === 'stale' ? 'vieille' : 'vide'}
              </p>
            </div>
          ))}
          {(backups.unbacked || []).map((item) => (
            <div className="act" key={item.key}>
              <span className="act-glyph crit" aria-hidden="true">✕</span>
              <div>
                <p className="act-name">{item.label}</p>
                <p className="act-meta">{item.detail}</p>
              </div>
              <p className="act-tss tone-crit">jamais</p>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <p className="sec-title">Certificats · {certs.length} suivis</p>
        {certs.length === 0 && <p className="grd-note">Aucun certificat mesuré.</p>}
        {certs.slice(0, 6).map((cert) => {
          const tone = cert.daysLeft <= (limits.certCritDays ?? 10) ? 'crit' : cert.daysLeft <= (limits.certWarnDays ?? 20) ? 'warn' : ''
          return (
            <div className="alloc-row" key={cert.domain}>
              <span className="alloc-name grd-domain">{cert.domain.replace(/\.(fr|com)$/, '')}</span>
              <span className="alloc-track">
                <span className={'alloc-fill ' + tone} style={{ width: Math.min(100, Math.round((cert.daysLeft / 90) * 100)) + '%' }} />
              </span>
              <span className={'ichip ' + (tone || 'good')}>{cert.daysLeft} j</span>
            </div>
          )
        })}
        <p className="grd-note">Mesuré par handshake TLS réel, pas d'après la conf de certbot.</p>
      </section>
    </div>
  )
}

/* ── SSH : tentatives refusées par jour, connexions réussies ──────────── */
const count = (value) => (value == null ? '—' : value.toLocaleString('fr-FR'))
const dayLabel = (day) => new Date(day + 'T12:00:00').toLocaleDateString('fr-FR', { day: 'numeric', month: 'short' })

function SshCard({ ssh }) {
  if (!ssh) return null
  if (ssh.error) {
    return (
      <section className="card">
        <p className="sec-title">SSH</p>
        <p className="grd-note">Mesure indisponible : {ssh.error}</p>
      </section>
    )
  }

  const days = ssh.days || []
  const peak = Math.max(1, ...days.map((entry) => entry.attempts ?? 0))
  const hasGap = days.some((entry) => entry.attempts == null)
  const barStep = 10
  const chartHeight = 60
  const alerts = ssh.loginAlerts || []
  const busiest = ssh.yesterday?.topSubnet

  return (
    <section className="card">
      <p className="sec-title">SSH · tentatives refusées</p>
      <div className="tiles">
        <div className="tile">
          <span className="tile-val">{count(ssh.today?.attempts ?? 0)}</span>
          <span className="tile-key">Aujourd'hui</span>
          <span className="tile-delta">en cours</span>
        </div>
        <div className="tile">
          <span className="tile-val">{count(ssh.yesterday?.attempts)}</span>
          <span className="tile-key">Hier</span>
          <span className="tile-delta">{ssh.yesterday?.uniqueIps != null ? count(ssh.yesterday.uniqueIps) + ' IP' : ''}</span>
        </div>
        <div className="tile">
          <span className="tile-val">{count(ssh.bannedNow)}</span>
          <span className="tile-key">Bannies</span>
          <span className="tile-delta">actives</span>
        </div>
        <div className="tile">
          <span className={'tile-val ' + (alerts.length ? 'tone-crit' : 'tone-good')}>{alerts.length}</span>
          <span className="tile-key">Alertes</span>
          <span className="tile-delta">connexions</span>
        </div>
      </div>

      {days.length > 0 && (
        <div className="ssh-chart">
          <svg viewBox={`0 0 ${days.length * barStep} ${chartHeight}`} preserveAspectRatio="none" className="ssh-chart-svg" role="img"
            aria-label={`Tentatives SSH par jour, maximum ${count(peak)}`}>
            {days.map((entry, index) => {
              if (entry.attempts == null) {
                return (
                  <rect key={entry.day} x={index * barStep + 1.5} y={chartHeight - 2} width={barStep - 3} height="2" className="ssh-bar-gap">
                    <title>{`${dayLabel(entry.day)} : aucune mesure`}</title>
                  </rect>
                )
              }
              const height = Math.max(entry.attempts ? 1.5 : 0, (entry.attempts / peak) * (chartHeight - 2))
              const isToday = index === days.length - 1
              return (
                <rect key={entry.day} x={index * barStep + 1.5} y={chartHeight - height} width={barStep - 3} height={height} rx="1.2"
                  className={'ssh-bar' + (isToday ? ' ssh-bar-today' : '')}>
                  <title>{`${dayLabel(entry.day)} : ${count(entry.attempts)} tentatives, ${count(entry.bans)} bannissements`}</title>
                </rect>
              )
            })}
          </svg>
          <div className="ssh-chart-axis">
            <span>{dayLabel(days[0].day)}</span>
            <span>max {count(peak)} / jour</span>
            <span>aujourd'hui</span>
          </div>
        </div>
      )}

      {alerts.length > 0 && (
        <div className="acts">
          {alerts.map((alert) => (
            <div className="act" key={alert.ip + alert.at}>
              <span className="act-glyph crit" aria-hidden="true">!</span>
              <div>
                <p className="act-name">{alert.reason === 'password' ? 'Connexion par mot de passe' : 'IP jamais vue'}</p>
                <p className="act-meta">{alert.user}@{alert.ip} · {shortDateTime(alert.at)}{alert.key ? ` · ${alert.key}` : ''}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      <p className="sec-title ssh-subtitle">Dernières connexions réussies</p>
      {(ssh.recentLogins || []).length === 0 && <p className="grd-note">Aucune connexion enregistrée.</p>}
      <div className="acts">
        {(ssh.recentLogins || []).slice(0, 3).map((login) => (
          <div className="act" key={login.ip + login.at}>
            <span className={'act-glyph ' + (login.method === 'password' ? 'crit' : 'good')} aria-hidden="true">{login.method === 'password' ? '!' : '✓'}</span>
            <div>
              <p className="act-name">{login.key || login.user}</p>
              <p className="act-meta">{login.ip} · {shortDateTime(login.at)}{login.method === 'password' ? ' · mot de passe' : ''}</p>
            </div>
          </div>
        ))}
      </div>

      {ssh.passwordAuth && (
        <p className="grd-note tone-crit">
          Connexion par mot de passe OUVERTE ({(ssh.authMethods || []).join(', ')}) : c'est elle qui rend ces tentatives dangereuses.
        </p>
      )}
      <p className="grd-note">
        Des robots qui balaient Internet : du bruit de fond{ssh.passwordAuth === false ? ', inoffensif avec des clés seules' : ''}.
        {busiest ? ` Le plus actif hier : ${busiest.subnet} (${count(busiest.count)} tentatives).` : ''}
        {ssh.bansSince ? ` Bannissements comptés depuis le ${shortDate(ssh.bansSince)} (mise en route de fail2ban).` : ''}
        {hasGap ? ' Trait gris : aucune mesure ce jour-là (machine éteinte).' : ''}
        {ssh.since ? ` Suivi depuis le ${new Date(ssh.since + 'T12:00:00').toLocaleDateString('fr-FR', { day: 'numeric', month: 'long' })}.` : ''}
      </p>
    </section>
  )
}

/* ── Incidents : ouverts puis résolus ─────────────────────────────────── */
function Incidents() {
  const [data, setData] = useState(null)

  useEffect(() => {
    api.gardienIncidents()
      .then(setData)
      .catch(() => setData({ open: [], resolved: [] }))
  }, [])

  if (!data) return <div className="empty">Chargement…</div>
  const open = data.open || []
  const resolved = data.resolved || []

  if (!open.length && !resolved.length) {
    return <div className="empty">Aucun incident depuis la mise en service du gardien.</div>
  }

  const statusClass = (severity) => (severity === 'crit' ? 'adh-manque' : severity === 'warn' ? 'adh-partiel' : 'adh-fait')

  return (
    <div className="board">
      <p className="eyebrow">
        {open.length} ouvert{open.length > 1 ? 's' : ''} · {resolved.length} résolu{resolved.length > 1 ? 's' : ''}
      </p>

      <div className="adh-items">
        {open.map((incident) => (
          <div className="adh-item" key={incident.id}>
            <span className={'adh-status ' + statusClass(incident.severity)}>
              {incident.severity === 'crit' ? 'Critique' : 'Ouvert'}
            </span>
            <div>
              <p className="adh-planned">{incident.title}</p>
              <p className="adh-evidence">{incident.detail}</p>
              <span className="adh-when">
                Détecté {shortDateTime(incident.firstSeenAt)}
                {incident.occurrences > 1 ? ` · revu ${incident.occurrences} fois` : ''}
              </span>
            </div>
          </div>
        ))}

        {resolved.map((incident) => (
          <div className="adh-item" key={incident.id}>
            <span className="adh-status adh-fait">Résolu</span>
            <div>
              <p className="adh-planned">{incident.title}</p>
              <p className="adh-evidence">{incident.detail}</p>
              <span className="adh-when">
                Ouvert {shortDateTime(incident.firstSeenAt)} · résolu {shortDateTime(incident.resolvedAt)}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Conversation avec le gardien ─────────────────────────────────────── */
function GardienChat() {
  const [messages, setMessages] = useState(null)
  const [draft, setDraft] = useState('')
  const [sending, setSending] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    let alive = true
    api.gardienChatHistory()
      .then((data) => { if (alive) setMessages(data.messages || []) })
      .catch(() => { if (alive) setMessages([]) })
    return () => { alive = false }
  }, [])

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, sending])

  const send = async (text) => {
    const content = (text ?? draft).trim()
    if (!content || sending) return
    setDraft('')
    setMessages((prev) => [...(prev || []), { role: 'user', content }])
    setSending(true)
    try {
      const result = await api.gardienChat(content)
      setMessages((prev) => [...prev, { role: 'assistant', content: result.reply || '…' }])
    } catch (sendError) {
      setMessages((prev) => [...prev, { role: 'assistant', content: 'Souci pour répondre. Réessaie.' }])
    } finally {
      setSending(false)
    }
  }

  const quicks = [
    'Il s’est passé quoi cette nuit ?',
    'Qu’est-ce qui mérite mon attention ?',
    'Pourquoi le scraper redémarre ?',
    'État des sauvegardes',
  ]

  return (
    <div className="chatview">
      <div className="stream">
        {messages == null && <div className="empty">Chargement…</div>}
        {messages && messages.length === 0 && (
          <div className="empty small">
            Demande-lui la nuit qui vient de passer, la cause d’un redémarrage, ou l’état des sauvegardes.
            Il lit la machine mais ne la touche pas : pour agir, il te donne la commande.
          </div>
        )}
        {(messages || []).map((message, index) => (
          <div key={index} className={'msg ' + (message.role === 'user' ? 'msg-me' : 'msg-coach')}>
            <div className="msg-bubble">
              {message.role === 'user' ? message.content : <div className="prose">{richText(message.content)}</div>}
            </div>
          </div>
        ))}
        {sending && <div className="msg msg-coach"><div className="msg-bubble typing">le gardien regarde la machine…</div></div>}
        <div ref={bottomRef} />
      </div>

      <div className="composer">
        <div className="quickrow">
          {quicks.map((quick) => (
            <button className="quick" type="button" key={quick} onClick={() => send(quick)} disabled={sending}>
              {quick}
            </button>
          ))}
        </div>
        <form className="inputrow" onSubmit={(event) => { event.preventDefault(); send() }}>
          <input
            type="text"
            placeholder="Demander au gardien…"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            aria-label="Message au gardien"
          />
          <button className="send" type="submit" aria-label="Envoyer" disabled={sending}>↑</button>
        </form>
      </div>
    </div>
  )
}

/* ── Journal : ce que le gardien a retenu ─────────────────────────────── */
function Journal() {
  const [entries, setEntries] = useState(null)

  useEffect(() => {
    api.gardienJournal()
      .then((data) => setEntries(data.entries || []))
      .catch(() => setEntries([]))
  }, [])

  if (entries == null) return <div className="empty">Chargement…</div>
  if (!entries.length) {
    return <div className="empty">Journal vide. Il se remplit tout seul : incidents ouverts et résolus, points du matin, constats que tu lui demandes de garder.</div>
  }

  return (
    <div className="board">
      {entries.map((entry) => (
        <details className="card journal-entry" key={entry.id}>
          <summary>
            <span className="je-kind">{entry.title || entry.kind}</span>
            <span className="je-date">{shortDate(entry.date)}</span>
          </summary>
          <div className="je-body">
            <p className="eyebrow">{entry.kind}</p>
            <p className="je-reason prewrap">{entry.body}</p>
          </div>
        </details>
      ))}
    </div>
  )
}
