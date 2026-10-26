// Règles de détection et cycle de vie des incidents.
//
// Le principe : chaque passage produit une liste de constats identifiés par une
// `key` stable (ex: `restart-loop:scraper`). On rapproche cette liste des
// incidents déjà connus. Une key qui apparaît ouvre un incident, une key qui
// disparaît le résout. C'est ce qui permet de dire « ouvert le 27/08, résolu le
// 01/09 » sans stocker d'historique lourd.
import { getIncidents, setIncidents, getSamples, appendSample } from './store.js'

const SEVERITY_RANK = { good: 0, warn: 1, crit: 2 }
export const worstSeverity = (list) =>
  list.reduce((worst, item) => (SEVERITY_RANK[item.severity] > SEVERITY_RANK[worst] ? item.severity : worst), 'good')

// Seuils. Regroupés ici pour être ajustables d'un seul endroit.
export const THRESHOLDS = {
  diskWarnPct: 75,
  diskCritPct: 85,
  ramWarnPct: 90,
  restartsWarn24h: 5,
  restartsCrit24h: 15,
  certWarnDays: 20,
  certCritDays: 10,
}

let idCounter = 0
const newId = () => `${Date.now().toString(36)}${(idCounter++).toString(36)}`

// ─── Redémarrages sur fenêtre glissante ──────────────────────────────────
// pm2 ne donne qu'un cumul depuis son démarrage. On échantillonne ce cumul à
// chaque collecte, et un delta contre le plus vieil échantillon de la fenêtre
// donne « combien de redémarrages sur les N dernières heures ».
export function restartsOverWindow(samples, name, hours) {
  const cutoff = Date.now() - hours * 3600000
  const inWindow = samples.filter((sample) => new Date(sample.at).getTime() >= cutoff)
  const oldest = inWindow[0]
  const newest = samples[samples.length - 1]
  if (!oldest || !newest) return null
  const before = oldest.counts?.[name]
  const now = newest.counts?.[name]
  if (before == null || now == null) return null
  // Un cumul qui recule = pm2 redémarré (compteurs remis à zéro) : on ne peut
  // rien conclure sur la fenêtre, mieux vaut ne rien annoncer.
  if (now < before) return null
  return now - before
}

export function recordRestartSample(pm2List) {
  const counts = {}
  for (const entry of pm2List) counts[entry.name] = entry.restarts
  appendSample(counts)
  return counts
}

export function restartSummary(pm2List) {
  const samples = getSamples()
  return pm2List.map((entry) => ({
    name: entry.name,
    status: entry.status,
    ignored: entry.ignored,
    total: entry.restarts,
    last24h: restartsOverWindow(samples, entry.name, 24),
    last7d: restartsOverWindow(samples, entry.name, 24 * 7),
    uptimeSeconds: entry.uptimeSeconds,
  }))
}

// ─── Règles ──────────────────────────────────────────────────────────────
export function evaluate(state) {
  const findings = []
  const add = (key, kind, severity, title, detail) => findings.push({ key, kind, severity, title, detail })

  // Processus pm2 hors ligne (hors ceux arrêtés volontairement).
  for (const entry of state.pm2 || []) {
    if (entry.ignored) continue
    if (entry.status !== 'online') {
      add(`service-down:${entry.name}`, 'service', 'crit',
        `${entry.name} n'est plus en ligne`,
        `Statut pm2 : ${entry.status}. ${entry.restarts} redémarrages au compteur.`)
    }
  }

  // Conteneurs Docker arrêtés ou en mauvaise santé.
  for (const container of state.docker || []) {
    if (container.state !== 'running') {
      add(`container-down:${container.name}`, 'container', 'crit',
        `Conteneur ${container.name} arrêté`,
        `${container.status} (image ${container.image}).`)
    } else if (container.health === 'unhealthy') {
      add(`container-unhealthy:${container.name}`, 'container', 'crit',
        `Conteneur ${container.name} en échec de healthcheck`,
        `${container.status} (image ${container.image}).`)
    }
  }

  // Disque.
  const disk = state.system?.disk
  if (disk) {
    if (disk.usePct >= THRESHOLDS.diskCritPct) {
      add('disk', 'system', 'crit', `Disque à ${disk.usePct} %`,
        `${gib(disk.freeBytes)} libres sur ${gib(disk.totalBytes)}. Au-delà de ${THRESHOLDS.diskCritPct} %, un build Docker ou un dump peut échouer.`)
    } else if (disk.usePct >= THRESHOLDS.diskWarnPct) {
      add('disk', 'system', 'warn', `Disque à ${disk.usePct} %`,
        `${gib(disk.freeBytes)} libres sur ${gib(disk.totalBytes)}.`)
    }
  }

  // Mémoire et absence de swap.
  const memory = state.system?.memory
  if (memory) {
    if (memory.usePct >= THRESHOLDS.ramWarnPct) {
      add('ram', 'system', 'warn', `RAM à ${memory.usePct} %`,
        `${gib(memory.availableBytes)} disponibles sur ${gib(memory.totalBytes)}.`)
    }
    if (memory.swapTotalBytes === 0) {
      add('no-swap', 'system', 'warn', 'Aucun swap configuré',
        `${gib(memory.totalBytes)} de RAM pour une vingtaine de process Node, sans filet : un pic tue un service au hasard.`)
    }
  }

  // Boucles de redémarrage.
  for (const entry of state.restarts || []) {
    if (entry.ignored || entry.last24h == null) continue
    if (entry.last24h >= THRESHOLDS.restartsCrit24h) {
      add(`restart-loop:${entry.name}`, 'service', 'crit',
        `${entry.name} redémarre en boucle`,
        `${entry.last24h} redémarrages sur 24 h${entry.last7d != null ? `, ${entry.last7d} sur 7 jours` : ''}.`)
    } else if (entry.last24h >= THRESHOLDS.restartsWarn24h) {
      add(`restart-loop:${entry.name}`, 'service', 'warn',
        `${entry.name} redémarre souvent`,
        `${entry.last24h} redémarrages sur 24 h${entry.last7d != null ? `, ${entry.last7d} sur 7 jours` : ''}.`)
    }
  }

  // Certificats.
  for (const cert of state.certs || []) {
    if (cert.daysLeft == null) continue
    if (cert.daysLeft <= THRESHOLDS.certCritDays) {
      add(`cert:${cert.domain}`, 'cert', 'crit',
        `Certificat ${cert.domain} expire dans ${cert.daysLeft} j`,
        `Renouvellement automatique attendu bien avant. S'il n'a pas eu lieu, vérifier que le vhost répond en HTTP.`)
    } else if (cert.daysLeft <= THRESHOLDS.certWarnDays) {
      add(`cert:${cert.domain}`, 'cert', 'warn',
        `Certificat ${cert.domain} expire dans ${cert.daysLeft} j`,
        `Rien à faire si certbot tourne, juste à garder en tête.`)
    }
  }

  // Sauvegardes attendues mais pas fraîches.
  for (const backup of state.backups?.checked || []) {
    if (backup.status === 'ok') continue
    const why = backup.status === 'stale'
      ? `Dernière copie il y a ${Math.round(backup.ageHours)} h, au-delà des ${backup.maxAgeHours} h tolérées.`
      : backup.status === 'empty' ? 'Le dossier de sauvegarde est vide.'
      : `Dossier illisible : ${backup.error || 'raison inconnue'}.`
    add(`backup:${backup.key}`, 'backup', 'crit', `Sauvegarde ${backup.label} en retard`, why)
  }

  // SSH. Une connexion réussie depuis une IP jamais vue, ou par mot de passe,
  // reste ouverte 24 h (durée de vie de l'alerte dans lib/ssh.js), puis se
  // résout seule : l'IP est alors connue.
  for (const alert of state.ssh?.loginAlerts || []) {
    const when = new Date(alert.at).toLocaleString('fr-FR', { timeZone: 'Europe/Paris', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
    const who = `${alert.user}@${alert.ip} le ${when}`
    if (alert.reason === 'password') {
      add(`ssh-login:${alert.ip}`, 'security', 'crit', 'Connexion SSH par mot de passe',
        `${who}. Aucune clé utilisée : si ce n'est pas toi, quelqu'un a le mot de passe du compte.`)
    } else {
      add(`ssh-login:${alert.ip}`, 'security', 'warn', 'Connexion SSH depuis une IP jamais vue',
        `${who}, clé ${alert.key || 'non identifiée'}. Si ce n'est pas toi, cette clé est compromise.`)
    }
  }

  // Connexion par mot de passe encore acceptée : c'est elle qui rend les
  // milliers de tentatives quotidiennes dangereuses.
  if (state.ssh?.passwordAuth) {
    add('ssh-password-auth', 'security', 'warn', 'Connexion SSH par mot de passe ouverte',
      `Le serveur SSH accepte encore les mots de passe (méthodes annoncées : ${state.ssh.authMethods.join(', ')}). Les robots essaient des milliers de mots de passe par jour : les couper rend leurs tentatives inoffensives. Correctif : PasswordAuthentication no dans un fichier /etc/ssh/sshd_config.d/01-*.conf (lu avant 50-cloud-init.conf, qui dit yes).`)
  }

  // Pic de tentatives : la veille au-delà de 3 fois la médiane de la semaine.
  const spike = state.ssh?.spike
  if (spike) {
    add('ssh-spike', 'security', 'warn', `${spike.attempts.toLocaleString('fr-FR')} tentatives SSH hier`,
      `Environ ${Math.round(spike.attempts / Math.max(1, spike.median))} fois la normale (médiane ${Math.round(spike.median).toLocaleString('fr-FR')} par jour sur la semaine). fail2ban bannit, mais c'est à regarder.`)
  }

  // Données sans aucune sauvegarde : constat permanent, volontairement signalé
  // en un seul incident pour ne pas noyer la liste.
  const unbacked = state.backups?.unbacked || []
  if (unbacked.length) {
    add('backup-gap', 'backup', 'crit',
      `${unbacked.length} ${unbacked.length > 1 ? 'jeux de données' : 'jeu de données'} sans sauvegarde`,
      unbacked.map((item) => `${item.label} (${item.detail})`).join(' · ') + '. Perte du disque = perte sèche.')
  }

  return findings
}

const gib = (bytes) => (bytes == null ? '?' : `${(bytes / 1024 ** 3).toFixed(1)} G`)

// ─── Rapprochement avec les incidents connus ─────────────────────────────
export function reconcile(findings) {
  const now = new Date().toISOString()
  const known = getIncidents()
  const byKey = new Map(known.filter((incident) => !incident.resolvedAt).map((incident) => [incident.key, incident]))
  const seen = new Set()
  const opened = []
  const escalated = []

  for (const finding of findings) {
    seen.add(finding.key)
    const existing = byKey.get(finding.key)
    if (existing) {
      const wasSeverity = existing.severity
      existing.severity = finding.severity
      existing.title = finding.title
      existing.detail = finding.detail
      existing.lastSeenAt = now
      existing.occurrences = (existing.occurrences || 1) + 1
      if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[wasSeverity]) escalated.push(existing)
    } else {
      const incident = {
        id: newId(),
        key: finding.key,
        kind: finding.kind,
        severity: finding.severity,
        title: finding.title,
        detail: finding.detail,
        firstSeenAt: now,
        lastSeenAt: now,
        resolvedAt: null,
        occurrences: 1,
      }
      known.push(incident)
      opened.push(incident)
    }
  }

  const resolved = []
  for (const incident of known) {
    if (incident.resolvedAt) continue
    if (!seen.has(incident.key)) {
      incident.resolvedAt = now
      resolved.push(incident)
    }
  }

  // On garde tout l'historique ouvert, et les 60 derniers résolus.
  const open = known.filter((incident) => !incident.resolvedAt)
  const closed = known.filter((incident) => incident.resolvedAt)
    .sort((first, second) => new Date(second.resolvedAt) - new Date(first.resolvedAt))
    .slice(0, 60)
  setIncidents([...open, ...closed])

  return { opened, resolved, escalated, open, closed }
}
