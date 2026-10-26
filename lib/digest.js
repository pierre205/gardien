// Digest du matin, construit sans appel au modèle : ce sont des faits chiffrés,
// une phrase générée coûterait des tokens pour dire la même chose en moins sûr.
// Le Gardien ne pousse rien s'il n'y a rien à dire (pas de « tout va bien » à 8 h).
import { getIncidents } from './store.js'

const shortHour = (iso) => new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Paris' })
const shortDate = (iso) => new Date(iso).toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', timeZone: 'Europe/Paris' })

export function buildNightDigest(state, { hours = 12 } = {}) {
  const cutoff = Date.now() - hours * 3600000
  const incidents = getIncidents()

  const newlyOpened = incidents.filter((incident) =>
    !incident.resolvedAt && new Date(incident.firstSeenAt).getTime() >= cutoff)
  const newlyResolved = incidents.filter((incident) =>
    incident.resolvedAt && new Date(incident.resolvedAt).getTime() >= cutoff)
  const stillOpen = incidents.filter((incident) => !incident.resolvedAt)

  // Redémarrages survenus pendant la nuit.
  const restarted = (state.restarts || []).filter((entry) => !entry.ignored && entry.last24h > 0)

  const lines = []

  if (newlyOpened.length) {
    for (const incident of newlyOpened) {
      lines.push(`${incident.severity === 'crit' ? 'Critique' : 'À surveiller'} : ${incident.title.toLowerCase()}. ${incident.detail}`)
    }
  }

  if (restarted.length && !newlyOpened.some((incident) => incident.key.startsWith('restart-loop:'))) {
    const worst = restarted.sort((first, second) => second.last24h - first.last24h)[0]
    lines.push(`${worst.name} a redémarré ${worst.last24h} fois sur 24 h.`)
  }

  if (newlyResolved.length) {
    lines.push(`Résolu depuis hier : ${newlyResolved.map((incident) => incident.title.toLowerCase()).join(', ')}.`)
  }

  // Rien de neuf : on ne pousse pas, mais on renvoie quand même le contexte pour
  // les déclenchements manuels.
  const hasNews = lines.length > 0

  const disk = state.system?.disk
  const context = [
    disk ? `disque ${disk.usePct} %` : null,
    state.system?.memory ? `RAM ${state.system.memory.usePct} %` : null,
    `${(state.docker || []).filter((container) => container.state === 'running').length} conteneurs actifs`,
    stillOpen.length ? `${stillOpen.length} incident${stillOpen.length > 1 ? 's' : ''} ouvert${stillOpen.length > 1 ? 's' : ''}` : 'aucun incident ouvert',
  ].filter(Boolean).join(' · ')

  return {
    hasNews,
    title: newlyOpened.some((incident) => incident.severity === 'crit') ? 'Le gardien a un problème à signaler' : 'La nuit du gardien',
    text: hasNews ? `${lines.join('\n')}\n\n${context}.` : `Nuit calme. ${context}.`,
    context,
  }
}

// Message court d'une alerte immédiate (service tombé, disque plein, etc.).
export function buildAlertText(incident) {
  return {
    title: incident.severity === 'crit' ? `Alerte : ${incident.title}` : incident.title,
    body: incident.detail.replace(/\s+/g, ' ').slice(0, 150),
  }
}

export const digestHelpers = { shortHour, shortDate }
