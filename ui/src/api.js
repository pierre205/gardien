// Client de l'API du Gardien. Même origine que le service : en démo, Express
// sert l'UI et l'API sur le même port ; en production, nginx route
// /gardien-api/ vers le service et pose l'authentification devant.

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json'

  const response = await fetch(path, { ...options, headers })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.error || `Erreur ${response.status}`)
  return data
}

export const api = {
  gardienState: (fresh = false) => request('/gardien-api/state' + (fresh ? '?fresh=1' : '')),
  gardienIncidents: () => request('/gardien-api/incidents'),
  gardienJournal: () => request('/gardien-api/journal'),
  gardienCerts: () => request('/gardien-api/certs'),
  gardienLogs: (service, lines = 40) => request(`/gardien-api/logs?service=${encodeURIComponent(service)}&lines=${lines}`),
  gardienChatHistory: () => request('/gardien-api/chat/history'),
  gardienChat: (message) => request('/gardien-api/chat', { method: 'POST', body: JSON.stringify({ message }) }),
}
