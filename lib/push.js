// Envoi d'une notif au hub PWA via son service de push (endpoint interne en
// loopback, secret partagé). Le hub détient les abonnements Web Push : chaque
// agent lui demande de pousser, aucun ne gère ses propres clés VAPID.
// Best-effort : ne casse jamais l'appelant.
const PUSH_URL = process.env.HUB_PUSH_URL || ''
const PUSH_TOKEN = process.env.INTERNAL_PUSH_TOKEN || ''

export async function pushToHub({ title, body, url = '/', tag = 'gardien' }) {
  if (!PUSH_URL || !PUSH_TOKEN) return { sent: 0, skipped: 'push non configuré' }
  try {
    const response = await fetch(PUSH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-internal-token': PUSH_TOKEN },
      body: JSON.stringify({ title, body, url, tag }),
    })
    if (!response.ok) return { sent: 0, error: `push ${response.status}` }
    return await response.json()
  } catch (pushError) {
    return { sent: 0, error: pushError.message }
  }
}
