// Texte du gardien : **gras** -> <strong>, rendu en nœuds React (pas de HTML
// brut, donc rien de ce que le modèle écrit ne peut s'exécuter dans la page).
export function richText(text) {
  if (!text) return null
  return String(text).split(/\*\*(.+?)\*\*/g).map((chunk, index) => (
    index % 2 === 1 ? <strong key={index}>{chunk}</strong> : chunk
  ))
}
