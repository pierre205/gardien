// Configuration propre à la machine surveillée : qui la possède, ce qui y tourne
// volontairement à l'arrêt, ce qui est sauvegardé et ce qui ne l'est pas.
//
// Lue depuis gardien.config.json (non versionné). À défaut, l'exemple versionné
// sert de base, ce qui permet de lancer le service sans rien préparer. En mode
// démo, c'est la configuration de la machine fictive qui s'applique.
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { DEMO, DEMO_CONFIG } from './demo.js'

const LOCAL_CONFIG = fileURLToPath(new URL('../gardien.config.json', import.meta.url))
const EXAMPLE_CONFIG = fileURLToPath(new URL('../gardien.config.example.json', import.meta.url))

function loadConfig() {
  if (DEMO) return DEMO_CONFIG
  const file = process.env.GARDIEN_CONFIG || (existsSync(LOCAL_CONFIG) ? LOCAL_CONFIG : EXAMPLE_CONFIG)
  return JSON.parse(readFileSync(file, 'utf8'))
}

const raw = loadConfig()

export const CONFIG = {
  ownerName: raw.ownerName || "l'utilisateur",
  machineDescription: raw.machineDescription || 'un serveur Linux',
  ignoredPm2: raw.ignoredPm2 || [],
  fail2banContainer: raw.fail2banContainer || 'fail2ban',
  backupTargets: (raw.backupTargets || []).map((target) => ({
    ...target,
    match: target.match ? new RegExp(target.match) : null,
  })),
  unbacked: raw.unbacked || [],
}
