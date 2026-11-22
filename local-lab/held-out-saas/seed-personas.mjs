// Prints the seeded personas as JSON (LabRunner `seedCommand` format): `node seed-personas.mjs`
import { createApp } from './src/app.mjs'

process.stdout.write(`${JSON.stringify({ personas: createApp().personas() })}\n`)
