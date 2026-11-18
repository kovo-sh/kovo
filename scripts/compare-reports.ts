import { compareReports } from './report-comparison.ts'

try {
  if (process.argv.length !== 3) throw new Error('Pass the manifest path with npm run compare:reports -- path/to/manifest.json')
  const result = await compareReports(process.argv[2])
  process.stdout.write(JSON.stringify(result, null, 2) + '\n')
  if (result.status === 'failed') process.exitCode = 1
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Could not compare reports.')
  process.exitCode = 1
}
