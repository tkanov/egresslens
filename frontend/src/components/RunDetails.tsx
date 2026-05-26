import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface RunDetailsProps {
  metadata: Record<string, unknown>
}

function asString(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return null
}

function formatCommand(value: unknown): string | null {
  if (Array.isArray(value)) {
    return value.map((part) => String(part)).join(' ')
  }
  return asString(value)
}

function formatDate(value: unknown): string | null {
  const raw = asString(value)
  if (!raw) return null
  const date = new Date(raw)
  if (Number.isNaN(date.getTime())) return raw
  return date.toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatDuration(start: unknown, end: unknown): string | null {
  const startRaw = asString(start)
  const endRaw = asString(end)
  if (!startRaw || !endRaw) return null

  const started = new Date(startRaw).getTime()
  const ended = new Date(endRaw).getTime()
  if (Number.isNaN(started) || Number.isNaN(ended) || ended < started) return null

  const seconds = (ended - started) / 1000
  return `${seconds.toFixed(seconds < 10 ? 2 : 1)}s`
}

export function RunDetails({ metadata }: RunDetailsProps) {
  const hasMetadata = Object.keys(metadata).length > 0
  const command = formatCommand(metadata.command)
  const started = formatDate(metadata.start_time)
  const ended = formatDate(metadata.end_time)
  const duration = formatDuration(metadata.start_time, metadata.end_time)

  const details = [
    { label: 'Command', value: command, wide: true },
    { label: 'Exit code', value: asString(metadata.exit_code) },
    { label: 'Duration', value: duration },
    { label: 'Mode', value: asString(metadata.mode) },
    { label: 'Image', value: asString(metadata.image) },
    { label: 'Started', value: started },
    { label: 'Finished', value: ended },
    { label: 'Working directory', value: asString(metadata.cwd), wide: true },
  ].filter((item) => item.value)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Run details</CardTitle>
      </CardHeader>
      <CardContent>
        {!hasMetadata ? (
          <p className="text-sm text-muted-foreground">
            No run metadata was uploaded. Add run.json with the JSONL file to show command, image, exit code, and timing.
          </p>
        ) : (
          <dl className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {details.map(({ label, value, wide }) => (
              <div key={label} className={wide ? 'md:col-span-2 lg:col-span-4' : undefined}>
                <dt className="text-xs font-medium uppercase text-muted-foreground">{label}</dt>
                <dd className="mt-1 break-words font-mono text-sm text-foreground">{value}</dd>
              </div>
            ))}
          </dl>
        )}
      </CardContent>
    </Card>
  )
}
