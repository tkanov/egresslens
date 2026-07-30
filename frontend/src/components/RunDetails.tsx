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

function asCount(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function asCounts(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return {}
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

  // Capture counts from run.json. ipv6_connects_skipped is the only per-run
  // signal that the capture was incomplete, and it previously stopped here --
  // written to run.json and rendered nowhere.
  const counts = asCounts(metadata.counts)
  const ipv6Skipped = asCount(counts.ipv6_connects_skipped)
  const captureCounts = [
    { label: 'Events captured', value: asCount(counts.total_events) },
    { label: 'Destination IPs', value: asCount(counts.unique_dst_ips) },
    { label: 'Destination IP:port pairs', value: asCount(counts.unique_dst_ip_ports) },
    { label: 'IPv6 not captured', value: ipv6Skipped },
  ].filter((item): item is { label: string; value: number } => item.value !== null)

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
          <div className="space-y-6">
            <dl className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {details.map(({ label, value, wide }) => (
                <div key={label} className={wide ? 'md:col-span-2 lg:col-span-4' : undefined}>
                  <dt className="text-xs font-medium uppercase text-muted-foreground">{label}</dt>
                  <dd className="mt-1 break-words font-mono text-sm text-foreground">{value}</dd>
                </div>
              ))}
            </dl>

            {captureCounts.length > 0 && (
              <div className="space-y-3 border-t pt-4">
                <dl className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                  {captureCounts.map(({ label, value }) => (
                    <div key={label}>
                      <dt className="text-xs font-medium uppercase text-muted-foreground">{label}</dt>
                      <dd className="mt-1 font-mono text-sm text-foreground">
                        {value.toLocaleString()}
                      </dd>
                    </div>
                  ))}
                </dl>

                {ipv6Skipped !== null && ipv6Skipped > 0 && (
                  <p className="text-xs text-amber-700 dark:text-amber-400">
                    {ipv6Skipped.toLocaleString()} IPv6 connection(s) were observed but their
                    destinations were not captured. They are absent from every table on this
                    page and cannot raise a policy FAIL.
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
