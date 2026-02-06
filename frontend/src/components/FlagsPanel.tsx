import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import type { Flag } from '@/api'
import { cn } from '@/lib/utils'

interface FlagsPanelProps {
  flags: Flag[]
}

const severityVariant = (severity: string) =>
  severity === 'high' ? 'destructive' : 'default'

export function FlagsPanel({ flags }: FlagsPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Flags</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {flags.length === 0 ? (
          <p className="text-sm text-muted-foreground">No flags raised.</p>
        ) : (
          flags.map((f, i) => (
            <Alert
              key={i}
              variant={severityVariant(f.severity) as 'default' | 'destructive'}
              className={cn(
                f.severity === 'medium' && 'border-amber-500/50 [&_svg]:text-amber-600'
              )}
            >
              <AlertTitle>{f.name}</AlertTitle>
              <AlertDescription>{f.description}</AlertDescription>
            </Alert>
          ))
        )}
      </CardContent>
    </Card>
  )
}
