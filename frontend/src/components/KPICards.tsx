import { Card, CardContent, CardHeader } from '@/components/ui/card'
import type { ReportSummary } from '@/api'

interface KPICardsProps {
  summary: ReportSummary
}

export function KPICards({ summary }: KPICardsProps) {
  const cards = [
    { 
      label: 'Total events', 
      value: summary.total_events,
      icon: '📊',
      accent: 'border-blue-200 bg-blue-50/50 dark:bg-blue-950/20'
    },
    { 
      label: 'Unique IPs', 
      value: summary.unique_ips,
      icon: '🌐',
      accent: 'border-green-200 bg-green-50/50 dark:bg-green-950/20 border-2'
    },
    {
      label: 'Unique ports',
      value: summary.unique_ports,
      icon: '🔌',
      accent: 'border-purple-200 bg-purple-50/50 dark:bg-purple-950/20'
    },
    // The true destination total. The top-destinations table is capped at 50 by
    // the backend, so without this number on the page a reader has nothing to
    // infer the truncation from.
    {
      label: 'Unique destinations',
      value: summary.unique_destinations,
      icon: '🎯',
      accent: 'border-amber-200 bg-amber-50/50 dark:bg-amber-950/20'
    },
    { 
      label: 'Failures', 
      value: summary.failures,
      icon: '⚠️',
      accent: summary.failures > 0 
        ? 'border-red-200 bg-red-50/50 dark:bg-red-950/20' 
        : 'border-gray-200 bg-gray-50/50 dark:bg-gray-950/20'
    },
  ]
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      {cards.map(({ label, value, icon, accent }) => (
        <Card key={label} className={accent}>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <span className="text-lg">{icon}</span>
              <span className="text-sm font-medium text-muted-foreground">{label}</span>
            </div>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold">{value.toLocaleString()}</span>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
