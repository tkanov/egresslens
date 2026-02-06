import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { Event } from '@/api'

interface TimelineChartProps {
  events: Event[]
}

function groupByMinute(events: Event[]): { time: string; count: number }[] {
  const buckets: Record<number, number> = {}
  for (const e of events) {
    const min = Math.floor(e.ts / 60) * 60
    buckets[min] = (buckets[min] ?? 0) + 1
  }
  return Object.entries(buckets)
    .map(([k, count]) => ({
      time: new Date(Number(k) * 1000).toISOString().slice(11, 16),
      count,
    }))
    .sort((a, b) => a.time.localeCompare(b.time))
}

export function TimelineChart({ events }: TimelineChartProps) {
  const data = groupByMinute(events)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Events over time</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="text-sm text-muted-foreground">No event data to chart.</p>
        ) : (
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis dataKey="time" className="text-xs" />
                <YAxis className="text-xs" />
                <Tooltip />
                <Bar dataKey="count" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
