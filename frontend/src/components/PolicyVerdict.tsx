import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { PolicyVerdict as PolicyVerdictData } from '@/api'
import { cn } from '@/lib/utils'

interface PolicyVerdictProps {
  policy?: PolicyVerdictData
}

export function PolicyVerdict({ policy }: PolicyVerdictProps) {
  if (!policy?.enabled) return null

  const pass = policy.verdict === 'pass'

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle>Egress policy</CardTitle>
          <span
            className={cn(
              'inline-flex items-center rounded px-2 py-0.5 text-sm font-semibold',
              pass
                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
            )}
          >
            {pass ? 'PASS' : 'FAIL'}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          {policy.expected_count} of {policy.expected_count + policy.unexpected_count} destination(s)
          matched the allowlist ({policy.allow_rules} rule{policy.allow_rules === 1 ? '' : 's'}).
        </p>

        {policy.unexpected.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>Count</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policy.unexpected.map((d, i) => (
                <TableRow key={`${d.dst_ip}-${d.dst_port}-${i}`}>
                  <TableCell>
                    {d.domain ?? <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="font-mono">{d.dst_ip}</TableCell>
                  <TableCell className="font-mono">{d.dst_port}</TableCell>
                  <TableCell>{d.count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
