import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ExternalLink } from 'lucide-react'
import { openIpLookup } from '@/lib/ipLookup'
import { getPortInfo } from '@/lib/portInfo'
import type { TopDestination } from '@/api'
import { cn } from '@/lib/utils'

interface TopDestinationsProps {
  destinations: TopDestination[]
}

function PortDisplay({ port, proto }: { port: number; proto?: string | null }) {
  const portInfo = getPortInfo(port)
  const transportProto = proto?.toUpperCase() || null
  
  // Color mapping for common services
  const getServiceColor = (service: string) => {
    const colors: Record<string, string> = {
      'HTTPS': 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
      'HTTP': 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
      'SSH': 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
      'DNS': 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400',
      'FTP': 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
      'SMTP': 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-400',
      'MySQL': 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
      'PostgreSQL': 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400',
      'Redis': 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
    }
    return colors[service] || 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300'
  }
  
  const getTransportColor = (proto: string) => {
    return proto === 'TCP' 
      ? 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
      : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
  }

  return (
    <div className="flex items-center gap-2">
      <span className="font-mono font-medium">{port}</span>
      {portInfo && (
        <span className={cn(
          'inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium',
          getServiceColor(portInfo.service)
        )}>
          {portInfo.service}
        </span>
      )}
      {transportProto && (
        <span className={cn(
          'inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium',
          getTransportColor(transportProto)
        )}>
          {transportProto}
        </span>
      )}
    </div>
  )
}

export function TopDestinations({ destinations }: TopDestinationsProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Top destinations</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>IP</TableHead>
              <TableHead>Port / Protocol</TableHead>
              <TableHead>Count</TableHead>
              <TableHead>Domain</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {destinations.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center text-muted-foreground">
                  No destinations
                </TableCell>
              </TableRow>
            ) : (
              destinations.map((d, i) => (
                <TableRow key={`${d.dst_ip}-${d.dst_port}-${i}`}>
                  <TableCell className="font-mono">
                    <div className="flex items-center gap-2">
                      {d.dst_ip}
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6"
                        onClick={() => openIpLookup(d.dst_ip, 'whois')}
                        title="Check IP on ip-api.com"
                      >
                        <ExternalLink className="h-3 w-3" />
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell>
                    <PortDisplay port={d.dst_port} proto={d.proto} />
                  </TableCell>
                  <TableCell>{d.count}</TableCell>
                  <TableCell className="text-muted-foreground">
                    {d.domain ?? '—'}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
