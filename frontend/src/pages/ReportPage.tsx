import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { getReport, downloadReport, ApiError } from '@/api'
import type { ReportResponse } from '@/api'
import { KPICards } from '@/components/KPICards'
import { TopDestinations } from '@/components/TopDestinations'
import { TimelineChart } from '@/components/TimelineChart'
import { FlagsPanel } from '@/components/FlagsPanel'
import { RunDetails } from '@/components/RunDetails'

export function ReportPage() {
  const { id } = useParams<{ id: string }>()
  const [report, setReport] = useState<ReportResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    setError(null)
    getReport(id)
      .then(setReport)
      .catch((e) => setError(e instanceof ApiError ? e.detail ?? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [id])

  const handleExport = () => {
    if (!id) return
    setExporting(true)
    setExportError(null)
    downloadReport(id)
      .catch((e) => setExportError(e instanceof ApiError ? e.detail ?? e.message : String(e)))
      .finally(() => setExporting(false))
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <p className="text-muted-foreground">Loading report…</p>
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background p-6">
        <p className="text-destructive">{error ?? 'Report not found.'}</p>
        <Button asChild variant="outline">
          <Link to="/">Back to upload</Link>
        </Button>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="mx-auto max-w-6xl space-y-6" data-testid="report-page">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold">Report</h1>
            <p className="text-sm text-muted-foreground">
              {report.id} · {new Date(report.created_at).toLocaleString('en-GB', {
                day: 'numeric',
                month: 'short',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
              })}
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" asChild>
              <Link to="/">New upload</Link>
            </Button>
            <Button data-testid="export-markdown" onClick={handleExport} disabled={exporting}>
              {exporting ? 'Exporting…' : 'Export .md'}
            </Button>
          </div>
        </div>

        {exportError && (
          <p className="text-right text-sm text-destructive">Export failed: {exportError}</p>
        )}

        <div data-testid="kpi-section"><KPICards summary={report.summary} /></div>
        <div data-testid="run-details-section"><RunDetails metadata={report.metadata} /></div>
        <div data-testid="top-destinations-section"><TopDestinations destinations={report.summary.top_destinations} /></div>
        <div data-testid="timeline-section"><TimelineChart events={report.top_events} /></div>
        <div data-testid="flags-section"><FlagsPanel flags={report.flags} /></div>
      </div>
    </div>
  )
}
