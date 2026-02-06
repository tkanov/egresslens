import { useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { uploadReport, ApiError } from '@/api'
import { cn } from '@/lib/utils'

const ACCEPT = '.jsonl,application/jsonl,application/x-ndjson'

export function UploadPage() {
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [dragActive, setDragActive] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleUpload = useCallback(async () => {
    if (!file) return
    setError(null)
    setUploading(true)
    try {
      const { report_id } = await uploadReport(file)
      navigate(`/reports/${report_id}`)
    } catch (e) {
      setError(e instanceof ApiError ? e.detail ?? e.message : String(e))
    } finally {
      setUploading(false)
    }
  }, [file, navigate])

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
    const f = e.dataTransfer.files[0]
    if (f && (f.name.endsWith('.jsonl') || f.type === 'application/jsonl' || f.type === 'application/x-ndjson')) {
      setFile(f)
      setError(null)
    } else {
      setError('Please drop a .jsonl file.')
    }
  }, [])

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(true)
  }, [])

  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
  }, [])

  const onFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      setFile(f)
      setError(null)
    }
  }, [])

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="mx-auto max-w-2xl space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Upload Egress Report</CardTitle>
            <CardDescription>
              Drag and drop a JSONL file from EgressLens CLI, or choose a file.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div
              onDrop={onDrop}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
              className={cn(
                'rounded-lg border-2 border-dashed p-8 text-center transition-colors',
                dragActive ? 'border-primary bg-primary/5' : 'border-muted-foreground/25',
                file ? 'bg-muted/30' : ''
              )}
            >
              {file ? (
                <p className="text-sm font-medium text-foreground">{file.name}</p>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Drag a .jsonl file here or click to browse
                </p>
              )}
              <input
                ref={inputRef}
                type="file"
                accept={ACCEPT}
                onChange={onFileChange}
                className="hidden"
                aria-hidden
              />
              <Button
                type="button"
                variant="outline"
                className="mt-2"
                onClick={() => inputRef.current?.click()}
              >
                Choose file
              </Button>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertTitle>Upload failed</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button
              onClick={handleUpload}
              disabled={!file || uploading}
              className="w-full"
            >
              {uploading ? 'Uploading…' : 'Upload and view report'}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
