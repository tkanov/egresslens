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
  const [metadataFile, setMetadataFile] = useState<File | null>(null)
  const [straceFile, setStraceFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [dragActive, setDragActive] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const metadataInputRef = useRef<HTMLInputElement>(null)
  const straceInputRef = useRef<HTMLInputElement>(null)

  const handleUpload = useCallback(async () => {
    if (!file) return
    setError(null)
    setUploading(true)
    try {
      const { report_id } = await uploadReport(file, metadataFile, straceFile)
      navigate(`/reports/${report_id}`)
    } catch (e) {
      setError(e instanceof ApiError ? e.detail ?? e.message : String(e))
    } finally {
      setUploading(false)
    }
  }, [file, metadataFile, straceFile, navigate])

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

  const onMetadataFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      if (f.name !== 'run.json' && !f.name.endsWith('.json')) {
        setError('Please choose run.json or another JSON metadata file.')
        return
      }
      setMetadataFile(f)
      setError(null)
    }
  }, [])

  const onStraceFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      if (f.name !== 'egress.strace' && !f.name.endsWith('.strace')) {
        setError('Please choose egress.strace or another .strace file.')
        return
      }
      setStraceFile(f)
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

            <div className="rounded-lg border p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-medium">Run metadata</p>
                  <p className="text-sm text-muted-foreground">
                    {metadataFile ? metadataFile.name : 'Optional: add run.json from the same output directory.'}
                  </p>
                </div>
                <div className="flex gap-2">
                  {metadataFile && (
                    <Button
                      type="button"
                      variant="ghost"
                      onClick={() => setMetadataFile(null)}
                    >
                      Clear
                    </Button>
                  )}
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => metadataInputRef.current?.click()}
                  >
                    Choose run.json
                  </Button>
                </div>
              </div>
              <input
                ref={metadataInputRef}
                type="file"
                accept=".json,application/json"
                onChange={onMetadataFileChange}
                className="hidden"
                aria-hidden
              />
            </div>

            <div className="rounded-lg border p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-medium">Passive DNS trace</p>
                  <p className="text-sm text-muted-foreground">
                    {straceFile ? straceFile.name : 'Optional: add egress.strace to enrich public IPs with domains.'}
                  </p>
                </div>
                <div className="flex gap-2">
                  {straceFile && (
                    <Button
                      type="button"
                      variant="ghost"
                      onClick={() => setStraceFile(null)}
                    >
                      Clear
                    </Button>
                  )}
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => straceInputRef.current?.click()}
                  >
                    Choose egress.strace
                  </Button>
                </div>
              </div>
              <input
                ref={straceInputRef}
                type="file"
                accept=".strace,text/plain"
                onChange={onStraceFileChange}
                className="hidden"
                aria-hidden
              />
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
