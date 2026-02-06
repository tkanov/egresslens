// API client for EgressLens backend

// Use relative URLs in dev (via Vite proxy) or env var for production
// In dev container, relative URLs work through Vite proxy to backend
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

// Type definitions matching backend schemas
export interface Event {
  ts: number;
  pid: number;
  event: string;
  family: string;
  proto: string;
  dst_ip: string;
  dst_port: number;
  result: string;
  errno?: string | null;
  resolved_domain?: string | null;
  cmd?: string | null;
  container_image?: string | null;
  run_id?: string | null;
}

export interface Flag {
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
}

export interface TopDestination {
  dst_ip: string;
  dst_port: number;
  proto?: string | null;
  count: number;
  domain?: string | null;
}

export interface ReportSummary {
  total_events: number;
  unique_ips: number;
  unique_ports: number;
  unique_destinations: number;
  failures: number;
  failure_rate: number;
  top_destinations: TopDestination[];
}

export interface ReportUploadResponse {
  report_id: string;
}

export interface ReportResponse {
  id: string;
  created_at: string; // ISO datetime string
  metadata: Record<string, unknown>;
  summary: ReportSummary;
  flags: Flag[];
  top_events: Event[];
}

export interface PaginatedEventsResponse {
  report_id: string;
  total: number;
  returned: number;
  events: Event[];
}

export class ApiError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public detail?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorDetail: string;
    try {
      const errorData = await response.json();
      errorDetail = errorData.detail || errorData.message || response.statusText;
    } catch {
      errorDetail = response.statusText;
    }
    throw new ApiError(
      `API request failed: ${errorDetail}`,
      response.status,
      errorDetail
    );
  }

  // Handle empty responses
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return response.json();
  }
  
  // For text/markdown responses
  return response.text() as unknown as T;
}

/**
 * Upload a JSONL file and create a report
 */
export async function uploadReport(file: File): Promise<ReportUploadResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/api/reports/upload`, {
    method: 'POST',
    body: formData,
  });

  return handleResponse<ReportUploadResponse>(response);
}

/**
 * Get a report by ID
 */
export async function getReport(reportId: string): Promise<ReportResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reports/${reportId}`);
  return handleResponse<ReportResponse>(response);
}

/**
 * Get events for a report with optional pagination
 */
export async function getReportEvents(
  reportId: string,
  limit?: number
): Promise<PaginatedEventsResponse> {
  const url = new URL(`${API_BASE_URL}/api/reports/${reportId}/events`);
  if (limit !== undefined) {
    url.searchParams.set('limit', limit.toString());
  }

  const response = await fetch(url.toString());
  return handleResponse<PaginatedEventsResponse>(response);
}

/**
 * Export a report as markdown
 */
export async function exportReport(reportId: string): Promise<Blob> {
  const response = await fetch(`${API_BASE_URL}/api/reports/${reportId}/export.md`);
  
  if (!response.ok) {
    let errorDetail: string;
    try {
      const errorData = await response.json();
      errorDetail = errorData.detail || errorData.message || response.statusText;
    } catch {
      errorDetail = response.statusText;
    }
    throw new ApiError(
      `Export failed: ${errorDetail}`,
      response.status,
      errorDetail
    );
  }

  return response.blob();
}

/**
 * Download a report as markdown file
 */
export async function downloadReport(reportId: string, filename?: string): Promise<void> {
  const blob = await exportReport(reportId);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || `egresslens-report-${reportId}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}
