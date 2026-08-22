import type { AlertItem, FileEvent, HealthStatus, IncidentItem, SystemStatus } from '../types';

const API_BASE = '/api/v1';

export async function fetchHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Health fetch failed');
  return res.json();
}

export async function fetchStatus(): Promise<SystemStatus> {
  const res = await fetch(`${API_BASE}/status`);
  if (!res.ok) throw new Error('Status fetch failed');
  return res.json();
}

export async function fetchEvents(limit = 30): Promise<{ items: FileEvent[] }> {
  const res = await fetch(`${API_BASE}/events?page_size=${limit}`);
  if (!res.ok) throw new Error('Events fetch failed');
  return res.json();
}

export async function fetchAlerts(limit = 20): Promise<{ items: AlertItem[] }> {
  const res = await fetch(`${API_BASE}/alerts?page_size=${limit}`);
  if (!res.ok) throw new Error('Alerts fetch failed');
  return res.json();
}

export async function fetchIncidents(limit = 10): Promise<{ items: IncidentItem[] }> {
  const res = await fetch(`${API_BASE}/incidents?page_size=${limit}`);
  if (!res.ok) throw new Error('Incidents fetch failed');
  return res.json();
}

export async function triggerReportDownload(incidentId?: string, format: 'pdf' | 'csv' | 'json' = 'pdf'): Promise<void> {
  let targetIncidentId = incidentId;

  if (!targetIncidentId) {
    const incidents = await fetchIncidents(1);
    if (incidents.items && incidents.items.length > 0) {
      targetIncidentId = incidents.items[0].id;
    }
  }

  if (!targetIncidentId) {
    alert('No active incidents available to generate report for.');
    return;
  }

  // Trigger report generation first
  const genRes = await fetch(`${API_BASE}/reports/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      incident_id: targetIncidentId,
      formats: [format],
      include_event_timeline: true,
      include_process_metadata: true,
      include_remediation: true,
    }),
  });

  if (!genRes.ok) {
    const err = await genRes.json().catch(() => ({}));
    throw new Error(err.detail || 'Report generation failed');
  }

  // Download the generated file
  const downloadUrl = `${API_BASE}/reports/${targetIncidentId}?fmt=${format}`;
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = `rdrs_report_${targetIncidentId.slice(0, 8)}.${format}`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
