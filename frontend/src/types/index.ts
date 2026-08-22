export interface HealthStatus {
  status: 'ok' | 'degraded' | 'error';
  version: string;
  timestamp: string;
  database_reachable: boolean;
  monitor_running: boolean;
  poller_running: boolean;
}

export interface SystemStatus {
  current_score: number;
  severity: 'NOMINAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  response_mode: 'simulation' | 'alert' | 'active';
  file_queue_depth: number;
  process_queue_depth: number;
  engine_running: boolean;
  watch_paths: string[];
  timestamp: string;
}

export interface FileEvent {
  id: string;
  timestamp: string;
  event_type: 'created' | 'modified' | 'deleted' | 'renamed' | 'permission_change';
  file_path: string;
  destination_path: string | null;
  file_extension: string | null;
  entropy_score: number | null;
  file_size_bytes: number | null;
  process_pid: number | null;
  process_name: string | null;
}

export interface AlertItem {
  id: string;
  timestamp: string;
  alert_type: string;
  threat_score_id: string;
  message: string;
  acknowledged: boolean;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  raw_context?: Record<string, any> | null;
}

export interface IncidentItem {
  id: string;
  timestamp: string;
  threat_score: number;
  severity_level: string;
  suspect_process_pid: number | null;
  suspect_process_name: string | null;
  affected_files_count: number;
  affected_extensions: string[] | null;
  quarantine_path: string | null;
  response_mode: string;
  resolved: boolean;
}

export interface TelemetryPoint {
  timestamp: string;
  timeLabel: string;
  cpu_percent: number;
  avg_entropy: number;
  threat_score: number;
}
