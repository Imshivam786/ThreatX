export interface MonitoredSystem {
  id?: number;
  localName: string;
  ipAddress: string;
  systemType: string;
  description?: string;
  sshPort: number;
  sshUsername: string;
  sshPassword?: string;
  logPath: string;
  dateConfigured: Date;
  isActive: boolean;
  lastAnalyzed?: Date;
}

export interface ThreatData {
  system_id: number;
  system_name: string;
  total_requests: number;
  threats_detected: number;
  high_severity_threats: number;
  medium_severity_threats: number;
  low_severity_threats: number;
  top_attack_types: AttackType[];
  time_series_data: TimeSeriesPoint[];
  recent_alerts: Alert[];
  resolved_threats: number;
  resolution_time_series: ResolutionPoint[];
  auto_resolved_threats: number;
}

export interface ResolutionPoint {
  timestamp: string;
  detected_count: number;
  resolved_count: number;
}

export interface TimeSeriesPoint {
  timestamp: string;
  request_count: number;  // Changed from requestCount
  threat_count: number;  // Changed from threatCount
}

export interface AttackType {
  name: string;
  count: number;
  severity: string;
}


export interface Alert {
  id: number;
  timestamp: Date;
  severity: string;
  attackType: string;
  sourceIp: string;
  description: string;
  status: string;
  resolved_at?: Date;
  resolved_by?: string;
  logged_to_system: boolean;
}
