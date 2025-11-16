import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, Subject } from 'rxjs';
import { Alert, ThreatData } from '../models/system.model';

@Injectable({
  providedIn: 'root'
})
export class AnalysisService {
  private http = inject(HttpClient);
  private apiUrl = 'http://localhost:8000/api';
  
  // Subject for real-time threat updates via WebSocket (we'll implement this later)
  private threatUpdates = new Subject<ThreatData>();
  public threatUpdates$ = this.threatUpdates.asObservable();

  // Start analysis for a specific system
  startAnalysis(systemId: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/analysis/start/${systemId}`, {});
  }

  // Stop analysis for a specific system
  stopAnalysis(systemId: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/analysis/stop/${systemId}`, {});
  }

  // Get threat data for visualization
  getThreatData(systemId: number): Observable<ThreatData> {
    return this.http.get<ThreatData>(`${this.apiUrl}/analysis/threats/${systemId}`);
  }

  // Get real-time alerts for a system
  getRealtimeAlerts(systemId: number): Observable<Alert[]> {
    return this.http.get<Alert[]>(`${this.apiUrl}/analysis/alerts/${systemId}`);
  }

  // Get analysis status (is analysis running?)
  getAnalysisStatus(systemId: number): Observable<{isRunning: boolean, startTime?: Date}> {
    return this.http.get<{isRunning: boolean, startTime?: Date}>(`${this.apiUrl}/analysis/status/${systemId}`);
  }

  // Get historical threat trends
  getThreatTrends(systemId: number, hours: number = 24): Observable<any> {
    return this.http.get(`${this.apiUrl}/analysis/trends/${systemId}?hours=${hours}`);
  }

  // Acknowledge an alert
  acknowledgeAlert(alertId: number): Observable<any> {
    return this.http.put(`${this.apiUrl}/analysis/alerts/${alertId}/acknowledge`, {});
  }

  // Get OSINT threat intelligence
  getOSINTThreats(limit: number = 100): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/osint/threats?limit=${limit}`);
  }

  // Check if an IP is malicious (from OSINT feeds)
  checkIPReputation(ipAddress: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/osint/check-ip`, { ip: ipAddress });
  }

  // Get vulnerability information from OSINT
  getVulnerabilities(systemId: number): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/osint/vulnerabilities/${systemId}`);
  }

  // Emit threat updates (for future WebSocket integration)
  emitThreatUpdate(data: ThreatData): void {
    this.threatUpdates.next(data);
  }

  resolveAlert(alertId: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/analysis/resolve-alert/${alertId}`, {});
  }

  logAlertToSystem(alertId: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/analysis/log-to-system/${alertId}`, {});
  }


}
