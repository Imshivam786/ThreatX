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
  
  private threatUpdates = new Subject<ThreatData>();
  public threatUpdates$ = this.threatUpdates.asObservable();

  startAnalysis(systemId: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/analysis/start/${systemId}`, {});
  }

  stopAnalysis(systemId: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/analysis/stop/${systemId}`, {});
  }

  getThreatData(systemId: number): Observable<ThreatData> {
    return this.http.get<ThreatData>(`${this.apiUrl}/analysis/threats/${systemId}`);
  }

  getRealtimeAlerts(systemId: number): Observable<Alert[]> {
    return this.http.get<Alert[]>(`${this.apiUrl}/analysis/alerts/${systemId}`);
  }

  getAnalysisStatus(systemId: number): Observable<{isRunning: boolean, startTime?: Date}> {
    return this.http.get<{isRunning: boolean, startTime?: Date}>(`${this.apiUrl}/analysis/status/${systemId}`);
  }

  getThreatTrends(systemId: number, hours: number = 24): Observable<any> {
    return this.http.get(`${this.apiUrl}/analysis/trends/${systemId}?hours=${hours}`);
  }

  acknowledgeAlert(alertId: number): Observable<any> {
    return this.http.put(`${this.apiUrl}/analysis/alerts/${alertId}/acknowledge`, {});
  }

  getOSINTThreats(limit: number = 100): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/osint/threats?limit=${limit}`);
  }

  checkIPReputation(ipAddress: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/osint/check-ip`, { ip: ipAddress });
  }

  getVulnerabilities(systemId: number): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/osint/vulnerabilities/${systemId}`);
  }

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
