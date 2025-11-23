import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { MonitoredSystem } from '../models/system.model';

@Injectable({
  providedIn: 'root'
})
export class SystemService {
  private http = inject(HttpClient);
  private apiUrl = 'http://localhost:8000/api';
  
  private systemsSubject = new BehaviorSubject<MonitoredSystem[]>([]);
  public systems$ = this.systemsSubject.asObservable();

  constructor() {
    this.loadSystems();
  }

  getSystems(): Observable<MonitoredSystem[]> {
    return this.http.get<MonitoredSystem[]>(`${this.apiUrl}/systems`);
  }

  loadSystems(): void {
    this.getSystems().subscribe({
      next: (systems) => this.systemsSubject.next(systems),
      error: (error) => console.error('Error loading systems:', error)
    });
  }

  getSystemById(id: number): Observable<MonitoredSystem> {
    return this.http.get<MonitoredSystem>(`${this.apiUrl}/systems/${id}`);
  }

  addSystem(system: MonitoredSystem): Observable<MonitoredSystem> {
    return this.http.post<MonitoredSystem>(`${this.apiUrl}/systems`, system);
  }

  deleteSystem(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/systems/${id}`);
  }

  updateSystem(id: number, system: MonitoredSystem): Observable<MonitoredSystem> {
    return this.http.put<MonitoredSystem>(`${this.apiUrl}/systems/${id}`, system);
  }

  testConnection(systemId: number): Observable<{success: boolean, message: string}> {
    return this.http.post<{success: boolean, message: string}>(`${this.apiUrl}/systems/${systemId}/test`, {});
  }

  getSystemStats(systemId: number): Observable<any> {
    return this.http.get(`${this.apiUrl}/systems/${systemId}/stats`);
  }
}
