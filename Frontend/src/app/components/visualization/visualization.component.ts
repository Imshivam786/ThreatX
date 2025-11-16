import { CommonModule } from '@angular/common';
import { Component, inject, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { ChartConfiguration, ChartType } from 'chart.js';
import { BaseChartDirective } from 'ng2-charts';
import { interval, Subscription } from 'rxjs';
import { MonitoredSystem, ThreatData } from '../../models/system.model';
import { AnalysisService } from '../../services/analysis.service';
import { SystemService } from '../../services/system.service';

@Component({
  selector: 'app-visualization',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatChipsModule,
    MatTableModule,
    BaseChartDirective
  ],
  templateUrl: './visualization.component.html',
  styleUrls: ['./visualization.component.scss']
})
export class VisualizationComponent implements OnInit, OnDestroy {
  private route = inject(ActivatedRoute);
  private systemService = inject(SystemService);
  private analysisService = inject(AnalysisService);  // Now using AnalysisService

  systemId!: number;
  system?: MonitoredSystem;
  threatData?: ThreatData;
  loading = true;
  analyzing = false;
  autoRefresh = false;
  private refreshSubscription?: Subscription;

  @ViewChild('lineChart') lineChart?: BaseChartDirective;
  @ViewChild('pieChart') pieChart?: BaseChartDirective;
  @ViewChild('barChart') barChart?: BaseChartDirective;
  @ViewChild('resolutionChart') resolutionChart?: BaseChartDirective;

  // Alert columns for table
  alertColumns: string[] = ['timestamp', 'severity', 'attackType', 'sourceIp', 'description', 'status', 'actions'];

  // Line Chart Configuration
  public lineChartType: ChartType = 'line';
  public lineChartData: ChartConfiguration['data'] = {
    datasets: [
      {
        data: [],
        label: 'Requests',
        borderColor: '#3f51b5',
        backgroundColor: 'rgba(63, 81, 181, 0.1)',
        fill: true,
        tension: 0.4
      },
      {
        data: [],
        label: 'Threats Detected',
        borderColor: '#f44336',
        backgroundColor: 'rgba(244, 67, 54, 0.1)',
        fill: true,
        tension: 0.4
      }
    ],
    labels: []
  };

  public lineChartOptions: ChartConfiguration['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top'
      }
    },
    scales: {
      y: {
        beginAtZero: true
      }
    }
  };


  public resolutionChartType: ChartType = 'line';
  public resolutionChartData: ChartConfiguration['data'] = {
    datasets: [
      {
        data: [],
        label: 'Threats Detected',
        borderColor: '#f44336',
        backgroundColor: 'rgba(244, 67, 54, 0.1)',
        fill: true,
        tension: 0.4
      },
      {
        data: [],
        label: 'Threats Resolved',
        borderColor: '#4caf50',
        backgroundColor: 'rgba(76, 175, 80, 0.1)',
        fill: true,
        tension: 0.4
      }
    ],
    labels: []
  };

  public resolutionChartOptions: ChartConfiguration['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top'
      },
      title: {
        display: true,
        text: 'Threat Resolution Tracking'
      }
    },
    scales: {
      y: {
        beginAtZero: true
      }
    }
  };

  // Pie Chart Configuration
  public pieChartType: ChartType = 'pie';
  public pieChartData: ChartConfiguration['data'] = {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: ['#f44336', '#ff9800', '#4caf50']
    }]
  };

  public pieChartOptions: ChartConfiguration['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right'
      }
    }
  };

  // Bar Chart Configuration
  public barChartType: ChartType = 'bar';
  public barChartData: ChartConfiguration['data'] = {
    labels: [],
    datasets: [{
      data: [],
      label: 'Attack Count',
      backgroundColor: '#3f51b5'
    }]
  };

  public barChartOptions: ChartConfiguration['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false
      }
    },
    scales: {
      y: {
        beginAtZero: true
      }
    }
  };

  ngOnInit(): void {
    this.systemId = +this.route.snapshot.paramMap.get('id')!;
    this.loadSystemInfo();

    // Auto-load threat data once on page load
    this.loadThreatData();
  }

  ngOnDestroy(): void {
    // Stop auto-refresh polling
    this.stopAutoRefresh();

    // Stop analysis on backend if it's running
    if (this.autoRefresh || this.analyzing) {
      console.log('Component destroyed - stopping analysis...');
      this.analysisService.stopAnalysis(this.systemId).subscribe({
        next: () => {
          console.log('Analysis stopped successfully');
        },
        error: (error) => {
          console.error('Error stopping analysis:', error);
        }
      });
    }
  }


  loadSystemInfo(): void {
    this.loading = true;
    this.systemService.getSystemById(this.systemId).subscribe({
      next: (system) => {
        this.system = system;
        this.loading = false;
      },
      error: (error) => {
        console.error('Error loading system:', error);
        this.loading = false;
      }
    });
  }

  startAnalysis(): void {
    this.analyzing = true;
    this.autoRefresh = true;

    // Start analysis on backend using AnalysisService
    this.analysisService.startAnalysis(this.systemId).subscribe({
      next: () => {
        // Load initial data
        this.loadThreatData();

        // Start auto-refresh every 5 seconds
        this.refreshSubscription = interval(5000).subscribe(() => {
          if (this.autoRefresh) {
            this.loadThreatData();
          }
        });
      },
      error: (error) => {
        console.error('Error starting analysis:', error);
        this.analyzing = false;
        this.autoRefresh = false;
      }
    });
  }

  stopAnalysis(): void {
    this.autoRefresh = false;
    this.analyzing = false;

    // Stop analysis on backend
    this.analysisService.stopAnalysis(this.systemId).subscribe({
      next: () => {
        console.log('Analysis stopped');
      },
      error: (error) => {
        console.error('Error stopping analysis:', error);
      }
    });

    this.stopAutoRefresh();
  }

  private stopAutoRefresh(): void {
    if (this.refreshSubscription) {
      this.refreshSubscription.unsubscribe();
    }
  }

  loadThreatData(): void {
    // Use AnalysisService to get threat data
    this.analysisService.getThreatData(this.systemId).subscribe({
      next: (data) => {
        console.log('Threat data received:', data); // Debug log

        if (data) {
          this.threatData = data;
          this.updateCharts(data);
        } else {
          console.warn('No threat data received');
        }

        this.analyzing = false;
      },
      error: (error) => {
        console.error('Error loading threat data:', error);
        this.analyzing = false;

        // Show user-friendly message
        alert('Error loading threat data. Check console for details.');
      }
    });
  }


  private updateCharts(data: ThreatData): void {
    console.log('Updating charts with data:', data);

    // Line Chart - use snake_case
    if (data.time_series_data && Array.isArray(data.time_series_data)) {
      this.lineChartData.labels = data.time_series_data.map(d =>
        new Date(d.timestamp).toLocaleTimeString()
      );
      this.lineChartData.datasets[0].data = data.time_series_data.map(d => d.request_count || 0);
      this.lineChartData.datasets[1].data = data.time_series_data.map(d => d.threat_count || 0);
    }

    // Pie Chart - use snake_case
    this.pieChartData.labels = ['High', 'Medium', 'Low'];
    this.pieChartData.datasets[0].data = [
      data.high_severity_threats || 0,
      data.medium_severity_threats || 0,
      data.low_severity_threats || 0
    ];

    console.log('Pie chart data:', this.pieChartData.datasets[0].data);

    // Bar Chart - use snake_case
    if (data.top_attack_types && Array.isArray(data.top_attack_types)) {
      this.barChartData.labels = data.top_attack_types.map(t => t.name || 'Unknown');
      this.barChartData.datasets[0].data = data.top_attack_types.map(t => t.count || 0);
    }

    console.log('Bar chart data:', this.barChartData.datasets[0].data);

    if (data.resolution_time_series && Array.isArray(data.resolution_time_series)) {
      this.resolutionChartData.labels = data.resolution_time_series.map(d =>
        new Date(d.timestamp).toLocaleTimeString()
      );
      this.resolutionChartData.datasets[0].data = data.resolution_time_series.map(d => d.detected_count || 0);
      this.resolutionChartData.datasets[1].data = data.resolution_time_series.map(d => d.resolved_count || 0);
      this.resolutionChartData = { ...this.resolutionChartData };
    }

    this.resolutionChartData = { ...this.resolutionChartData };

    setTimeout(() => {
      this.lineChart?.chart?.update();
      this.pieChart?.chart?.update();
      this.barChart?.chart?.update();

      console.log('Charts updated!');
    }, 100);
  }


  getSeverityColor(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'high': return 'warn';
      case 'medium': return 'accent';
      case 'low': return 'primary';
      default: return '';
    }
  }

  formatTimestamp(timestamp: Date): string {
    return new Date(timestamp).toLocaleString();
  }

  resolveAlert(alertId: number): void {
    if (confirm('Mark this alert as resolved?')) {
      this.analysisService.resolveAlert(alertId).subscribe({
        next: () => {
          alert('Alert resolved successfully!');
          this.loadThreatData();
        },
        error: (error) => {
          console.error('Error resolving alert:', error);
          alert('Failed to resolve alert');
        }
      });
    }
  }

  logAlertToSystem(alertId: number, severity: string): void {
    if (severity !== 'High') {
      alert('Only high severity alerts can be logged to system');
      return;
    }

    if (confirm('Log this threat to the remote system for IP blocking?')) {
      this.analysisService.logAlertToSystem(alertId).subscribe({
        next: () => {
          alert('Alert logged to remote system successfully!');
          this.loadThreatData();
        },
        error: (error) => {
          console.error('Error logging alert:', error);
          alert('Failed to log alert to system');
        }
      });
    }
  }

}
