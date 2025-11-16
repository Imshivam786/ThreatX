import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { RouterModule } from '@angular/router';
import { MonitoredSystem } from '../../models/system.model';
import { SystemService } from '../../services/system.service';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    MatCardModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatChipsModule,
    MatProgressSpinnerModule,
    MatSnackBarModule
  ],
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent implements OnInit {
  private systemService = inject(SystemService);
  private snackBar = inject(MatSnackBar);

  systems: MonitoredSystem[] = [];
  displayedColumns: string[] = ['localName', 'ipAddress', 'systemType', 'dateConfigured', 'status', 'actions'];
  loading = true;

  ngOnInit(): void {
    this.loadSystems();
  }

  loadSystems(): void {
    this.loading = true;
    this.systemService.getSystems().subscribe({
      next: (systems) => {
        this.systems = systems;
        console.log("systems are: ", this.systems)
        this.loading = false;
      },
      error: (error) => {
        console.error('Error loading systems:', error);
        this.loading = false;
        this.snackBar.open('Error loading systems', 'Close', { duration: 3000 });
      }
    });
  }

  deleteSystem(system: MonitoredSystem): void {
    if (confirm(`Are you sure you want to remove ${system.localName} from monitoring?`)) {
      this.systemService.deleteSystem(system.id!).subscribe({
        next: () => {
          this.snackBar.open('System removed successfully', 'Close', { duration: 3000 });
          this.loadSystems();
        },
        error: (error) => {
          console.error('Error deleting system:', error);
          this.snackBar.open('Error removing system', 'Close', { duration: 3000 });
        }
      });
    }
  }

  formatDate(date: Date): string {
    return new Date(date).toLocaleDateString();
  }
}
