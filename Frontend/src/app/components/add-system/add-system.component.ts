import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { Router, RouterModule } from '@angular/router';
import { MonitoredSystem } from '../../models/system.model';
import { SystemService } from '../../services/system.service';

@Component({
  selector: 'app-add-system',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    ReactiveFormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatSelectModule,
    MatIconModule,
    MatSnackBarModule
  ],
  templateUrl: './add-system.component.html',
  styleUrls: ['./add-system.component.scss']
})
export class AddSystemComponent {
  private fb = inject(FormBuilder);
  private systemService = inject(SystemService);
  private router = inject(Router);
  private snackBar = inject(MatSnackBar);

  systemForm: FormGroup;
  submitting = false;

  systemTypes = [
    'SCADA HMI',
    'Web Server',
    'Database Server',
    'Power Grid Controller',
    'Water Supply System',
    'Healthcare System',
    'Other'
  ];

  constructor() {
    this.systemForm = this.fb.group({
      localName: ['', [Validators.required, Validators.minLength(3)]],
      ipAddress: ['', [Validators.required, Validators.pattern(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)]],
      systemType: ['', Validators.required],
      description: [''],
      sshPort: [22, [Validators.required, Validators.min(1), Validators.max(65535)]],
      sshUsername: ['', Validators.required],
      sshPassword: ['', Validators.required],
      logPath: ['/var/log', Validators.required]
    });
  }

  onSubmit(): void {
    if (this.systemForm.valid) {
      this.submitting = true;
      
      const newSystem: MonitoredSystem = {
        ...this.systemForm.value,
        dateConfigured: new Date(),
        isActive: true
      };

      this.systemService.addSystem(newSystem).subscribe({
        next: (response) => {
          this.snackBar.open('System added successfully!', 'Close', { duration: 3000 });
          this.router.navigate(['/home']);
        },
        error: (error) => {
          console.error('Error adding system:', error);
          this.snackBar.open('Error adding system. Please try again.', 'Close', { duration: 3000 });
          this.submitting = false;
        }
      });
    } else {
      this.snackBar.open('Please fill all required fields correctly', 'Close', { duration: 3000 });
    }
  }

  onCancel(): void {
    this.router.navigate(['/home']);
  }
}
