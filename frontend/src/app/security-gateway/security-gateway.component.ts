import { Component, OnInit, OnDestroy } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Subject, takeUntil, timer } from 'rxjs';
import { CommonModule } from '@angular/common';
import { MaterialModule } from '../material.module';
import { 
  SecurityGatewayService, 
  SecurityGatewayConfig, 
  SecurityGatewayStatus,
  ConnectionTestResult,
  ConfigUpdateResult,
  ModeChangeResult,
  SecurityAnalysisResult,
  AnalysisRequest
} from '../services/security-gateway.service';

@Component({
  selector: 'app-security-gateway',
  templateUrl: './security-gateway.component.html',
  styleUrls: ['./security-gateway.component.css'],
  imports: [CommonModule, MaterialModule, ReactiveFormsModule],
  standalone: true
})
export class SecurityGatewayComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  
  // Expose Math object to template
  Math = Math;
  
  configForm: FormGroup;
  status: SecurityGatewayStatus | null = null;
  config: SecurityGatewayConfig | null = null;
  connectionTest: ConnectionTestResult | null = null;
  availableModes: { [key: string]: string } = {};
  availablePolicies: any = {};
  currentPolicy: string = 'default';
  
  loading = {
    status: false,
    config: false,
    testConnection: false,
    updateConfig: false,
    changeMode: false,
    policies: false
  };

  constructor(
    private securityGatewayService: SecurityGatewayService,
    private formBuilder: FormBuilder,
    private snackBar: MatSnackBar
  ) {
    this.configForm = this.formBuilder.group({
      base_url: ['', [Validators.required, this.urlValidator]],
      application_id: ['', Validators.required],
      timeout: [10, [Validators.required, Validators.min(1), Validators.max(300)]],
      enabled: [true],
      mode: ['monitor', Validators.required]
    });
  }

  ngOnInit(): void {
    this.loadStatus();
    this.loadConfig();
    this.loadAvailableModes();
    this.loadAvailablePolicies();
    
    // Auto-refresh status every 30 seconds
    timer(0, 30000)
      .pipe(takeUntil(this.destroy$))
      .subscribe(() => {
        if (!this.loading.status) {
          this.loadStatus();
        }
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  private urlValidator(control: any) {
    if (!control.value) return null;
    
    try {
      const url = new URL(control.value);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return { invalidUrl: true };
      }
      return null;
    } catch {
      return { invalidUrl: true };
    }
  }

  loadStatus(): void {
    this.loading.status = true;
    this.securityGatewayService.getStatus()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (status) => {
          this.status = status;
          this.loading.status = false;
        },
        error: (error) => {
          this.showError('Failed to load status: ' + error.message);
          this.loading.status = false;
        }
      });
  }

  loadConfig(): void {
    this.loading.config = true;
    this.securityGatewayService.getConfig()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (config) => {
          this.config = config;
          this.configForm.patchValue(config);
          this.loading.config = false;
        },
        error: (error) => {
          this.showError('Failed to load configuration: ' + error.message);
          this.loading.config = false;
        }
      });
  }

  loadAvailableModes(): void {
    this.securityGatewayService.getAvailableModes()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (modes) => {
          this.availableModes = modes.modes;
        },
        error: (error) => {
          this.showError('Failed to load available modes: ' + error.message);
        }
      });
  }

  loadAvailablePolicies(): void {
    this.loading.policies = true;
    this.securityGatewayService.getAvailablePolicies()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (response) => {
          this.availablePolicies = response.policies;
          this.currentPolicy = response.default_policy || 'default';
          this.loading.policies = false;
        },
        error: (error) => {
          this.showError('Failed to load available policies: ' + error.message);
          this.loading.policies = false;
        }
      });
  }

  changePolicy(policy: string): void {
    this.currentPolicy = policy;
    this.showSuccess(`Policy changed to ${policy}`);
  }

  getPolicyKeys(): string[] {
    return Object.keys(this.availablePolicies);
  }

  getPolicyColor(policy: string): string {
    switch (policy.toLowerCase()) {
      case 'default':
        return 'primary';
      case 'enhanced':
        return 'accent';
      default:
        return 'primary';
    }
  }

  testConnection(url?: string): void {
    this.loading.testConnection = true;
    this.connectionTest = null;
    
    const testUrl = url || this.configForm.get('base_url')?.value;
    
    this.securityGatewayService.testConnection(testUrl)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (result) => {
          this.connectionTest = result;
          this.loading.testConnection = false;
          
          if (result.success) {
            this.showSuccess(`Connection successful! Response time: ${Math.round(result.response_time_ms || 0)}ms`);
          } else {
            this.showError(`Connection failed: ${result.error}`);
          }
        },
        error: (error) => {
          this.loading.testConnection = false;
          this.showError('Connection test failed: ' + error.message);
        }
      });
  }

  updateConfiguration(): void {
    if (this.configForm.invalid) {
      this.markFormGroupTouched();
      return;
    }

    this.loading.updateConfig = true;
    const formValue = this.configForm.value;
    
    this.securityGatewayService.updateConfig(formValue)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (result: ConfigUpdateResult) => {
          this.loading.updateConfig = false;
          
          if (result.status === 'success') {
            this.showSuccess(result.message);
            this.config = result.current_config;
            this.loadStatus(); // Refresh status
          } else if (result.status === 'partial_success') {
            this.showWarning(`${result.message}. Failed updates: ${result.failed_updates.join(', ')}`);
            this.config = result.current_config;
            this.loadStatus();
          }
        },
        error: (error) => {
          this.loading.updateConfig = false;
          this.showError('Failed to update configuration: ' + error.message);
        }
      });
  }

  changeMode(mode: string): void {
    this.loading.changeMode = true;
    
    this.securityGatewayService.setMode(mode)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (result: ModeChangeResult) => {
          this.loading.changeMode = false;
          this.showSuccess(result.message);
          this.configForm.patchValue({ mode: result.mode });
          this.loadStatus(); // Refresh status
        },
        error: (error) => {
          this.loading.changeMode = false;
          this.showError('Failed to change mode: ' + error.message);
        }
      });
  }

  resetForm(): void {
    if (this.config) {
      this.configForm.patchValue(this.config);
      this.configForm.markAsUntouched();
    }
  }

  refreshAll(): void {
    this.loadStatus();
    this.loadConfig();
    this.connectionTest = null;
  }

  private markFormGroupTouched(): void {
    Object.keys(this.configForm.controls).forEach(key => {
      this.configForm.get(key)?.markAsTouched();
    });
  }

  private showSuccess(message: string): void {
    this.snackBar.open(message, 'Close', {
      duration: 5000,
      panelClass: ['success-snackbar']
    });
  }

  private showError(message: string): void {
    this.snackBar.open(message, 'Close', {
      duration: 8000,
      panelClass: ['error-snackbar']
    });
  }

  private showWarning(message: string): void {
    this.snackBar.open(message, 'Close', {
      duration: 6000,
      panelClass: ['warning-snackbar']
    });
  }

  // Helper methods for template
  getStatusColor(mode: string): string {
    return this.securityGatewayService.getStatusColor(mode);
  }

  getStatusIcon(mode: string): string {
    return this.securityGatewayService.getStatusIcon(mode);
  }

  getConnectionStatusColor(status: string): string {
    return this.securityGatewayService.getConnectionStatusColor(status);
  }

  getConnectionStatusIcon(status: string): string {
    return this.securityGatewayService.getConnectionStatusIcon(status);
  }

  getModeKeys(): string[] {
    return Object.keys(this.availableModes);
  }

  isFormChanged(): boolean {
    if (!this.config) return false;
    
    const formValue = this.configForm.value;
    return JSON.stringify(formValue) !== JSON.stringify({
      base_url: this.config.base_url,
      application_id: this.config.application_id,
      timeout: this.config.timeout,
      enabled: this.config.enabled,
      mode: this.config.mode
    });
  }
}
