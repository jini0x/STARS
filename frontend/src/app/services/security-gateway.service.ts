import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { ConfigService } from './config.service';

export interface SecurityFinding {
  module: string;
  threat_type: string;
  confidence: number;
  severity: string;
  description: string;
  details: { [key: string]: any };
}

export interface SecurityAnalysisResult {
  analysis_id: string;
  timestamp: string;
  content_type: string; // "INPUT" or "OUTPUT"
  threat_detected: boolean;
  confidence_score: number;
  severity: string; // "LOW", "MEDIUM", "HIGH", "CRITICAL"
  findings: SecurityFinding[];
  recommendation: string; // "ALLOW", "BLOCK", "REVIEW"
  policy_applied: string;
  processing_time: number;
  modules_used: string[];
  metadata: { [key: string]: any };
}

export interface SecurityGatewayConfig {
  base_url: string;
  application_id: string;
  timeout: number;
  enabled: boolean;
  mode: string;
  policy?: string; // "default" or "enhanced"
}

export interface SecurityGatewayStatus {
  enabled: boolean;
  mode: string;
  mode_description: string;
  base_url: string;
  application_id: string;
  timeout: number;
  available_modes: { [key: string]: string };
}

export interface SecurityMode {
  mode: string;
  description: string;
}

export interface SecurityModes {
  modes: { [key: string]: string };
  current_mode: string;
}

export interface ConfigUpdateResult {
  status: string;
  successful_updates: string[];
  failed_updates: string[];
  current_config: SecurityGatewayConfig;
  message: string;
}

export interface ConnectionTestResult {
  success: boolean;
  status_code?: number;
  response_time_ms?: number;
  url?: string;
  status: string;
  error?: string;
}

export interface ModeChangeResult {
  status: string;
  mode: string;
  description: string;
  message: string;
}

export interface AnalysisRequest {
  content: string;
  application_id?: string;
  policy?: string;
  context?: { [key: string]: any };
  session_id?: string;
  target_service?: string;
  user_context?: { [key: string]: any };
  input_analysis_id?: string;
  ai_service?: string;
  model_info?: { [key: string]: any };
}

@Injectable({
  providedIn: 'root'
})
export class SecurityGatewayService {

  constructor(
    private http: HttpClient,
    private configService: ConfigService
  ) { }

  private get apiUrl(): string {
    return this.configService.apiUrl;
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'An unknown error occurred';
    
    if (error.error instanceof ErrorEvent) {
      // Client-side error
      errorMessage = `Error: ${error.error.message}`;
    } else {
      // Server-side error
      errorMessage = error.error?.error || `HTTP ${error.status}: ${error.message}`;
    }
    
    console.error('SecurityGatewayService error:', errorMessage);
    return throwError(() => new Error(errorMessage));
  }

  /**
   * Get comprehensive security gateway status
   */
  getStatus(): Observable<SecurityGatewayStatus> {
    return this.http.get<SecurityGatewayStatus>(`${this.apiUrl}/api/security/status`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Get current security mode
   */
  getCurrentMode(): Observable<SecurityMode> {
    return this.http.get<SecurityMode>(`${this.apiUrl}/api/security/mode`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Set security mode
   */
  setMode(mode: string): Observable<ModeChangeResult> {
    return this.http.post<ModeChangeResult>(`${this.apiUrl}/api/security/mode`, { mode })
      .pipe(catchError(this.handleError));
  }

  /**
   * Get all available security modes
   */
  getAvailableModes(): Observable<SecurityModes> {
    return this.http.get<SecurityModes>(`${this.apiUrl}/api/security/modes`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Get current security gateway configuration
   */
  getConfig(): Observable<SecurityGatewayConfig> {
    return this.http.get<SecurityGatewayConfig>(`${this.apiUrl}/api/security/config`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Update security gateway configuration
   */
  updateConfig(config: Partial<SecurityGatewayConfig>): Observable<ConfigUpdateResult> {
    return this.http.post<ConfigUpdateResult>(`${this.apiUrl}/api/security/config`, config)
      .pipe(catchError(this.handleError));
  }

  /**
   * Test connection to security gateway
   */
  testConnection(url?: string): Observable<ConnectionTestResult> {
    const body = url ? { url } : {};
    return this.http.post<ConnectionTestResult>(`${this.apiUrl}/api/security/test-connection`, body)
      .pipe(catchError(this.handleError));
  }

  /**
   * Analyze input content for security threats
   */
  analyzeInput(request: AnalysisRequest): Observable<SecurityAnalysisResult> {
    return this.http.post<SecurityAnalysisResult>(`${this.apiUrl}/analyze/input`, request)
      .pipe(catchError(this.handleError));
  }

  /**
   * Analyze output content for policy violations
   */
  analyzeOutput(request: AnalysisRequest): Observable<SecurityAnalysisResult> {
    return this.http.post<SecurityAnalysisResult>(`${this.apiUrl}/analyze/output`, request)
      .pipe(catchError(this.handleError));
  }

  /**
   * Get available security policies
   */
  getAvailablePolicies(): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/api/security/policies`)
      .pipe(catchError(this.handleError));
  }

  /**
   * Validate URL format
   */
  validateUrl(url: string): boolean {
    try {
      const urlObj = new URL(url);
      return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
      return false;
    }
  }

  /**
   * Get status color based on security mode
   */
  getStatusColor(mode: string): string {
    switch (mode.toLowerCase()) {
      case 'disabled':
        return 'gray';
      case 'monitor':
        return 'green';
      case 'audit':
        return 'blue';
      case 'enforce':
        return 'red';
      default:
        return 'gray';
    }
  }

  /**
   * Get status icon based on security mode
   */
  getStatusIcon(mode: string): string {
    switch (mode.toLowerCase()) {
      case 'disabled':
        return 'block';
      case 'monitor':
        return 'visibility';
      case 'audit':
        return 'search';
      case 'enforce':
        return 'security';
      default:
        return 'help';
    }
  }

  /**
   * Get connection status color
   */
  getConnectionStatusColor(status: string): string {
    switch (status.toLowerCase()) {
      case 'connected':
        return 'green';
      case 'timeout':
        return 'orange';
      case 'connection_error':
      case 'error':
        return 'red';
      case 'disabled':
        return 'gray';
      default:
        return 'gray';
    }
  }

  /**
   * Get connection status icon
   */
  getConnectionStatusIcon(status: string): string {
    switch (status.toLowerCase()) {
      case 'connected':
        return 'wifi';
      case 'timeout':
        return 'schedule';
      case 'connection_error':
      case 'error':
        return 'wifi_off';
      case 'disabled':
        return 'block';
      default:
        return 'help';
    }
  }
}
