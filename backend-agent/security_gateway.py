import os
import requests
import json
import logging
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SecurityFinding:
    """Individual security finding from analysis"""
    module: str
    threat_type: str
    confidence: float
    severity: str
    description: str
    details: dict

@dataclass
class SecurityAnalysisResult:
    """Result of security analysis from the gateway"""
    analysis_id: str
    timestamp: str
    content_type: str  # "INPUT" or "OUTPUT"
    threat_detected: bool
    confidence_score: float
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    findings: list[SecurityFinding]
    recommendation: str  # "ALLOW", "BLOCK", "REVIEW"
    policy_applied: str
    processing_time: float
    modules_used: list[str]
    metadata: dict
    error: Optional[str] = None

class SecurityGateway:
    """Client for the Detection Middleware Gateway API with dynamic mode switching"""
    
    # Available security modes
    MODES = {
        'disabled': 'No security analysis performed',
        'monitor': 'Log all interactions, never block content',
        'enforce': 'Analyze and block/filter based on policies',
        'audit': 'Enhanced logging with detailed analysis'
    }
    
    def __init__(self, base_url: str = None, application_id: str = "benchmark_stars"):
        self.base_url = base_url or os.getenv('SECURITY_GATEWAY_URL', 'http://localhost:8000/api/v1')
        self.application_id = application_id
        self.enabled = os.getenv('SECURITY_GATEWAY_ENABLED', 'true').lower() == 'true'
        self.timeout = int(os.getenv('SECURITY_GATEWAY_TIMEOUT', '10'))
        
        # Initialize mode - can be changed at runtime
        self._mode = os.getenv('SECURITY_GATEWAY_MODE', 'monitor').lower()
        if self._mode not in self.MODES:
            logger.warning(f"Invalid security mode '{self._mode}', defaulting to 'monitor'")
            self._mode = 'monitor'
        
        if self.enabled:
            logger.info(f"Security Gateway initialized: {self.base_url} (mode: {self._mode})")
        else:
            logger.info("Security Gateway disabled")
    
    def is_enabled(self) -> bool:
        """Check if security gateway is enabled"""
        return self.enabled and self._mode != 'disabled'
    
    def get_mode(self) -> str:
        """Get current security mode"""
        return self._mode
    
    def set_mode(self, mode: str) -> bool:
        """
        Set security mode at runtime
        
        Args:
            mode: One of 'disabled', 'monitor', 'enforce', 'audit'
            
        Returns:
            True if mode was set successfully, False otherwise
        """
        mode = mode.lower()
        if mode not in self.MODES:
            logger.error(f"Invalid security mode '{mode}'. Valid modes: {list(self.MODES.keys())}")
            return False
        
        old_mode = self._mode
        self._mode = mode
        logger.info(f"Security Gateway mode changed from '{old_mode}' to '{mode}'")
        return True
    
    def get_available_modes(self) -> Dict[str, str]:
        """Get all available security modes with descriptions"""
        return self.MODES.copy()
    
    def set_base_url(self, url: str) -> bool:
        """
        Set security gateway base URL at runtime
        
        Args:
            url: New base URL for the security gateway
            
        Returns:
            True if URL was set successfully, False otherwise
        """
        if not url or not isinstance(url, str):
            logger.error("Invalid URL provided")
            return False
        
        # Basic URL validation
        if not (url.startswith('http://') or url.startswith('https://')):
            logger.error("URL must start with http:// or https://")
            return False
        
        old_url = self.base_url
        self.base_url = url.rstrip('/')  # Remove trailing slash
        logger.info(f"Security Gateway URL changed from '{old_url}' to '{url}'")
        return True
    
    def set_timeout(self, timeout: int) -> bool:
        """
        Set security gateway timeout at runtime
        
        Args:
            timeout: Timeout in seconds (must be positive)
            
        Returns:
            True if timeout was set successfully, False otherwise
        """
        if not isinstance(timeout, int) or timeout <= 0:
            logger.error("Timeout must be a positive integer")
            return False
        
        old_timeout = self.timeout
        self.timeout = timeout
        logger.info(f"Security Gateway timeout changed from {old_timeout}s to {timeout}s")
        return True
    
    def set_application_id(self, app_id: str) -> bool:
        """
        Set security gateway application ID at runtime
        
        Args:
            app_id: New application ID
            
        Returns:
            True if application ID was set successfully, False otherwise
        """
        if not app_id or not isinstance(app_id, str):
            logger.error("Invalid application ID provided")
            return False
        
        old_app_id = self.application_id
        self.application_id = app_id
        logger.info(f"Security Gateway application ID changed from '{old_app_id}' to '{app_id}'")
        return True
    
    def set_enabled(self, enabled: bool) -> bool:
        """
        Enable or disable security gateway at runtime
        
        Args:
            enabled: True to enable, False to disable
            
        Returns:
            True if setting was changed successfully, False otherwise
        """
        old_enabled = self.enabled
        self.enabled = enabled
        logger.info(f"Security Gateway {'enabled' if enabled else 'disabled'} (was {'enabled' if old_enabled else 'disabled'})")
        return True
    
    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update multiple configuration settings at once
        
        Args:
            config: Dictionary with configuration updates
                   Supported keys: base_url, timeout, application_id, enabled, mode
        
        Returns:
            Dictionary with results of each update attempt
        """
        results = {}
        
        if 'base_url' in config:
            results['base_url'] = self.set_base_url(config['base_url'])
        
        if 'timeout' in config:
            results['timeout'] = self.set_timeout(config['timeout'])
        
        if 'application_id' in config:
            results['application_id'] = self.set_application_id(config['application_id'])
        
        if 'enabled' in config:
            results['enabled'] = self.set_enabled(config['enabled'])
        
        if 'mode' in config:
            results['mode'] = self.set_mode(config['mode'])
        
        return results
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test connectivity to the security gateway
        
        Returns:
            Dictionary with connection test results
        """
        if not self.enabled:
            return {
                "success": False,
                "error": "Security gateway is disabled",
                "status": "disabled"
            }
        
        try:
            # Try to make a simple request to test connectivity
            # We'll use a health check endpoint if available, or try the base URL
            test_url = f"{self.base_url}/health" if not self.base_url.endswith('/health') else self.base_url
            
            response = requests.get(test_url, timeout=self.timeout)
            
            return {
                "success": True,
                "status_code": response.status_code,
                "response_time_ms": response.elapsed.total_seconds() * 1000,
                "url": test_url,
                "status": "connected"
            }
            
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": f"Connection timeout after {self.timeout}s",
                "url": self.base_url,
                "status": "timeout"
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "error": "Connection refused or host unreachable",
                "url": self.base_url,
                "status": "connection_error"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "url": self.base_url,
                "status": "error"
            }
    
    def get_config(self) -> Dict[str, Any]:
        """Get current gateway configuration"""
        return {
            "base_url": self.base_url,
            "application_id": self.application_id,
            "timeout": self.timeout,
            "enabled": self.enabled,
            "mode": self._mode
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive status of security gateway"""
        return {
            "enabled": self.enabled,
            "mode": self._mode,
            "mode_description": self.MODES.get(self._mode, "Unknown"),
            "base_url": self.base_url,
            "application_id": self.application_id,
            "timeout": self.timeout,
            "available_modes": self.MODES
        }
    
    def analyze_input(self, content: str, context: Dict[str, Any] = None, 
                     session_id: Optional[str] = None, policy: str = "default") -> SecurityAnalysisResult:
        """
        Analyze input content for security threats before sending to LLM
        
        Args:
            content: The prompt/content to analyze
            context: Additional context (model_name, tool_name, etc.)
            session_id: Session correlation ID
            policy: Security policy to use ("default" or "enhanced")
        
        Returns:
            SecurityAnalysisResult with analysis results
        """
        # Handle different modes
        if not self.enabled or self._mode == 'disabled':
            return self._create_empty_result("INPUT", "ALLOW")
        
        # For monitor and audit modes, always allow but log
        if self._mode in ['monitor', 'audit']:
            try:
                # Still perform analysis for logging purposes
                result = self._perform_input_analysis(content, context, session_id, policy)
                # Override recommendation to always allow in monitor mode
                result.recommendation = "ALLOW"
                # Log the event
                self.log_security_event("llm_input", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway monitoring error: {e}")
                return self._create_empty_result("INPUT", "ALLOW", str(e))
        
        # For enforce mode, perform full analysis and respect recommendations
        elif self._mode == 'enforce':
            try:
                result = self._perform_input_analysis(content, context, session_id, policy)
                self.log_security_event("llm_input", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway enforcement error: {e}")
                return self._create_empty_result("INPUT", "ALLOW", str(e))
        
        # Fallback
        return self._create_empty_result("INPUT", "ALLOW")
    
    def _create_empty_result(self, content_type: str, recommendation: str, error: Optional[str] = None) -> SecurityAnalysisResult:
        """Create an empty security analysis result for fallback cases"""
        import uuid
        from datetime import datetime
        
        return SecurityAnalysisResult(
            analysis_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow().isoformat(),
            content_type=content_type,
            threat_detected=False,
            confidence_score=0.0,
            severity="LOW",
            findings=[],
            recommendation=recommendation,
            policy_applied="none",
            processing_time=0.0,
            modules_used=[],
            metadata={},
            error=error
        )
    
    def _perform_input_analysis(self, content: str, context: Dict[str, Any] = None, 
                               session_id: Optional[str] = None, policy: str = "default") -> SecurityAnalysisResult:
        """Perform input analysis using the new API format"""
        payload = {
            "content": content,
            "application_id": self.application_id,
            "policy": policy
        }
        
        if context:
            payload["context"] = context
        if session_id:
            payload["session_id"] = session_id
        
        response = requests.post(
            f"{self.base_url}/analyze/input",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            return self._parse_analysis_response(data)
        else:
            logger.warning(f"Security gateway input analysis failed: {response.status_code}")
            return self._create_empty_result("INPUT", "ALLOW", f"HTTP {response.status_code}: {response.text}")
    
    def _parse_analysis_response(self, data: Dict[str, Any]) -> SecurityAnalysisResult:
        """Parse the new API response format into SecurityAnalysisResult"""
        findings = []
        for finding_data in data.get("findings", []):
            findings.append(SecurityFinding(
                module=finding_data.get("module", "unknown"),
                threat_type=finding_data.get("threat_type", "unknown"),
                confidence=finding_data.get("confidence", 0.0),
                severity=finding_data.get("severity", "LOW"),
                description=finding_data.get("description", ""),
                details=finding_data.get("details", {})
            ))
        
        return SecurityAnalysisResult(
            analysis_id=data.get("analysis_id", "unknown"),
            timestamp=data.get("timestamp", ""),
            content_type=data.get("content_type", "INPUT"),
            threat_detected=data.get("threat_detected", False),
            confidence_score=data.get("confidence_score", 0.0),
            severity=data.get("severity", "LOW"),
            findings=findings,
            recommendation=data.get("recommendation", "ALLOW"),
            policy_applied=data.get("policy_applied", "default"),
            processing_time=data.get("processing_time", 0.0),
            modules_used=data.get("modules_used", []),
            metadata=data.get("metadata", {})
        )
    
    
    def analyze_output(self, content: str, input_analysis_id: Optional[str] = None, 
                      context: Dict[str, Any] = None, session_id: Optional[str] = None, 
                      policy: str = "default") -> SecurityAnalysisResult:
        """
        Analyze output content from LLM for policy violations
        
        Args:
            content: The LLM response to analyze
            input_analysis_id: ID from the corresponding input analysis
            context: Additional context (model_name, tool_name, etc.)
            session_id: Session correlation ID
            policy: Security policy to use ("default" or "enhanced")
        
        Returns:
            SecurityAnalysisResult with analysis results
        """
        # Handle different modes
        if not self.enabled or self._mode == 'disabled':
            return self._create_empty_result("OUTPUT", "ALLOW")
        
        # For monitor and audit modes, always allow but log
        if self._mode in ['monitor', 'audit']:
            try:
                # Still perform analysis for logging purposes
                result = self._perform_output_analysis(content, input_analysis_id, context, session_id, policy)
                # Override recommendation to always allow in monitor mode
                result.recommendation = "ALLOW"
                # Log the event
                self.log_security_event("llm_output", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway monitoring error: {e}")
                return self._create_empty_result("OUTPUT", "ALLOW", str(e))
        
        # For enforce mode, perform full analysis and respect recommendations
        elif self._mode == 'enforce':
            try:
                result = self._perform_output_analysis(content, input_analysis_id, context, session_id, policy)
                self.log_security_event("llm_output", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway enforcement error: {e}")
                return self._create_empty_result("OUTPUT", "ALLOW", str(e))
        
        # Fallback
        return self._create_empty_result("OUTPUT", "ALLOW")
    
    def _perform_output_analysis(self, content: str, input_analysis_id: Optional[str] = None,
                                context: Dict[str, Any] = None, session_id: Optional[str] = None, 
                                policy: str = "default") -> SecurityAnalysisResult:
        """Perform output analysis using the new API format"""
        payload = {
            "content": content,
            "application_id": self.application_id,
            "policy": policy
        }
        
        if context:
            payload["context"] = context
        if session_id:
            payload["session_id"] = session_id
        if input_analysis_id:
            payload["input_analysis_id"] = input_analysis_id
        
        response = requests.post(
            f"{self.base_url}/analyze/output",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            return self._parse_analysis_response(data)
        else:
            logger.warning(f"Security gateway output analysis failed: {response.status_code}")
            return self._create_empty_result("OUTPUT", "ALLOW", f"HTTP {response.status_code}: {response.text}")
    
    def _perform_analysis_with_context(self, content: str, analysis_type: str, 
                                     input_analysis_id: Optional[str] = None,
                                     context: Dict[str, Any] = None) -> SecurityAnalysisResult:
        """Internal method to perform security analysis with additional context"""
        payload = {
            "content": content,
            "application_id": self.application_id,
            "analysis_type": analysis_type,
            **(context or {})
        }
        
        if input_analysis_id:
            payload["input_analysis_id"] = input_analysis_id
        
        response = requests.post(
            f"{self.base_url}/analyze/{analysis_type}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            return SecurityAnalysisResult(
                recommendation=data.get("recommendation", "ALLOW"),
                analysis_id=data.get("analysis_id"),
                risk_score=data.get("risk_score"),
                threats_detected=data.get("threats_detected", []),
                policy_violations=data.get("policy_violations", []),
                filtered_content=data.get("filtered_content")
            )
        else:
            logger.warning(f"Security gateway {analysis_type} analysis failed: {response.status_code}")
            return SecurityAnalysisResult(
                recommendation="ALLOW",
                error=f"HTTP {response.status_code}: {response.text}"
            )
    
    def log_security_event(self, event_type: str, content: str, result: SecurityAnalysisResult, 
                          context: Dict[str, Any] = None):
        """Log security events for audit trail"""
        event_data = {
            "timestamp": result.timestamp,
            "event_type": event_type,
            "application_id": self.application_id,
            "recommendation": result.recommendation,
            "threat_detected": result.threat_detected,
            "confidence_score": result.confidence_score,
            "severity": result.severity,
            "findings_count": len(result.findings),
            "analysis_id": result.analysis_id,
            "content_length": len(content) if content else 0,
            "policy_applied": result.policy_applied,
            "processing_time": result.processing_time,
            "modules_used": result.modules_used,
            "context": context or {}
        }
        
        if result.recommendation == "BLOCK":
            logger.warning(f"Security Gateway BLOCKED {event_type}: {json.dumps(event_data)}")
        elif result.recommendation == "REVIEW":
            logger.info(f"Security Gateway FLAGGED {event_type}: {json.dumps(event_data)}")
        elif result.threat_detected:
            logger.info(f"Security Gateway DETECTED {event_type}: {json.dumps(event_data)}")

# Global instance
_security_gateway = None

def get_security_gateway() -> SecurityGateway:
    """Get the global security gateway instance"""
    global _security_gateway
    if _security_gateway is None:
        _security_gateway = SecurityGateway()
    return _security_gateway
