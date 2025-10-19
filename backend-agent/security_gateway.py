import os
import requests
import json
import logging
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SecurityAnalysisResult:
    """Result of security analysis from the gateway"""
    recommendation: str  # "ALLOW", "BLOCK", "REVIEW"
    analysis_id: Optional[str] = None
    risk_score: Optional[float] = None
    threats_detected: Optional[list] = None
    policy_violations: Optional[list] = None
    filtered_content: Optional[str] = None
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
    
    def __init__(self, base_url: str = None, application_id: str = "stars-backend"):
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
    
    def analyze_input(self, content: str, context: Dict[str, Any] = None) -> SecurityAnalysisResult:
        """
        Analyze input content for security threats before sending to LLM
        
        Args:
            content: The prompt/content to analyze
            context: Additional context (model_name, tool_name, etc.)
        
        Returns:
            SecurityAnalysisResult with analysis results
        """
        # Handle different modes
        if not self.enabled or self._mode == 'disabled':
            return SecurityAnalysisResult(recommendation="ALLOW")
        
        # For monitor and audit modes, always allow but log
        if self._mode in ['monitor', 'audit']:
            try:
                # Still perform analysis for logging purposes
                result = self._perform_analysis(content, "input", context)
                # Override recommendation to always allow in monitor mode
                result.recommendation = "ALLOW"
                # Log the event
                self.log_security_event("llm_input", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway monitoring error: {e}")
                return SecurityAnalysisResult(recommendation="ALLOW", error=str(e))
        
        # For enforce mode, perform full analysis and respect recommendations
        elif self._mode == 'enforce':
            try:
                result = self._perform_analysis(content, "input", context)
                self.log_security_event("llm_input", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway enforcement error: {e}")
                return SecurityAnalysisResult(recommendation="ALLOW", error=str(e))
        
        # Fallback
        return SecurityAnalysisResult(recommendation="ALLOW")
    
    def _perform_analysis(self, content: str, analysis_type: str, context: Dict[str, Any] = None) -> SecurityAnalysisResult:
        """Internal method to perform the actual security analysis"""
        payload = {
            "content": content,
            "application_id": self.application_id,
            "analysis_type": analysis_type,
            **(context or {})
        }
        
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
    
    def analyze_output(self, content: str, input_analysis_id: Optional[str] = None, 
                      context: Dict[str, Any] = None) -> SecurityAnalysisResult:
        """
        Analyze output content from LLM for policy violations
        
        Args:
            content: The LLM response to analyze
            input_analysis_id: ID from the corresponding input analysis
            context: Additional context (model_name, tool_name, etc.)
        
        Returns:
            SecurityAnalysisResult with analysis results
        """
        # Handle different modes
        if not self.enabled or self._mode == 'disabled':
            return SecurityAnalysisResult(recommendation="ALLOW")
        
        # For monitor and audit modes, always allow but log
        if self._mode in ['monitor', 'audit']:
            try:
                # Still perform analysis for logging purposes
                result = self._perform_analysis_with_context(content, "output", input_analysis_id, context)
                # Override recommendation to always allow in monitor mode
                result.recommendation = "ALLOW"
                # Log the event
                self.log_security_event("llm_output", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway monitoring error: {e}")
                return SecurityAnalysisResult(recommendation="ALLOW", error=str(e))
        
        # For enforce mode, perform full analysis and respect recommendations
        elif self._mode == 'enforce':
            try:
                result = self._perform_analysis_with_context(content, "output", input_analysis_id, context)
                self.log_security_event("llm_output", content, result, context)
                return result
            except Exception as e:
                logger.warning(f"Security gateway enforcement error: {e}")
                return SecurityAnalysisResult(recommendation="ALLOW", error=str(e))
        
        # Fallback
        return SecurityAnalysisResult(recommendation="ALLOW")
    
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
            "timestamp": None,  # Will be set by logging system
            "event_type": event_type,
            "application_id": self.application_id,
            "recommendation": result.recommendation,
            "risk_score": result.risk_score,
            "threats_detected": result.threats_detected,
            "policy_violations": result.policy_violations,
            "analysis_id": result.analysis_id,
            "content_length": len(content) if content else 0,
            "context": context or {}
        }
        
        if result.recommendation == "BLOCK":
            logger.warning(f"Security Gateway BLOCKED {event_type}: {json.dumps(event_data)}")
        elif result.recommendation == "REVIEW":
            logger.info(f"Security Gateway FLAGGED {event_type}: {json.dumps(event_data)}")
        elif result.threats_detected or result.policy_violations:
            logger.info(f"Security Gateway DETECTED {event_type}: {json.dumps(event_data)}")

# Global instance
_security_gateway = None

def get_security_gateway() -> SecurityGateway:
    """Get the global security gateway instance"""
    global _security_gateway
    if _security_gateway is None:
        _security_gateway = SecurityGateway()
    return _security_gateway
