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
    """Client for the Detection Middleware Gateway API"""
    
    def __init__(self, base_url: str = None, application_id: str = "stars-backend"):
        self.base_url = base_url or os.getenv('SECURITY_GATEWAY_URL', 'http://localhost:8000/api/v1')
        self.application_id = application_id
        self.enabled = os.getenv('SECURITY_GATEWAY_ENABLED', 'true').lower() == 'true'
        self.timeout = int(os.getenv('SECURITY_GATEWAY_TIMEOUT', '10'))
        
        if self.enabled:
            logger.info(f"Security Gateway initialized: {self.base_url}")
        else:
            logger.info("Security Gateway disabled")
    
    def is_enabled(self) -> bool:
        """Check if security gateway is enabled"""
        return self.enabled
    
    def analyze_input(self, content: str, context: Dict[str, Any] = None) -> SecurityAnalysisResult:
        """
        Analyze input content for security threats before sending to LLM
        
        Args:
            content: The prompt/content to analyze
            context: Additional context (model_name, tool_name, etc.)
        
        Returns:
            SecurityAnalysisResult with analysis results
        """
        if not self.enabled:
            return SecurityAnalysisResult(recommendation="ALLOW")
        
        try:
            payload = {
                "content": content,
                "application_id": self.application_id,
                "analysis_type": "input",
                **(context or {})
            }
            
            response = requests.post(
                f"{self.base_url}/analyze/input",
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
                logger.warning(f"Security gateway input analysis failed: {response.status_code}")
                return SecurityAnalysisResult(
                    recommendation="ALLOW",
                    error=f"HTTP {response.status_code}: {response.text}"
                )
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Security gateway input analysis error: {e}")
            return SecurityAnalysisResult(
                recommendation="ALLOW",
                error=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error in input analysis: {e}")
            return SecurityAnalysisResult(
                recommendation="ALLOW",
                error=str(e)
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
        if not self.enabled:
            return SecurityAnalysisResult(recommendation="ALLOW")
        
        try:
            payload = {
                "content": content,
                "application_id": self.application_id,
                "analysis_type": "output",
                **(context or {})
            }
            
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
                return SecurityAnalysisResult(
                    recommendation=data.get("recommendation", "ALLOW"),
                    analysis_id=data.get("analysis_id"),
                    risk_score=data.get("risk_score"),
                    threats_detected=data.get("threats_detected", []),
                    policy_violations=data.get("policy_violations", []),
                    filtered_content=data.get("filtered_content")
                )
            else:
                logger.warning(f"Security gateway output analysis failed: {response.status_code}")
                return SecurityAnalysisResult(
                    recommendation="ALLOW",
                    error=f"HTTP {response.status_code}: {response.text}"
                )
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Security gateway output analysis error: {e}")
            return SecurityAnalysisResult(
                recommendation="ALLOW",
                error=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error in output analysis: {e}")
            return SecurityAnalysisResult(
                recommendation="ALLOW",
                error=str(e)
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
