"""
Google Model Armor provider using the official Google Cloud Security Command Center client library.

This module provides threat detection capabilities using Google's Model Armor service
through the official Google Cloud client library for better authentication, error handling,
and API compatibility.
"""

import asyncio
import logging
import time
from typing import Dict, Optional

try:
    from google.cloud import modelarmor_v1
    from google.api_core.client_options import ClientOptions
    from google.auth import default
    from google.auth.exceptions import DefaultCredentialsError
    from google.api_core import exceptions as gcp_exceptions
    GOOGLE_CLOUD_AVAILABLE = True
except ImportError:
    GOOGLE_CLOUD_AVAILABLE = False

from threat_detection import ThreatDetectionProvider, ThreatAnalysisResult

logger = logging.getLogger(__name__)


class GoogleModelArmorProvider(ThreatDetectionProvider):
    """
    Google Model Armor threat detection provider using the official Google Cloud client library.
    
    This provider uses Google Cloud Security Command Center's Model Armor service to detect
    threats in prompts and responses. It supports both service account authentication and
    Application Default Credentials (ADC).
    """
    
    def __init__(self, config: Dict):
        super().__init__(config)
        
        if not GOOGLE_CLOUD_AVAILABLE:
            logger.error("Google Cloud Security Command Center library not available. "
                        "Install with: pip install google-cloud-security-command-center")
            self.enabled = False
            return
        
        # Configuration
        self.project_id = config.get('project_id')
        self.location = config.get('location', 'europe-west4')
        self.template_id = config.get('template_id', 'ai-sec-bench')
        self.service_account_path = config.get('service_account_path')
        
        # Initialize client
        self.client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the Google Cloud Model Armor client."""
        try:
            if self.service_account_path:
                # Use service account key file
                import os
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self.service_account_path
            
            # Initialize the client with default credentials
            credentials, project = default()
            
            # Use configured project_id or fall back to default project
            if not self.project_id:
                self.project_id = project
            
            if not self.project_id:
                logger.error("No project ID configured for Google Model Armor. "
                           "Set GOOGLE_MODEL_ARMOR_PROJECT_ID environment variable.")
                self.enabled = False
                return
            
            # Create the Model Armor client with proper endpoint
            client_options = ClientOptions(
                api_endpoint=f"modelarmor.{self.location}.rep.googleapis.com"
            )
            
            self.client = modelarmor_v1.ModelArmorClient(
                transport="rest",
                client_options=client_options,
                credentials=credentials
            )
            
            logger.info(f"Google Model Armor provider initialized for project: {self.project_id}, location: {self.location}")
            
        except DefaultCredentialsError as e:
            logger.error(f"Google Cloud credentials not found: {e}")
            logger.error("Set up Application Default Credentials or provide a service account key file.")
            self.enabled = False
        except Exception as e:
            logger.error(f"Failed to initialize Google Model Armor client: {e}")
            self.enabled = False
    
    def get_provider_name(self) -> str:
        return "google_model_armor"
    
    def is_available(self) -> bool:
        return (super().is_available() and 
                GOOGLE_CLOUD_AVAILABLE and 
                self.client is not None and 
                self.project_id is not None)
    
    async def analyze_prompt(self, prompt: str, context: Dict) -> ThreatAnalysisResult:
        """Analyze a prompt for threats using Google Model Armor."""
        return await self._analyze_content(prompt, "prompt", context)
    
    async def analyze_response(self, response: str, context: Dict) -> ThreatAnalysisResult:
        """Analyze a model response for threats using Google Model Armor."""
        return await self._analyze_content(response, "response", context)
    
    async def _analyze_content(self, content: str, content_type: str, context: Dict) -> ThreatAnalysisResult:
        """
        Analyze content using Google Model Armor service.
        
        Args:
            content: The text content to analyze
            content_type: Either "prompt" or "response"
            context: Additional context information
            
        Returns:
            ThreatAnalysisResult with the analysis results
        """
        start_time = time.time()
        
        if not self.is_available():
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=False,
                threat_types=[],
                confidence_score=0.0,
                details={},
                processing_time=time.time() - start_time,
                error="Google Model Armor provider not available"
            )
        
        try:
            # Run the synchronous Google Cloud API call in a thread pool
            # to avoid blocking the async event loop
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                self._call_model_armor_api, 
                content, 
                content_type, 
                context
            )
            
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=result['threat_detected'],
                threat_types=result['threat_types'],
                confidence_score=result['confidence_score'],
                details=result['details'],
                processing_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Google Model Armor analysis failed: {str(e)}")
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=False,
                threat_types=[],
                confidence_score=0.0,
                details={},
                processing_time=time.time() - start_time,
                error=str(e)
            )
    
    def _call_model_armor_api(self, content: str, content_type: str, context: Dict) -> Dict:
        """
        Make the actual API call to Google Model Armor.
        
        This method runs synchronously and should be called from an executor.
        """
        try:
            # Create the data item for the content
            user_prompt_data = modelarmor_v1.DataItem(text=content)
            
            # Construct the template name
            template_name = f"projects/{self.project_id}/locations/{self.location}/templates/{self.template_id}"
            
            # Create the request based on the actual Model Armor API
            if content_type == "prompt":
                request = modelarmor_v1.SanitizeUserPromptRequest(
                    name=template_name,
                    user_prompt_data=user_prompt_data,
                )
                
                # Call the sanitize user prompt API
                response = self.client.sanitize_user_prompt(request=request)
            else:
                # For responses, we might use a different method or the same one
                # For now, use the same sanitize method
                request = modelarmor_v1.SanitizeUserPromptRequest(
                    name=template_name,
                    user_prompt_data=user_prompt_data,
                )
                
                response = self.client.sanitize_user_prompt(request=request)
            
            # Parse the response
            return self._parse_model_armor_response(response, content_type)
            
        except gcp_exceptions.GoogleAPIError as e:
            logger.error(f"Google Cloud API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in Model Armor API call: {e}")
            raise
    
    def _parse_model_armor_response(self, response, content_type: str) -> Dict:
        """
        Parse the Google Model Armor API response.
        
        Args:
            response: The response from the Model Armor API
            content_type: Either "prompt" or "response"
            
        Returns:
            Dict with parsed threat detection results
        """
        try:
            threat_detected = False
            threat_types = []
            max_confidence = 0.0
            details = {
                'project_id': self.project_id,
                'location': self.location,
                'template_id': self.template_id,
                'content_type': content_type,
                'invocation_result': str(response.invocation_result),
                'filter_results': {}
            }
            
            # Check if any filters found matches
            if hasattr(response, 'sanitization_result'):
                sanitization_result = response.sanitization_result
                
                # Check overall filter match state
                if hasattr(sanitization_result, 'filter_match_state'):
                    if sanitization_result.filter_match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                        threat_detected = True
                
                # Parse individual filter results
                if hasattr(sanitization_result, 'filter_results'):
                    for filter_name, filter_result in sanitization_result.filter_results.items():
                        details['filter_results'][filter_name] = {}
                        
                        # Handle RAI (Responsible AI) filter results
                        if hasattr(filter_result, 'rai_filter_result'):
                            rai_result = filter_result.rai_filter_result
                            if rai_result.match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                                threat_detected = True
                                threat_types.append('rai_violation')
                                
                                # Parse RAI filter type results
                                for rai_type, rai_type_result in rai_result.rai_filter_type_results.items():
                                    if rai_type_result.match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                                        threat_types.append(f'rai_{rai_type}')
                                        # Convert confidence level to numeric score
                                        confidence = self._confidence_level_to_score(rai_type_result.confidence_level)
                                        max_confidence = max(max_confidence, confidence)
                            
                            details['filter_results'][filter_name]['rai'] = {
                                'execution_state': str(rai_result.execution_state),
                                'match_state': str(rai_result.match_state)
                            }
                        
                        # Handle prompt injection and jailbreak filter results
                        if hasattr(filter_result, 'pi_and_jailbreak_filter_result'):
                            pi_result = filter_result.pi_and_jailbreak_filter_result
                            if pi_result.match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                                threat_detected = True
                                threat_types.append('prompt_injection_jailbreak')
                                confidence = self._confidence_level_to_score(pi_result.confidence_level)
                                max_confidence = max(max_confidence, confidence)
                            
                            details['filter_results'][filter_name]['pi_jailbreak'] = {
                                'execution_state': str(pi_result.execution_state),
                                'match_state': str(pi_result.match_state),
                                'confidence_level': str(pi_result.confidence_level)
                            }
                        
                        # Handle malicious URI filter results
                        if hasattr(filter_result, 'malicious_uri_filter_result'):
                            uri_result = filter_result.malicious_uri_filter_result
                            if uri_result.match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                                threat_detected = True
                                threat_types.append('malicious_uri')
                            
                            details['filter_results'][filter_name]['malicious_uri'] = {
                                'execution_state': str(uri_result.execution_state),
                                'match_state': str(uri_result.match_state)
                            }
                        
                        # Handle CSAM filter results
                        if hasattr(filter_result, 'csam_filter_filter_result'):
                            csam_result = filter_result.csam_filter_filter_result
                            if csam_result.match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                                threat_detected = True
                                threat_types.append('csam')
                            
                            details['filter_results'][filter_name]['csam'] = {
                                'execution_state': str(csam_result.execution_state),
                                'match_state': str(csam_result.match_state)
                            }
            
            return {
                'threat_detected': threat_detected,
                'threat_types': threat_types,
                'confidence_score': max_confidence,
                'details': details
            }
            
        except Exception as e:
            logger.error(f"Error parsing Model Armor response: {e}")
            # Fallback to simulation if parsing fails
            return self._simulate_threat_detection_fallback(content_type)
    
    def _confidence_level_to_score(self, confidence_level) -> float:
        """Convert Model Armor confidence level to numeric score."""
        # Map confidence levels to numeric scores
        confidence_mapping = {
            modelarmor_v1.ConfidenceLevel.HIGH: 0.9,
            modelarmor_v1.ConfidenceLevel.MEDIUM: 0.6,
            modelarmor_v1.ConfidenceLevel.LOW: 0.3,
            modelarmor_v1.ConfidenceLevel.CONFIDENCE_LEVEL_UNSPECIFIED: 0.0
        }
        return confidence_mapping.get(confidence_level, 0.0)
    
    def _simulate_threat_detection_fallback(self, content_type: str) -> Dict:
        """Fallback simulation when API parsing fails."""
        return {
            'threat_detected': False,
            'threat_types': [],
            'confidence_score': 0.0,
            'details': {
                'project_id': self.project_id,
                'location': self.location,
                'content_type': content_type,
                'analysis_method': 'fallback_simulation',
                'error': 'Failed to parse Model Armor response'
            }
        }
    
    def _simulate_threat_detection(self, content: str) -> Dict:
        """
        Simulate threat detection for testing purposes.
        
        In a real implementation, this would be replaced by the actual
        Google Model Armor API call results.
        """
        content_lower = content.lower()
        
        # Define threat patterns similar to what Model Armor might detect
        threat_patterns = {
            'prompt_injection': [
                'ignore previous instructions',
                'forget everything above',
                'system prompt',
                'override',
                'disregard'
            ],
            'jailbreak_attempt': [
                'jailbreak',
                'bypass',
                'circumvent',
                'act as',
                'pretend to be'
            ],
            'harmful_content': [
                'how to make',
                'instructions for creating',
                'step by step guide to'
            ],
            'data_extraction': [
                'show me your',
                'reveal your',
                'what is your',
                'tell me about your'
            ]
        }
        
        detected_types = []
        max_confidence = 0.0
        
        for threat_type, patterns in threat_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    detected_types.append(threat_type)
                    # Simulate confidence based on pattern specificity
                    confidence = min(0.9, len(pattern) / 50.0 + 0.3)
                    max_confidence = max(max_confidence, confidence)
                    break
        
        return {
            'detected': len(detected_types) > 0,
            'types': detected_types,
            'confidence': max_confidence
        }
    
    def get_authentication_info(self) -> Dict:
        """Get information about the current authentication setup."""
        return {
            'provider': self.get_provider_name(),
            'project_id': self.project_id,
            'location': self.location,
            'service_account_configured': bool(self.service_account_path),
            'client_available': self.client is not None,
            'google_cloud_library_available': GOOGLE_CLOUD_AVAILABLE
        }


# Factory function to create the provider
def create_google_model_armor_provider(config: Dict) -> GoogleModelArmorProvider:
    """
    Factory function to create a Google Model Armor provider instance.
    
    Args:
        config: Configuration dictionary with the following keys:
            - enabled: Whether the provider is enabled
            - mode: Provider mode ('monitor', 'block', 'disabled')
            - project_id: Google Cloud project ID
            - location: Google Cloud location (default: 'global')
            - service_account_path: Path to service account key file (optional)
    
    Returns:
        GoogleModelArmorProvider instance
    """
    return GoogleModelArmorProvider(config)
