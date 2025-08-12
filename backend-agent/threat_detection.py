"""
Multi-provider threat detection system for AI security monitoring.

This module provides a flexible framework for integrating multiple threat detection
providers (Google Model Armor, Azure Content Safety, OpenAI Moderation, etc.) to
analyze prompts and responses for potential security threats.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Union

import aiohttp
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class ThreatDetectionMode(Enum):
    """Modes for threat detection behavior."""
    DISABLED = "disabled"
    MONITOR = "monitor"  # Log threats but don't block
    BLOCK = "block"      # Block execution if threats detected


class AggregationRule(Enum):
    """Rules for aggregating results from multiple providers."""
    ANY_BLOCK = "any_block"           # Block if ANY provider recommends blocking
    MAJORITY_BLOCK = "majority_block" # Block if MAJORITY recommend blocking
    CONSENSUS_BLOCK = "consensus_block" # Block only if ALL providers agree
    THRESHOLD_BLOCK = "threshold_block" # Block if aggregate confidence > threshold


@dataclass
class ThreatAnalysisResult:
    """Result from a single threat detection provider."""
    provider: str
    threat_detected: bool
    threat_types: List[str]  # e.g., ['prompt_injection', 'harmful_content']
    confidence_score: float  # 0.0 to 1.0
    details: Dict
    processing_time: float
    error: Optional[str] = None


@dataclass
class AggregatedThreatResult:
    """Aggregated result from multiple threat detection providers."""
    individual_results: List[ThreatAnalysisResult]
    consensus_threat_detected: bool
    highest_confidence: float
    threat_types: Set[str]
    recommended_action: str  # 'allow', 'monitor', 'block'
    processing_time: float
    providers_used: List[str]


class ThreatDetectionProvider(ABC):
    """Abstract base class for threat detection providers."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.name = self.get_provider_name()
        self.enabled = config.get('enabled', False)
        self.mode = ThreatDetectionMode(config.get('mode', 'monitor'))
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the name of this provider."""
        pass
    
    @abstractmethod
    async def analyze_prompt(self, prompt: str, context: Dict) -> ThreatAnalysisResult:
        """Analyze a prompt for threats."""
        pass
    
    @abstractmethod
    async def analyze_response(self, response: str, context: Dict) -> ThreatAnalysisResult:
        """Analyze a model response for threats."""
        pass
    
    def is_available(self) -> bool:
        """Check if this provider is available and properly configured."""
        return self.enabled
    
    def should_block_on_threat(self) -> bool:
        """Check if this provider should block execution on threat detection."""
        return self.mode == ThreatDetectionMode.BLOCK


# Google Model Armor provider is now in a separate module
# Import it here to maintain compatibility
try:
    from google_model_armor_provider import GoogleModelArmorProvider
except ImportError:
    # Fallback to a dummy provider if the Google Cloud libraries aren't available
    class GoogleModelArmorProvider(ThreatDetectionProvider):
        """Fallback Google Model Armor provider when Google Cloud libraries are not available."""
        
        def __init__(self, config: Dict):
            super().__init__(config)
            self.enabled = False
            logger.warning("Google Cloud libraries not available. Google Model Armor provider disabled.")
        
        def get_provider_name(self) -> str:
            return "google_model_armor"
        
        def is_available(self) -> bool:
            return False
        
        async def analyze_prompt(self, prompt: str, context: Dict) -> ThreatAnalysisResult:
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=False,
                threat_types=[],
                confidence_score=0.0,
                details={},
                processing_time=0.0,
                error="Google Cloud libraries not available"
            )
        
        async def analyze_response(self, response: str, context: Dict) -> ThreatAnalysisResult:
            return await self.analyze_prompt(response, context)


class AzureContentSafetyProvider(ThreatDetectionProvider):
    """Azure Content Safety threat detection provider."""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.api_key = config.get('api_key')
        self.endpoint = config.get('endpoint', 'https://your-resource.cognitiveservices.azure.com/contentsafety/text:analyze')
    
    def get_provider_name(self) -> str:
        return "azure_content_safety"
    
    def is_available(self) -> bool:
        return super().is_available() and bool(self.api_key)
    
    async def analyze_prompt(self, prompt: str, context: Dict) -> ThreatAnalysisResult:
        return await self._analyze_content(prompt, context)
    
    async def analyze_response(self, response: str, context: Dict) -> ThreatAnalysisResult:
        return await self._analyze_content(response, context)
    
    async def _analyze_content(self, content: str, context: Dict) -> ThreatAnalysisResult:
        start_time = time.time()
        
        try:
            headers = {
                'Ocp-Apim-Subscription-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            payload = {
                'text': content
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.endpoint, headers=headers, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Parse Azure Content Safety response
                        threat_detected = False
                        threat_types = []
                        max_confidence = 0.0
                        
                        for category in result.get('categoriesAnalysis', []):
                            severity = category.get('severity', 0)
                            if severity > 2:  # Azure uses 0-6 scale, consider 3+ as threats
                                threat_detected = True
                                threat_types.append(category.get('category', 'unknown'))
                                max_confidence = max(max_confidence, severity / 6.0)
                        
                        return ThreatAnalysisResult(
                            provider=self.name,
                            threat_detected=threat_detected,
                            threat_types=threat_types,
                            confidence_score=max_confidence,
                            details=result,
                            processing_time=time.time() - start_time
                        )
                    else:
                        error_msg = f"HTTP {response.status}: {await response.text()}"
                        logger.error(f"Azure Content Safety API error: {error_msg}")
                        return ThreatAnalysisResult(
                            provider=self.name,
                            threat_detected=False,
                            threat_types=[],
                            confidence_score=0.0,
                            details={},
                            processing_time=time.time() - start_time,
                            error=error_msg
                        )
        
        except Exception as e:
            logger.error(f"Azure Content Safety analysis failed: {str(e)}")
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=False,
                threat_types=[],
                confidence_score=0.0,
                details={},
                processing_time=time.time() - start_time,
                error=str(e)
            )


class OpenAIModerationProvider(ThreatDetectionProvider):
    """OpenAI Moderation API threat detection provider."""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.api_key = config.get('api_key')
        self.endpoint = config.get('endpoint', 'https://api.openai.com/v1/moderations')
    
    def get_provider_name(self) -> str:
        return "openai_moderation"
    
    def is_available(self) -> bool:
        return super().is_available() and bool(self.api_key)
    
    async def analyze_prompt(self, prompt: str, context: Dict) -> ThreatAnalysisResult:
        return await self._analyze_content(prompt, context)
    
    async def analyze_response(self, response: str, context: Dict) -> ThreatAnalysisResult:
        return await self._analyze_content(response, context)
    
    async def _analyze_content(self, content: str, context: Dict) -> ThreatAnalysisResult:
        start_time = time.time()
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'input': content
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.endpoint, headers=headers, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Parse OpenAI moderation response
                        moderation_result = result['results'][0]
                        threat_detected = moderation_result['flagged']
                        threat_types = []
                        max_confidence = 0.0
                        
                        categories = moderation_result.get('categories', {})
                        category_scores = moderation_result.get('category_scores', {})
                        
                        for category, flagged in categories.items():
                            if flagged:
                                threat_types.append(category)
                                score = category_scores.get(category, 0.0)
                                max_confidence = max(max_confidence, score)
                        
                        return ThreatAnalysisResult(
                            provider=self.name,
                            threat_detected=threat_detected,
                            threat_types=threat_types,
                            confidence_score=max_confidence,
                            details=moderation_result,
                            processing_time=time.time() - start_time
                        )
                    else:
                        error_msg = f"HTTP {response.status}: {await response.text()}"
                        logger.error(f"OpenAI Moderation API error: {error_msg}")
                        return ThreatAnalysisResult(
                            provider=self.name,
                            threat_detected=False,
                            threat_types=[],
                            confidence_score=0.0,
                            details={},
                            processing_time=time.time() - start_time,
                            error=error_msg
                        )
        
        except Exception as e:
            logger.error(f"OpenAI Moderation analysis failed: {str(e)}")
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=False,
                threat_types=[],
                confidence_score=0.0,
                details={},
                processing_time=time.time() - start_time,
                error=str(e)
            )


class CustomRuleBasedProvider(ThreatDetectionProvider):
    """Custom rule-based threat detection provider using regex and keywords."""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.rules = config.get('rules', {})
        self.keywords = config.get('keywords', [])
        self.patterns = config.get('patterns', [])
    
    def get_provider_name(self) -> str:
        return "custom_rule_based"
    
    async def analyze_prompt(self, prompt: str, context: Dict) -> ThreatAnalysisResult:
        return await self._analyze_content(prompt, context)
    
    async def analyze_response(self, response: str, context: Dict) -> ThreatAnalysisResult:
        return await self._analyze_content(response, context)
    
    async def _analyze_content(self, content: str, context: Dict) -> ThreatAnalysisResult:
        start_time = time.time()
        
        try:
            import re
            
            threat_detected = False
            threat_types = []
            confidence_score = 0.0
            details = {}
            
            content_lower = content.lower()
            
            # Check keywords
            matched_keywords = []
            for keyword in self.keywords:
                if keyword.lower() in content_lower:
                    matched_keywords.append(keyword)
                    threat_detected = True
                    threat_types.append('keyword_match')
            
            # Check regex patterns
            matched_patterns = []
            for pattern_config in self.patterns:
                pattern = pattern_config.get('pattern', '')
                threat_type = pattern_config.get('type', 'pattern_match')
                try:
                    if re.search(pattern, content, re.IGNORECASE):
                        matched_patterns.append(pattern)
                        threat_detected = True
                        if threat_type not in threat_types:
                            threat_types.append(threat_type)
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            
            if threat_detected:
                confidence_score = min(1.0, (len(matched_keywords) + len(matched_patterns)) * 0.3)
            
            details = {
                'matched_keywords': matched_keywords,
                'matched_patterns': matched_patterns
            }
            
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=threat_detected,
                threat_types=threat_types,
                confidence_score=confidence_score,
                details=details,
                processing_time=time.time() - start_time
            )
        
        except Exception as e:
            logger.error(f"Custom rule-based analysis failed: {str(e)}")
            return ThreatAnalysisResult(
                provider=self.name,
                threat_detected=False,
                threat_types=[],
                confidence_score=0.0,
                details={},
                processing_time=time.time() - start_time,
                error=str(e)
            )


class ThreatResultAggregator:
    """Aggregates results from multiple threat detection providers."""
    
    def __init__(self, config: Dict):
        self.aggregation_rule = AggregationRule(config.get('aggregation_rule', 'any_block'))
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
    
    def aggregate(self, results: List[ThreatAnalysisResult]) -> AggregatedThreatResult:
        """Aggregate multiple threat analysis results."""
        start_time = time.time()
        
        # Filter out results with errors
        valid_results = [r for r in results if r.error is None]
        
        if not valid_results:
            return AggregatedThreatResult(
                individual_results=results,
                consensus_threat_detected=False,
                highest_confidence=0.0,
                threat_types=set(),
                recommended_action='allow',
                processing_time=time.time() - start_time,
                providers_used=[]
            )
        
        # Calculate aggregated metrics
        threats_detected = [r.threat_detected for r in valid_results]
        confidence_scores = [r.confidence_score for r in valid_results]
        all_threat_types = set()
        
        for result in valid_results:
            all_threat_types.update(result.threat_types)
        
        highest_confidence = max(confidence_scores) if confidence_scores else 0.0
        providers_used = [r.provider for r in valid_results]
        
        # Determine consensus threat detection
        consensus_threat_detected = self._determine_consensus(threats_detected, confidence_scores)
        
        # Determine recommended action
        recommended_action = self._determine_action(consensus_threat_detected, valid_results)
        
        return AggregatedThreatResult(
            individual_results=results,
            consensus_threat_detected=consensus_threat_detected,
            highest_confidence=highest_confidence,
            threat_types=all_threat_types,
            recommended_action=recommended_action,
            processing_time=time.time() - start_time,
            providers_used=providers_used
        )
    
    def _determine_consensus(self, threats_detected: List[bool], confidence_scores: List[float]) -> bool:
        """Determine consensus based on aggregation rule."""
        if not threats_detected:
            return False
        
        threat_count = sum(threats_detected)
        total_providers = len(threats_detected)
        max_confidence = max(confidence_scores) if confidence_scores else 0.0
        
        if self.aggregation_rule == AggregationRule.ANY_BLOCK:
            return threat_count > 0
        elif self.aggregation_rule == AggregationRule.MAJORITY_BLOCK:
            return threat_count > total_providers / 2
        elif self.aggregation_rule == AggregationRule.CONSENSUS_BLOCK:
            return threat_count == total_providers
        elif self.aggregation_rule == AggregationRule.THRESHOLD_BLOCK:
            return max_confidence >= self.confidence_threshold
        
        return False
    
    def _determine_action(self, consensus_threat_detected: bool, results: List[ThreatAnalysisResult]) -> str:
        """Determine recommended action based on results and provider modes."""
        if not consensus_threat_detected:
            return 'allow'
        
        # Check if any provider that detected a threat is in block mode
        for result in results:
            if result.threat_detected:
                # We need to check the provider's mode, but we don't have direct access here
                # This will be handled by the ThreatDetectionService
                pass
        
        return 'monitor'  # Default to monitor if threats detected


class ThreatDetectionConfig:
    """Configuration manager for threat detection system."""
    
    def __init__(self):
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from environment variables and config files."""
        config = {
            'enabled': os.getenv('THREAT_DETECTION_ENABLED', 'false').lower() == 'true',
            'mode': os.getenv('THREAT_DETECTION_MODE', 'monitor'),
            'parallel': os.getenv('THREAT_DETECTION_PARALLEL', 'true').lower() == 'true',
            'timeout': int(os.getenv('THREAT_DETECTION_TIMEOUT', '5')),
            'aggregation_rule': os.getenv('THREAT_DETECTION_AGGREGATION_RULE', 'any_block'),
            'confidence_threshold': float(os.getenv('THREAT_DETECTION_CONFIDENCE_THRESHOLD', '0.7')),
            'providers': {
                'google_model_armor': {
                    'enabled': os.getenv('GOOGLE_MODEL_ARMOR_ENABLED', 'false').lower() == 'true',
                    'project_id': os.getenv('GOOGLE_MODEL_ARMOR_PROJECT_ID'),
                    'location': os.getenv('GOOGLE_MODEL_ARMOR_LOCATION', 'us-central1'),
                    'template_id': os.getenv('GOOGLE_MODEL_ARMOR_TEMPLATE_ID', 'default'),
                    'service_account_path': os.getenv('GOOGLE_MODEL_ARMOR_SERVICE_ACCOUNT_PATH'),
                    'mode': os.getenv('GOOGLE_MODEL_ARMOR_MODE', 'monitor')
                },
                'azure_content_safety': {
                    'enabled': os.getenv('AZURE_CONTENT_SAFETY_ENABLED', 'false').lower() == 'true',
                    'api_key': os.getenv('AZURE_CONTENT_SAFETY_KEY'),
                    'endpoint': os.getenv('AZURE_CONTENT_SAFETY_ENDPOINT'),
                    'mode': os.getenv('AZURE_CONTENT_SAFETY_MODE', 'monitor')
                },
                'openai_moderation': {
                    'enabled': os.getenv('OPENAI_MODERATION_ENABLED', 'false').lower() == 'true',
                    'api_key': os.getenv('OPENAI_MODERATION_KEY'),
                    'endpoint': os.getenv('OPENAI_MODERATION_ENDPOINT'),
                    'mode': os.getenv('OPENAI_MODERATION_MODE', 'monitor')
                },
                'custom_rule_based': {
                    'enabled': os.getenv('CUSTOM_RULES_ENABLED', 'false').lower() == 'true',
                    'mode': os.getenv('CUSTOM_RULES_MODE', 'monitor'),
                    'keywords': self._load_custom_keywords(),
                    'patterns': self._load_custom_patterns()
                }
            }
        }
        
        return config
    
    def _load_custom_keywords(self) -> List[str]:
        """Load custom keywords from environment or config file."""
        keywords_str = os.getenv('CUSTOM_THREAT_KEYWORDS', '')
        if keywords_str:
            return [k.strip() for k in keywords_str.split(',') if k.strip()]
        
        # Try to load from file
        try:
            with open('threat_keywords.txt', 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return []
    
    def _load_custom_patterns(self) -> List[Dict]:
        """Load custom regex patterns from environment or config file."""
        try:
            with open('threat_patterns.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return []
    
    def is_enabled(self) -> bool:
        return self.config['enabled']
    
    def get_provider_config(self, provider_name: str) -> Dict:
        return self.config['providers'].get(provider_name, {})
    
    def get_global_config(self) -> Dict:
        return {k: v for k, v in self.config.items() if k != 'providers'}


class ThreatDetectionService:
    """Main service for coordinating threat detection across multiple providers."""
    
    def __init__(self):
        self.config = ThreatDetectionConfig()
        self.providers = self._initialize_providers()
        self.aggregator = ThreatResultAggregator(self.config.get_global_config())
        self.cache = {}  # Simple in-memory cache
    
    def _initialize_providers(self) -> List[ThreatDetectionProvider]:
        """Initialize all configured threat detection providers."""
        providers = []
        
        # Google Model Armor
        google_config = self.config.get_provider_config('google_model_armor')
        if google_config.get('enabled'):
            providers.append(GoogleModelArmorProvider(google_config))
        
        # Azure Content Safety
        azure_config = self.config.get_provider_config('azure_content_safety')
        if azure_config.get('enabled'):
            providers.append(AzureContentSafetyProvider(azure_config))
        
        # OpenAI Moderation
        openai_config = self.config.get_provider_config('openai_moderation')
        if openai_config.get('enabled'):
            providers.append(OpenAIModerationProvider(openai_config))
        
        # Custom Rule-Based
        custom_config = self.config.get_provider_config('custom_rule_based')
        if custom_config.get('enabled'):
            providers.append(CustomRuleBasedProvider(custom_config))
        
        # Filter to only available providers
        available_providers = [p for p in providers if p.is_available()]
        
        logger.info(f"Initialized {len(available_providers)} threat detection providers: "
                   f"{[p.get_provider_name() for p in available_providers]}")
        
        return available_providers
    
    def is_enabled(self) -> bool:
        """Check if threat detection is enabled and has available providers."""
        return self.config.is_enabled() and len(self.providers) > 0
    
    async def analyze_prompt(self, prompt: str, context: Optional[Dict] = None) -> AggregatedThreatResult:
        """Analyze a prompt for threats using all configured providers."""
        if not self.is_enabled():
            return self._create_disabled_result()
        
        context = context or {}
        
        # Check cache
        cache_key = self._get_cache_key(prompt, 'prompt')
        if cache_key in self.cache:
            logger.debug(f"Using cached threat analysis for prompt")
            return self.cache[cache_key]
        
        # Run analysis
        results = await self._run_providers('prompt', prompt, context)
        aggregated = self.aggregator.aggregate(results)
        
        # Cache result
        self.cache[cache_key] = aggregated
        
        # Log result
        self._log_analysis_result('prompt', prompt, aggregated)
        
        return aggregated
    
    async def analyze_response(self, response: str, context: Optional[Dict] = None) -> AggregatedThreatResult:
        """Analyze a model response for threats using all configured providers."""
        if not self.is_enabled():
            return self._create_disabled_result()
        
        context = context or {}
        
        # Check cache
        cache_key = self._get_cache_key(response, 'response')
        if cache_key in self.cache:
            logger.debug(f"Using cached threat analysis for response")
            return self.cache[cache_key]
        
        # Run analysis
        results = await self._run_providers('response', response, context)
        aggregated = self.aggregator.aggregate(results)
        
        # Cache result
        self.cache[cache_key] = aggregated
        
        # Log result
        self._log_analysis_result('response', response, aggregated)
        
        return aggregated
    
    async def _run_providers(self, analysis_type: str, content: str, context: Dict) -> List[ThreatAnalysisResult]:
        """Run threat analysis across all providers."""
        if self.config.config.get('parallel', True):
            # Run providers in parallel
            tasks = []
            for provider in self.providers:
                if analysis_type == 'prompt':
                    task = provider.analyze_prompt(content, context)
                else:
                    task = provider.analyze_response(content, context)
                tasks.append(task)
            
            timeout = self.config.config.get('timeout', 5)
            try:
                results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout)
                
                # Handle exceptions
                final_results = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Provider {self.providers[i].get_provider_name()} failed: {result}")
                        final_results.append(ThreatAnalysisResult(
                            provider=self.providers[i].get_provider_name(),
                            threat_detected=False,
                            threat_types=[],
                            confidence_score=0.0,
                            details={},
                            processing_time=0.0,
                            error=str(result)
                        ))
                    else:
                        final_results.append(result)
                
                return final_results
            
            except asyncio.TimeoutError:
                logger.warning(f"Threat detection timed out after {timeout} seconds")
                return [ThreatAnalysisResult(
                    provider=p.get_provider_name(),
                    threat_detected=False,
                    threat_types=[],
                    confidence_score=0.0,
                    details={},
                    processing_time=timeout,
                    error="Timeout"
                ) for p in self.providers]
        
        else:
            # Run providers sequentially
            results = []
            for provider in self.providers:
                try:
                    if analysis_type == 'prompt':
                        result = await provider.analyze_prompt(content, context)
                    else:
                        result = await provider.analyze_response(content, context)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Provider {provider.get_provider_name()} failed: {e}")
                    results.append(ThreatAnalysisResult(
                        provider=provider.get_provider_name(),
                        threat_detected=False,
                        threat_types=[],
                        confidence_score=0.0,
                        details={},
                        processing_time=0.0,
                        error=str(e)
                    ))
            
            return results
    
    def should_block(self, analysis: AggregatedThreatResult) -> bool:
        """Determine if execution should be blocked based on analysis results."""
        if not analysis.consensus_threat_detected:
            return False
        
        # Check if any provider that detected a threat is in block mode
        for result in analysis.individual_results:
            if result.threat_detected and result.error is None:
                provider = next((p for p in self.providers if p.get_provider_name() == result.provider), None)
                if provider and provider.should_block_on_threat():
                    return True
        
        return False
    
    def _create_disabled_result(self) -> AggregatedThreatResult:
        """Create a result for when threat detection is disabled."""
        return AggregatedThreatResult(
            individual_results=[],
            consensus_threat_detected=False,
            highest_confidence=0.0,
            threat_types=set(),
            recommended_action='allow',
            processing_time=0.0,
            providers_used=[]
        )
    
    def _get_cache_key(self, content: str, content_type: str) -> str:
        """Generate a cache key for the content."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        return f"{content_type}:{content_hash}"
    
    def _log_analysis_result(self, analysis_type: str, content: str, result: AggregatedThreatResult):
        """Log the threat analysis result."""
        content_preview = content[:100] + "..." if len(content) > 100 else content
        
        if result.consensus_threat_detected:
            logger.warning(f"Threat detected in {analysis_type}: {result.threat_types} "
                          f"(confidence: {result.highest_confidence:.2f}) "
                          f"- Content preview: {content_preview}")
        else:
            logger.debug(f"No threats detected in {analysis_type} "
                        f"- Content preview: {content_preview}")
        
        # Add to trace if available
        try:
            from status import status
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Convert result to dict for tracing
            result_dict = {
                'providers_used': result.providers_used,
                'consensus_threat_detected': result.consensus_threat_detected,
                'threat_types': result.threat_types,
                'highest_confidence': result.highest_confidence,
                'recommended_action': result.recommended_action,
                'processing_time': result.processing_time,
                'individual_results': [
                    {
                        'provider': r.provider,
                        'threat_detected': r.threat_detected,
                        'confidence_score': r.confidence_score,
                        'threat_types': r.threat_types,
                        'processing_time': r.processing_time,
                        'error': r.error
                    }
                    for r in result.individual_results
                ]
            }
            
            status.trace_threat_detection(analysis_type, content_hash, result_dict)
        except ImportError:
            # Status module not available, skip tracing
            pass
        except Exception as e:
            logger.debug(f"Failed to trace threat detection result: {e}")


# Global instance for easy access
threat_detection_service = ThreatDetectionService()
