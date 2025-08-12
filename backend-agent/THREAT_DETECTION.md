# Threat Detection System

The STARS backend-agent now includes a comprehensive multi-provider threat detection system that analyzes prompts and model responses for potential security threats before and after LLM interactions.

## Overview

The threat detection system provides:
- **Multi-provider support**: Google Model Armor, Azure Content Safety, OpenAI Moderation, and custom rule-based detection
- **Flexible configuration**: Monitor-only or blocking modes per provider
- **Async processing**: Non-blocking threat analysis with configurable timeouts
- **Comprehensive logging**: Full tracing and audit trails
- **Caching**: Efficient caching to avoid redundant analyses

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   LLM Request   │───▶│ Threat Detection │───▶│  LLM Execution  │
│                 │    │   (Pre-analysis) │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐             │
│ Final Response  │◀───│ Threat Detection │◀────────────┘
│                 │    │ (Post-analysis)  │
└─────────────────┘    └──────────────────┘
```

## Supported Providers

### 1. Google Model Armor
Advanced AI safety detection service from Google Cloud Security Command Center.
- **Authentication**: Google Cloud Service Account or Application Default Credentials
- **API**: Google Cloud Security Command Center client library
- **Features**: Comprehensive threat detection with confidence scores
- **Requirements**: Google Cloud project with Security Command Center enabled

### 2. Azure Content Safety
Microsoft's content moderation service.
- **Endpoint**: `https://{resource}.cognitiveservices.azure.com/contentsafety/text:analyze`
- **Authentication**: Subscription key
- **Features**: Category-based threat detection with severity levels

### 3. OpenAI Moderation
OpenAI's built-in content moderation API.
- **Endpoint**: `https://api.openai.com/v1/moderations`
- **Authentication**: API key
- **Features**: Multiple threat categories with confidence scores

### 4. Custom Rule-Based Detection
Local pattern matching using keywords and regex.
- **Configuration**: `threat_keywords.txt` and `threat_patterns.json`
- **Features**: Fast local detection, fully customizable rules

## Configuration

### Environment Variables

Copy `.env.threat_detection.example` to your `.env` file and configure:

```bash
# Enable threat detection
THREAT_DETECTION_ENABLED=true

# Global settings
THREAT_DETECTION_MODE=monitor
THREAT_DETECTION_PARALLEL=true
THREAT_DETECTION_TIMEOUT=5
THREAT_DETECTION_AGGREGATION_RULE=any_block
THREAT_DETECTION_CONFIDENCE_THRESHOLD=0.7

# Provider configurations
GOOGLE_MODEL_ARMOR_ENABLED=true
GOOGLE_MODEL_ARMOR_PROJECT_ID=your-gcp-project-id
GOOGLE_MODEL_ARMOR_LOCATION=global
GOOGLE_MODEL_ARMOR_SERVICE_ACCOUNT_PATH=/path/to/service-account-key.json
GOOGLE_MODEL_ARMOR_MODE=monitor

AZURE_CONTENT_SAFETY_ENABLED=true
AZURE_CONTENT_SAFETY_KEY=your_subscription_key
AZURE_CONTENT_SAFETY_MODE=block

OPENAI_MODERATION_ENABLED=true
OPENAI_MODERATION_KEY=your_openai_key
OPENAI_MODERATION_MODE=monitor

CUSTOM_RULES_ENABLED=true
CUSTOM_RULES_MODE=monitor
```

### Configuration Options

#### Global Settings
- **THREAT_DETECTION_ENABLED**: Enable/disable entire system
- **THREAT_DETECTION_MODE**: Default mode for all providers
- **THREAT_DETECTION_PARALLEL**: Run providers concurrently (recommended)
- **THREAT_DETECTION_TIMEOUT**: Maximum time to wait for analysis
- **THREAT_DETECTION_AGGREGATION_RULE**: How to combine multiple provider results
- **THREAT_DETECTION_CONFIDENCE_THRESHOLD**: Threshold for confidence-based blocking

#### Provider Modes
- **monitor**: Log threats but allow execution
- **block**: Block execution when threats are detected
- **disabled**: Skip this provider entirely

#### Aggregation Rules
- **any_block**: Block if ANY provider detects a threat
- **majority_block**: Block if MAJORITY of providers detect threats
- **consensus_block**: Block only if ALL providers agree on threat
- **threshold_block**: Block if confidence score exceeds threshold

## Custom Rules Configuration

### Keywords (`threat_keywords.txt`)
Add one keyword per line. Lines starting with `#` are comments.

```
# Prompt injection attempts
ignore previous instructions
system prompt
jailbreak
bypass
```

### Regex Patterns (`threat_patterns.json`)
Define complex patterns with threat types:

```json
[
  {
    "pattern": "(?i)ignore\\s+(?:all\\s+)?(?:previous|prior)\\s+(?:instructions?|prompts?|commands?)",
    "type": "prompt_injection",
    "description": "Attempts to ignore previous instructions"
  }
]
```

## Usage Examples

### Basic Setup
1. Install dependencies: `pip install aiohttp`
2. Copy configuration: `cp .env.threat_detection.example .env`
3. Configure at least one provider
4. Enable threat detection: `THREAT_DETECTION_ENABLED=true`

### Monitor Mode (Recommended for Testing)
```bash
THREAT_DETECTION_ENABLED=true
THREAT_DETECTION_MODE=monitor
OPENAI_MODERATION_ENABLED=true
OPENAI_MODERATION_KEY=your_key
OPENAI_MODERATION_MODE=monitor
```

### Production Blocking Setup
```bash
THREAT_DETECTION_ENABLED=true
THREAT_DETECTION_AGGREGATION_RULE=majority_block
GOOGLE_MODEL_ARMOR_ENABLED=true
GOOGLE_MODEL_ARMOR_MODE=block
AZURE_CONTENT_SAFETY_ENABLED=true
AZURE_CONTENT_SAFETY_MODE=block
OPENAI_MODERATION_ENABLED=true
OPENAI_MODERATION_MODE=monitor
```

## Integration Points

The threat detection system is integrated at the LLM layer (`llm.py`):

1. **Pre-analysis**: Before sending prompts to LLMs
2. **Post-analysis**: After receiving responses from LLMs
3. **Tracing**: All analyses are logged in trace files
4. **Caching**: Results are cached to improve performance

## Monitoring and Logging

### Trace Files
All threat detection activities are logged in trace files under the `traces/` directory:

```json
{
  "threat_detections": [
    {
      "type": "prompt",
      "content_hash": "sha256_hash",
      "timestamp": "2025-01-10T19:15:00Z",
      "providers_used": ["openai_moderation", "custom_rule_based"],
      "threats_detected": true,
      "threat_types": ["prompt_injection"],
      "highest_confidence": 0.85,
      "recommended_action": "block",
      "individual_results": [...]
    }
  ]
}
```

### Log Levels
- **DEBUG**: No threats detected
- **WARNING**: Threats detected
- **ERROR**: Provider failures or configuration issues

## Performance Considerations

### Caching
- Results are cached based on content hash
- Cache is in-memory and resets on restart
- Identical prompts/responses use cached results

### Async Processing
- All providers run concurrently by default
- Configurable timeout prevents hanging
- Graceful degradation on provider failures

### Network Optimization
- Connection pooling for HTTP requests
- Configurable timeouts
- Retry logic for transient failures

## Security Considerations

### Privacy
- Content hashes (not full content) are logged in traces
- API keys are never logged
- Sensitive data is not cached permanently

### Reliability
- System continues to function if threat detection fails
- Multiple providers provide redundancy
- Configurable fallback behavior

## Troubleshooting

### Common Issues

1. **No providers available**
   - Check API keys are configured
   - Verify network connectivity
   - Check provider-specific endpoints

2. **Slow performance**
   - Reduce timeout values
   - Enable parallel processing
   - Check network latency to providers

3. **False positives**
   - Adjust confidence thresholds
   - Use majority_block aggregation rule
   - Fine-tune custom rules

4. **Missing dependencies**
   - Install: `pip install aiohttp`
   - Check requirements.txt is up to date

### Debug Mode
Enable debug logging to see detailed threat detection activity:

```python
import logging
logging.getLogger('threat_detection').setLevel(logging.DEBUG)
```

## API Reference

### ThreatDetectionService
Main service class for threat detection.

```python
from threat_detection import threat_detection_service

# Analyze a prompt
result = await threat_detection_service.analyze_prompt(
    prompt="Your prompt here",
    context={"model_name": "gpt-4"}
)

# Check if should block
should_block = threat_detection_service.should_block(result)
```

### Configuration Classes
- `ThreatDetectionConfig`: Manages configuration loading
- `ThreatDetectionProvider`: Base class for providers
- `ThreatAnalysisResult`: Individual provider result
- `AggregatedThreatResult`: Combined result from all providers

## Contributing

### Adding New Providers
1. Inherit from `ThreatDetectionProvider`
2. Implement required methods
3. Add configuration support
4. Update documentation

### Custom Rules
- Add keywords to `threat_keywords.txt`
- Add regex patterns to `threat_patterns.json`
- Test thoroughly before production use

## License

This threat detection system is part of the STARS project and follows the same licensing terms.
