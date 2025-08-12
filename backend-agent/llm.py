from typing import Any, Dict, List
import abc
import asyncio
import logging
import os

from gen_ai_hub.proxy.core.proxy_clients import get_proxy_client
from gen_ai_hub.proxy.core.proxy_clients import set_proxy_version
from gen_ai_hub.proxy.native.openai import OpenAI as ProxyOpenAI
from gen_ai_hub.proxy.native.google_vertexai.clients import GenerativeModel
from gen_ai_hub.proxy.native.amazon.clients import Session
from openai import OpenAI as OfficialOpenAI
from openai import InternalServerError
import httpx
import ollama

from llm_response import Error, Filtered, LLMResponse, Success
from status import status

# Import threat detection system
try:
    from threat_detection import threat_detection_service
    THREAT_DETECTION_AVAILABLE = True
except ImportError:
    THREAT_DETECTION_AVAILABLE = False
    logger.warning("Threat detection system not available. Install required dependencies to enable threat detection.")

set_proxy_version('gen-ai-hub')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(status.trace_logging)

AICORE_MODELS = {
    'aicore-ibm':
    [
        'ibm--granite-13b-chat'
    ],
    'aicore-mistralai':
    [
        'mistralai--mistral-large-instruct',
        'mistralai--mistral-small-instruct',
    ],
    'aicore-opensource':
    [
        'meta--llama3.1-70b-instruct',
    ],
    'aws-bedrock':
    [
        'amazon--titan-text-lite',
        'amazon--titan-text-express',
        'amazon--nova-pro',
        'amazon--nova-lite',
        'amazon--nova-micro',
        'anthropic--claude-3-haiku',
        'anthropic--claude-3-sonnet',
        'anthropic--claude-3-opus',
        'anthropic--claude-3.5-sonnet',
        'anthropic--claude-3.7-sonnet',
    ],
    'azure-openai':
    [
        'gpt-4',
        'gpt-4o',
        'gpt-4o-mini',
        'gpt-4.1',
        'gpt-4.1-mini',
        'gpt-4.1-nano',
        # 'o1',
        # 'o3',
        # 'o3-mini',
        # 'o4-mini',
    ],
    'gcp-vertexai':
    [
        'gemini-1.5-pro',
        'gemini-1.5-flash',
        'gemini-2.0-flash',
        'gemini-2.0-flash-lite',
    ],
}


class LLM(abc.ABC):
    """
    This is the abstract class used to create and access LLMs for pentesting.
    """

    _supported_models = []

    @classmethod
    def from_model_name(cls, model_name: str) -> 'LLM':
        """
        Create a specific LLM object from the name of the model.
        Useful because the user can specify only the name in the agent.
        """
        # Foundation-models scenarios in AI Core
        if model_name in AICORE_MODELS['azure-openai']:
            # The agent sometimes autocorrects gpt-35-turbo to gpt-3.5-turbo,
            # so we handle this behavior here.
            if model_name == 'gpt-3.5-turbo':
                model_name = 'gpt-35-turbo'
            return AICoreOpenAILLM(model_name)
        if model_name in AICORE_MODELS['aicore-ibm']:
            # IBM models are compatible with OpenAI completion API
            return AICoreOpenAILLM(model_name)
        if model_name in AICORE_MODELS['aicore-opensource']:
            return AICoreOpenAILLM(model_name, False)
        if model_name in AICORE_MODELS['aicore-mistralai']:
            return AICoreOpenAILLM(model_name, False)
        if model_name in AICORE_MODELS['aws-bedrock']:
            if 'titan' in model_name:
                # Titan models don't support system prompts
                return AICoreAmazonBedrockLLM(model_name, False)
            else:
                return AICoreAmazonBedrockLLM(model_name)
        if model_name in AICORE_MODELS['gcp-vertexai']:
            return AICoreGoogleVertexLLM(model_name)

        # Custom models
        if model_name == 'mistral':
            return LocalOpenAILLM(
                os.getenv('MISTRAL_MODEL_NAME', ''),
                api_key=os.getenv('MISTRAL_KEY', ''),
                base_url=os.getenv('MISTRAL_URL', ''),
                supports_openai_style_system_messages=False)

        # If a model is not found, as a last resource, it is looked up in a
        # possible local ollama instance. If it not even served there, then an
        # exception is raised because such model has either an incorrect name
        # or it has not been deployed.
        ollama_host = os.getenv('OLLAMA_HOST')
        ollama_port = os.getenv('OLLAMA_PORT', 11434)
        try:
            if ollama_host:
                # The model is served in a remote ollama instance
                remote_ollama_host = f'{ollama_host}:{ollama_port}'
                return OllamaLLM(model_name, remote_ollama_host)
            else:
                # The model is served in a local ollama instance
                ollama.show(model_name)
                return OllamaLLM(model_name)
        except (ConnectionError, ollama.ResponseError, httpx.ConnectError):
            raise ValueError(f'Model {model_name} not found')

    @classmethod
    def _calculate_list_of_supported_models(self) -> list[str]:
        """
        Get the list of supported models using AI Core, local Mistral and
        Ollama. Gathering deployments from AI Core takes a while, so the result
        of this method are cached.
        """
        client = get_proxy_client()
        models = [d.model_name for d in client.deployments]
        if os.getenv('MISTRAL_URL'):
            models.append('mistral')
        try:
            ollama_models = []
            ollama_host = os.getenv('OLLAMA_HOST')
            ollama_port = os.getenv('OLLAMA_PORT', 11434)
            if ollama_host:
                # The model is served in a remote ollama instance
                remote_ollama_host = f'{ollama_host}:{ollama_port}'
                ollama_models = [m['model'] for m in
                                 ollama.Client(remote_ollama_host).list()
                                 ['models']]
            else:
                ollama_models = [m['name'] for m in ollama.list()['models']]
            return models + ollama_models
        except (ConnectionError, ollama.ResponseError, httpx.ConnectError):
            return models

    @classmethod
    def get_supported_models(self) -> list[str]:
        """
        Return the list of supported models that can be instantiated.
        """
        if len(LLM._supported_models) == 0:
            logger.info('Getting list of supported models')
            LLM._supported_models = LLM._calculate_list_of_supported_models()
            logger.info(f'{len(LLM._supported_models)} models available')
        return LLM._supported_models

    @abc.abstractmethod
    def generate(self,
                 system_prompt: str,
                 prompt: str,
                 temperature: float,
                 max_tokens: int,
                 n: int) -> LLMResponse:
        """
        Generate completions using the LLM for a single message.
        Implementation is responsibility of subclasses.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def generate_completions_for_messages(
            self,
            messages: list,
            temperature: float,
            max_tokens: int,
            top_p: int = 1,
            frequency_penalty: float = 0.5,
            presence_penalty: float = 0.5,
            n: int = 1) -> LLMResponse:
        """
        Generate completions using the LLM for a list of messages
        in OpenAI-API style (dictionaries with keys role and content).

        n determines the number of different responses/ trials to generate.

        Other parameters will be directly passed to the client.

        Implementation is responsibility of subclasses.
        """
        raise NotImplementedError

    def _trace_llm_call(self, prompt, response):
        status.trace_llm(
            str(self),
            prompt,
            response
        )
        # Return response as convenience so that this method can be used
        # transparently for the return value.
        return response

    async def _analyze_prompt_threats(self, messages: list) -> tuple[bool, str]:
        """
        Analyze prompt messages for threats using the threat detection system.
        Returns (should_block, reason) tuple.
        """
        if not THREAT_DETECTION_AVAILABLE or not threat_detection_service.is_enabled():
            return False, ""
        
        try:
            # Convert messages to a single string for analysis
            prompt_text = self._messages_to_text(messages)
            context = {
                'model_name': getattr(self, 'model_name', 'unknown'),
                'model_type': str(self),
                'analysis_type': 'prompt'
            }
            
            # Run threat analysis
            analysis_result = await threat_detection_service.analyze_prompt(prompt_text, context)
            
            # Check if we should block
            should_block = threat_detection_service.should_block(analysis_result)
            
            if should_block:
                threat_summary = f"Threats detected: {list(analysis_result.threat_types)} " \
                               f"(confidence: {analysis_result.highest_confidence:.2f})"
                return True, threat_summary
            
            return False, ""
            
        except Exception as e:
            logger.error(f"Threat detection failed for prompt: {e}")
            return False, ""

    async def _analyze_response_threats(self, response_text: str) -> tuple[bool, str]:
        """
        Analyze model response for threats using the threat detection system.
        Returns (should_block, reason) tuple.
        """
        if not THREAT_DETECTION_AVAILABLE or not threat_detection_service.is_enabled():
            return False, ""
        
        try:
            context = {
                'model_name': getattr(self, 'model_name', 'unknown'),
                'model_type': str(self),
                'analysis_type': 'response'
            }
            
            # Run threat analysis
            analysis_result = await threat_detection_service.analyze_response(response_text, context)
            
            # Check if we should block
            should_block = threat_detection_service.should_block(analysis_result)
            
            if should_block:
                threat_summary = f"Threats detected: {list(analysis_result.threat_types)} " \
                               f"(confidence: {analysis_result.highest_confidence:.2f})"
                return True, threat_summary
            
            return False, ""
            
        except Exception as e:
            logger.error(f"Threat detection failed for response: {e}")
            return False, ""

    def _messages_to_text(self, messages: list) -> str:
        """Convert message list to a single text string for threat analysis."""
        if isinstance(messages, str):
            return messages
        
        text_parts = []
        for message in messages:
            if isinstance(message, dict):
                role = message.get('role', '')
                content = message.get('content', '')
                if role and content:
                    text_parts.append(f"{role}: {content}")
                elif content:
                    text_parts.append(content)
            else:
                text_parts.append(str(message))
        
        return "\n".join(text_parts)

    def _run_with_threat_detection(self, messages: list, llm_call_func):
        """
        Wrapper to run LLM calls with threat detection.
        This handles the async threat detection in a sync context.
        """
        # Check prompt threats
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        should_block_prompt, prompt_reason = loop.run_until_complete(
            self._analyze_prompt_threats(messages)
        )
        
        if should_block_prompt:
            logger.warning(f"Prompt blocked by threat detection: {prompt_reason}")
            return self._trace_llm_call(messages, Filtered(f"Prompt blocked by threat detection: {prompt_reason}"))
        
        # Execute the actual LLM call
        response = llm_call_func()
        
        # If the response is successful, check response threats
        if isinstance(response, Success) and response.text:
            # Analyze the first response (or all responses concatenated)
            response_text = response.text[0] if response.text else ""
            should_block_response, response_reason = loop.run_until_complete(
                self._analyze_response_threats(response_text)
            )
            
            if should_block_response:
                logger.warning(f"Response blocked by threat detection: {response_reason}")
                return self._trace_llm_call(messages, Filtered(f"Response blocked by threat detection: {response_reason}"))
        
        return response


class AICoreOpenAILLM(LLM):
    """
    This class implements an interface to query LLMs using the Generative AI
    hub (AI Core) OpenAI proxy client.
    """

    def __init__(self,
                 model_name: str,
                 uses_system_prompt=True):
        self.model_name = model_name
        self.client = ProxyOpenAI()
        self.uses_system_prompt = uses_system_prompt

    def __str__(self) -> str:
        return f'{self.model_name}/OpenAI LLM via AI Core proxy'

    def generate(self,
                 system_prompt: str,
                 prompt: str,
                 temperature=0,
                 max_tokens=512,
                 n=1):
        if not system_prompt:
            messages = [
                {'role': 'user', 'content': prompt}
            ]
        else:
            if self.uses_system_prompt:
                messages = [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': prompt},
                ]
            else:
                # This path is specifically for the Mistral model, which
                # uses openai API for the most part, but does not
                # understand system prompts
                if not system_prompt:
                    system_prompt = ''
                messages = [
                    {'role': 'user',
                        'content': f'{system_prompt}{prompt}'},
                ]
        return self.generate_completions_for_messages(
            messages, temperature, max_tokens, n=n
        )

    def generate_completions_for_messages(self,
                                          messages: list,
                                          temperature: float,
                                          max_tokens: int,
                                          top_p: int = 1,
                                          frequency_penalty: float = 0.5,
                                          presence_penalty: float = 0.5,
                                          n: int = 1):
        
        def _execute_llm_call():
            try:
                if not self.uses_system_prompt:
                    if messages[0]['role'] == 'system':
                        system_message = messages.pop(0)
                        messages[0]['content'] = \
                            f'{system_message["content"]}{messages[0]["content"]}'
                response = self.client.chat.completions.create(
                    model_name=self.model_name,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    n=n,
                    top_p=top_p,
                    frequency_penalty=frequency_penalty,
                    presence_penalty=presence_penalty)
                responses = [response.choices[i].message.content for i in range(n)]
                return Success(responses)
            except InternalServerError as e:
                logger.error(f'A HTTP server-side error occurred while calling '
                             f'{self.model_name} model: {e}')
                if 'gpt' in self.model_name:
                    logger.error("The completion triggered OpenAI's firewall")
                    return Filtered(e)
                else:
                    return Error(e)
            except Exception as e:
                logger.error(f'An error occurred while calling the model: {e}')
                return Error(e)
        
        # Use threat detection wrapper
        return self._run_with_threat_detection(messages, _execute_llm_call)


class LocalOpenAILLM(AICoreOpenAILLM):
    """
    This class can be used for any OpenAI API-compatible model hosted
    locally (or on an inference server that is not from openai nor from SAP
    AI Core).
    Specifically, this class is used for a local Mistral instance.
    """

    def __init__(self,
                 model_name: str,
                 api_key: str = None,
                 base_url: str = None,
                 supports_openai_style_system_messages=True):
        self.client = OfficialOpenAI(api_key=api_key, base_url=base_url)
        self.model_name = model_name
        self.uses_system_prompt = \
            supports_openai_style_system_messages

    def generate_completions_for_messages(self,
                                          messages: list,
                                          temperature: float,
                                          max_tokens: int,
                                          top_p: int = 1,
                                          frequency_penalty: float = 0.5,
                                          presence_penalty: float = 0.5,
                                          n: int = 1):
        if not self.uses_system_prompt:
            if messages[0]['role'] == 'system':
                logger.debug(
                    f'{str(self)} was called with '
                    'wrong system message style.')
                system_message = messages.pop(0)
                messages[0]['content'] = \
                    f'{system_message["content"]}{messages[0]["content"]}'
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                n=n,
                top_p=top_p,
                frequency_penalty=frequency_penalty,
                presence_penalty=presence_penalty)
            responses = [
                response.choices[i].message.content for i in range(n)]
            return self._trace_llm_call(messages, Success(responses))
        except Exception as e:
            return self._trace_llm_call(messages, Error(str(e)))


class OllamaLLM(LLM):
    def __init__(self, model_name: str, host=None):
        self.model_name = model_name
        self.client = ollama.Client(host=host)

    def __str__(self) -> str:
        return f'{self.model_name}/Ollama LLM'

    def generate(self,
                 system_prompt: str,
                 prompt: str,
                 max_tokens: int = 4096,
                 temperature: float = 0.3,
                 n: int = 1,) -> list[str]:
        try:
            messages = [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt},
            ]
            generations = [
                self.client.generate(model=self.model_name,
                                     prompt=prompt,
                                     system=system_prompt,
                                     options={'temperature': temperature}
                                     )['response']
                for _ in range(n)]
            return self._trace_llm_call(messages, Success(generations))
        except Exception as e:
            return self._trace_llm_call(messages, Error(e))

    def generate_completions_for_messages(
            self,
            messages: list,
            temperature: float,
            max_tokens: int,
            top_p: int = 1,
            frequency_penalty: float = 0.5,
            presence_penalty: float = 0.5,
            n: int = 1) -> list[str]:
        try:
            generations = [
                self.client.chat(
                    self.model_name,
                    messages,
                    options={'temperature': temperature,
                             'top_p': top_p,
                             'frequency_penalty': frequency_penalty,
                             'presence_penalty': presence_penalty}
                )['message']['content']
                for _ in range(n)
            ]
            return self._trace_llm_call(messages, Success(generations))
        except Exception as e:
            return self._trace_llm_call(messages, Error(e))


class AICoreGoogleVertexLLM(LLM):

    def __init__(self, model_name: str):
        self.model_name = model_name
        proxy_client = get_proxy_client('gen-ai-hub')
        self.model = GenerativeModel(
            proxy_client=proxy_client,
            model_name=self.model_name
        )

    def __str__(self) -> str:
        return f'{self.model_name}/Google Vertex AI'

    def generate(self,
                 system_prompt: str,
                 prompt: str,
                 temperature: float = 1,
                 max_tokens: int = 1024,
                 n: int = 1) -> LLMResponse:
        contents = []
        if system_prompt:
            # System prompts are only supported at creation of the model.
            # Since we do not want to instantiate the model every time we
            # generate a response, we use a normal user prompt here.
            contents.append(
                {
                    'role': 'user',
                    'parts': [{
                        'text': system_prompt
                    }]
                }
            )
        contents.append(
            {
                'role': 'user',
                'parts': [{
                        'text': prompt
                }]
            }
        )
        try:
            responses = [self.model.generate_content(
                contents,
                generation_config={
                    'temperature': temperature,
                    'max_output_tokens': max_tokens
                }
            ).text for _ in range(n)]
            if not all(responses):
                return Filtered(
                    'One of the generations resulted in an empty response')
            return Success(responses)
        except ValueError as v:
            return Error(str(v))

    def generate_completions_for_messages(
            self,
            messages: list,
            temperature: float = 1,
            max_tokens: int = 1024,
            top_p: int = 1,
            frequency_penalty: float = 0.5,
            presence_penalty: float = 0.5,
            n: int = 1) -> LLMResponse:
        contents = []
        for message in messages:
            contents.append(
                {
                    'role': 'user',
                    'parts': [{'text': message['content']}]
                }
            )
        try:
            responses = [self.model.generate_content(
                contents,
                generation_config={
                    'temperature': temperature,
                    'max_output_tokens': max_tokens,
                    'top_p': top_p
                    # Frequency penalty and Presence penalty are not supported
                    # by the client.
                    # Even though it is supported in https://cloud.google.com/vertex-ai/docs/reference/rest/v1/GenerationConfig   # noqa: E501
                    # 'frequency_penalty': frequency_penalty,
                    # 'presence_penalty': presence_penalty,
                }).text for _ in range(n)]
            if not all(responses):
                return Filtered(
                    'One of the generations resulted in an empty response')
            return Success(responses)
        except ValueError as v:
            return Error(str(v))


class AICoreAmazonBedrockLLM(LLM):

    def __init__(self, model_name: str, uses_system_prompt: bool = True):
        self.model_name = model_name
        proxy_client = get_proxy_client('gen-ai-hub')
        self.model = Session().client(
            proxy_client=proxy_client,
            model_name=self.model_name
        )
        self.uses_system_prompt = uses_system_prompt

    def __str__(self) -> str:
        return f'{self.model_name}/Amazon Bedrock'

    def generate(self,
                 system_prompt: str,
                 prompt: str,
                 temperature: float = 1,
                 max_tokens: int = 1024,
                 n: int = 1) -> LLMResponse:

        # Declare types for messages and kwargs to avoid mypy errors
        messages: List[Dict[str, Any]] = []
        kwargs: Dict[str, Any] = {
            'inferenceConfig': {
                'temperature': temperature,
                'maxTokens': max_tokens
            }
        }
        if not system_prompt:
            messages.append(
                {'role': 'user', 'content': [{'text': prompt}]}
            )
        else:
            if self.uses_system_prompt:
                messages.append(
                    {'role': 'user', 'content': [{'text': prompt}]}
                )
                kwargs['system'] = [{'text': system_prompt}]
            else:
                # Similarly to the Mistral model, also among Bedrock models
                # there are some that do not support system prompt (e.g., titan
                # models).
                messages.append(
                    {'role': 'user',
                     'content': [{'text': f'{system_prompt}{prompt}'}]},
                )
        try:
            responses = [self.model.converse(
                messages=messages,
                **kwargs  # arguments supported by converse API
            )['output']['message']['content'][0]['text'] for _ in range(n)]
            if not all(responses):
                return Filtered(
                    'One of the generations resulted in an empty response')
            return Success(responses)
        except ValueError as v:
            return Error(str(v))

    def generate_completions_for_messages(
            self,
            messages: list,
            temperature: float = 1,
            max_tokens: int = 1024,
            top_p: int = 1,
            frequency_penalty: float = 0.5,
            presence_penalty: float = 0.5,
            n: int = 1) -> LLMResponse:
        contents = []
        # TODO: manage system prompt
        for message in messages:
            contents.append(
                {
                    'role': 'user',
                    'content': [{'text': message['content']}]
                }
            )
        try:
            responses = [self.model.converse(
                messages=contents,
                inferenceConfig={
                    'temperature': temperature,
                    'maxTokens': max_tokens,
                    'topP': top_p
                    # Frequency penalty and Presence penalty are not supported
                    # by Amazon.
                    # 'frequency_penalty': frequency_penalty,
                    # 'presence_penalty': presence_penalty,
                })['output']['message']['content'][0]['text']
                for _ in range(n)]
            if not all(responses):
                return Filtered(
                    'One of the generations resulted in an empty response')
            return Success(responses)
        except ValueError as v:
            return Error(str(v))
