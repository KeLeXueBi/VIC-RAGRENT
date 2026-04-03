import time
from typing import Optional
from loguru import logger

from openai import OpenAI
from openai.resources.chat.completions import messages
from openai.types.chat import ChatCompletionUserMessageParam
from models.impl.session_model import SessionModel

from utils.config_helper import default_config


class LLMQueryClient:
    """
    A lightweight wrapper around different LLM providers.

    This class abstracts away provider-specific configuration (DeepSeek, OpenRouter, Qwen)
    and exposes a unified `query` interface for the rest of the system.
    """
    _llm: str
    _client: OpenAI

    def __init__(self, llm_type: str = 'deepseek') -> None:
        self._llm = llm_type
        self._init_client()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # No persistent connection to close, but the context manager is kept
        # for consistency with other components.
        ...

    def _init_client(self):
        """
        Initialize the underlying OpenAI-compatible client based on the selected LLM.
        """
        config = default_config.config
        if self._llm == 'deepseek':
            ds_config = config.get('deepseek')
            api_key = ds_config.get('api-key')
            base_url = ds_config.get('api-url')
            if not api_key or not base_url:
                raise Exception('Please set DeepSeek API key and base URL in config.yaml')
            self._client = OpenAI(api_key=api_key, base_url=base_url)
        elif self._llm == 'gpt-4o-mini':
            openrouter_config = config.get('openrouter')
            api_key = openrouter_config.get('api-key')
            base_url = openrouter_config.get('api-url')
            if not api_key or not base_url:
                raise Exception('Please set OpenRouter API key and base URL in config.yaml')
            self._client = OpenAI(api_key=api_key, base_url=base_url)
        elif self._llm == 'Qwen':
            qwen_config = config.get('Qwen')
            api_key = qwen_config.get('api-key')
            base_url = qwen_config.get('api-url')
            if not api_key or not base_url:
                raise Exception('Please set Qwen API key and base URL in config.yaml')
            self._client = OpenAI(api_key=api_key, base_url=base_url)
        else:
            raise Exception(f'LLM type {self._llm} not supported')

    @property
    def client(self):
        """
        Lazily initialize and return the LLM client.
        """
        if not self._client:
            self._init_client()
        return self._client

    async def query(self, session: SessionModel, prompt: str, agent: str, temperature: float, donot_output_json: bool = False) -> Optional[str]:
        """
        Send a prompt to the selected LLM and return the generated response.

        Args:
            prompt: The full prompt string to be sent to the model.
            agent: The agent name (used for logging or future extensions).
            temperature: Controls randomness of the model output.
            donot_output_json: If False, enforce JSON output format via API.

        Returns:
            The model-generated response content as a string.
        """
        payload = [
            ChatCompletionUserMessageParam(
                content=prompt,
                role="user"
            )
        ]

        if self._llm == 'deepseek':
            common_args = dict(
                model="deepseek-chat",
                messages=payload,
                max_tokens=1600,
                temperature=temperature,
                stream=False
            )
        elif self._llm == 'gpt-4o-mini':
            common_args = dict(
                model="gpt-4o-mini",
                messages=payload,
                max_tokens=1600,
                temperature=temperature,
                stream=False
            )
        elif self._llm == 'Qwen':
            common_args = dict(
                model="qwen-plus",
                messages=payload,
                max_tokens=1600,
                temperature=temperature,
                stream=False
            )
        else:
            raise Exception(f'LLM type {self._llm} not supported')

        # Enforce structured output (JSON) for downstream parsing unless explicitly disabled.
        if not donot_output_json:
            common_args['response_format'] = {
                "type": "json_object"
            }

        start_time = time.time()

        response = self.client.chat.completions.create(**common_args)

        end_time = time.time()

        usage = response.usage

        prompt_tokens = usage.prompt_tokens
        completion_tokens = usage.completion_tokens
        total_tokens = usage.total_tokens

        latency_time = end_time - start_time

        logger.info(
            f"[LLM COST] agent={agent}, "
            f"prompt_tokens={prompt_tokens}, "
            f"completion_tokens={completion_tokens}, "
            f"total_tokens={total_tokens}, "
            f"latency_time={latency_time:.2f}s"
        )

        session.total_prompt_tokens += prompt_tokens
        session.total_completion_tokens += completion_tokens
        session.total_tokens += total_tokens
        session.total_latency_time += latency_time

        # The system assumes a single-turn interaction and extracts the first choice.
        reply_content = response.choices[0].message.content
        return reply_content
