from typing import List
from pydantic import Field
from models.abs_model import AbsModel


class LongTermMemoryModel(AbsModel):
    """
    Data structure representing a single interaction record in the multi-agent pipeline.

    Each entry captures the full context of an agent's reasoning step, including
    the prompt, response, and audit status. These records collectively form the
    session's long-term memory, enabling iterative reasoning, auditing, and
    final report generation.
    """

    agent: str = Field(...)
    # Name of the agent that produced this response.

    prompt: str = Field(...)
    # The prompt provided to the agent.

    response: str = Field(...)
    # The agent's generated response.

    status: str = Field(default="unchecked")
    # Audit status of the response (e.g., "unchecked", "approved").

    phase: str = Field(...)
    # The stage of the pipeline this interaction belongs to
    # (e.g., code analysis, initial inspection, secondary inspection).

    questions: str = Field(...)
    # The questions or instructions associated with this interaction.
