from typing import List, Dict, Any
from pydantic import Field

from models.abs_model import AbsModel
from models.impl.long_term_memory_model import LongTermMemoryModel


class SessionModel(AbsModel):
    """
    Runtime session state for a single commit review.

    This model stores the evolving state of the multi-agent pipeline, including
    the current phase, executed agent sequence, intermediate inspection results,
    audit records, and accumulated long-term memory.
    """
    
    commit_id: str = Field(..., description="The commit id")
    current_phase: str = Field(default='start', description="The current phase")
    agent_sequence: List[str] = Field(default=[], description="The agent sequence")
    vuln_inspection_results: Dict[str, Any] = Field(default_factory=dict,
                                                    description="The vulnerability inspection results")
    audit_history: List[Any] = Field(default_factory=list, description="The audit history")
    long_term_memory: List[LongTermMemoryModel] = Field(default_factory=list, description="The long term memory")
    agent_memory: Dict[str, Any] = Field(default_factory=dict, description="The agent memory")
    
    total_prompt_tokens: int = Field(default=0, description="The total prompt tokens")
    total_completion_tokens: int = Field(default=0, description="The total completion tokens")
    total_tokens: int = Field(default=0, description="The total tokens")
    total_latency_time: float = Field(default=0.00, description="The total latency time")
   
