from typing import Optional, List, Any, Dict
from pydantic import Field
from models.abs_model import AbsModel


class RoleDefinition(AbsModel):
    """
    Schema defining the behavior and capabilities of an agent role.

    Each role definition is used to dynamically construct prompts and guide
    agent reasoning, including responsibilities, constraints, and expected outputs.
    """

    role_key: Optional[str] = Field(default=None)
    # Unique identifier for the role.

    role: Optional[str] = Field(default=None)
    # Human-readable role name used in prompts.

    description: Optional[str] = Field(default=None)
    # High-level description of the role’s purpose.

    responsibilities: Optional[List[str]] = Field(default=None)
    # Core tasks the agent is expected to perform.

    special_abilities: Optional[List[str]] = Field(default=None)
    # Additional capabilities that enhance the agent's reasoning or analysis.

    guidelines: Optional[str] = Field(default=None)
    # General instructions or constraints for the agent.

    output_format: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # Expected structure of the agent's output (used to enforce JSON format).

    evaluation_criteria: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # Criteria used to evaluate the quality of the agent's response.

    intervention_protocol: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # Rules for handling incorrect or low-quality responses (e.g., retries or corrections).

    analysis_focus: Optional[List[str]] = Field(default_factory=list)
    # Specific aspects the agent should prioritize during analysis.

    questions: Optional[str] = Field(default=None)
    # Task-specific questions that guide the agent's reasoning.

    change_taxonomy: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # Classification schema for different types of code changes.

    operation_phases: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # Defines role-specific behavior across different stages of the pipeline.

    vulnerability_specializations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    # Specialized knowledge or rules for handling particular vulnerability types.

    report_types: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # Templates or formats for generating structured reports.
