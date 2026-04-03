from enum import StrEnum


class AgentType(StrEnum):
    """
    Enumeration of all agent roles used in the multi-agent review system.

    Each role corresponds to a specific responsibility in the review pipeline,
    forming a structured workflow from code understanding to vulnerability analysis.
    """

    # ----------------------------
    # Core system roles
    # ----------------------------

    AUDIT_SUPERVISOR = "audit_supervisor"
    # Oversees response quality and enforces correctness through auditing and retries.

    CODE_ANALYST = "code_analyst"
    # Performs structural code analysis (e.g., call graphs, data flow, language features).

    TARGET_ARCHITECT = "target_architect"
    # Interprets the intent of the commit and maps changes to high-level goals.

    VULNERABILITY_INSPECTOR = "vulnerability_inspector"
    # Detects potential vulnerabilities through multi-stage inspection (initial, secondary, final).

    DOCUMENTATION_SPECIALIST = "documentation_specialist"
    # Generates the final structured security report based on all prior analysis.

    # ----------------------------
    # Ablation / baseline roles
    # ----------------------------

    DIRECT_REVIEWER = "direct_reviewer"
    # A simplified single-agent baseline used in ablation experiments.
