from enum import StrEnum


class AuditStatus(StrEnum):
    """
    Enumeration of possible outcomes from the audit supervisor.

    These statuses determine how the system reacts to an agent's response,
    including whether to accept the result or trigger corrective actions.
    """

    APPROVED = "approved"
    # The response is considered valid and can be accepted without modification.
    
    NEEDS_ADD_PROMPT = "needs_add_prompt"
    # The response is considered valid and can be accepted without modification.

    NEEDS_MORE_CONTEXT = "needs_more_context"
     # The response lacks necessary context and may require invoking additional agents or retrieving more information.
    
    FAILED = "failed"
    # The response is invalid or unusable, and cannot be corrected through simple retries.
