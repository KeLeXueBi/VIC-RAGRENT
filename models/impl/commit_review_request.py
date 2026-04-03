from models.abs_model import AbsModel


class CommitReviewRequest(AbsModel):
    """
    Data structure representing a commit-level review request.

    This object serves as the unified input to the multi-agent review pipeline,
    providing all necessary information for analysis, including code changes,
    commit intent, and repository context.
    """

    commit_id: str
    # Unique identifier of the commit.

    message: str
    # Commit message describing the intent of the change.
    
    diff: str
    # Code changes (diff) introduced by the commit.
    
    repo_context: str
    # Surrounding repository context (e.g., related files, functions, or modules).
