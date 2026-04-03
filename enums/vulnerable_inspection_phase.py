from enum import StrEnum

class VulnInspectionPhase(StrEnum):
    """
    Enumeration of the multi-stage vulnerability inspection process.

    Each phase serves a distinct purpose, progressively refining candidate
    vulnerabilities from high-recall detection to high-confidence validation.
    """

    INITIAL = "initial"
    # First-pass inspection with a focus on high recall.
    # Identifies any potentially suspicious code fragments without strict validation.

    SECONDARY = "secondary"
    # In-depth analysis of candidates from the initial phase.
    # Uses additional context (e.g., call graphs, data flow, RAG) to filter false positives.
    
    FINAL = "final"
    # Final decision stage (voting or verification).
    # Confirms true vulnerabilities with stricter criteria and higher precision.
