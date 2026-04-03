import json
import re
from typing import List, Dict


class ResponseParser:
    @staticmethod
    def parse_json_from_response(response: str) -> Dict:
        """
        Parse a generic JSON object from a model response.

        This utility is used by multiple stages whose outputs are expected to be
        valid JSON dictionaries.
        """
        result = json.loads(response)

        if isinstance(result, dict):
            return result

        raise ValueError("Invalid response format")

    @staticmethod
    def parse_audit_response(response: str) -> Dict:
        # Parse the structured output produced by the audit stage.
        result = json.loads(response)
        if isinstance(result, dict):
            return result
        raise ValueError("Invalid response format")
    
    @staticmethod
    def parse_vuln_inspection_initial_response(response)->Dict:
        # Parse the structured output from the initial vulnerability-inspection stage.
        result = json.loads(response)
        if isinstance(result, dict):
            return result
        raise ValueError("Invalid response format")
