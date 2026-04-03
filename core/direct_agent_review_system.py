from typing import Dict, List, Optional, Tuple
from loguru import logger
from core.compute_cost import compute_cost

from core.response_parser import ResponseParser
from enums.agent_type import AgentType
from models.impl.commit_review_request import CommitReviewRequest
from models.impl.role_definition import RoleDefinition
from models.impl.session_model import SessionModel
from utils.definition_parser import DefinitionParser
from core.llm_query_client import LLMQueryClient


class DirectAgentReviewSystem:
    """
    Single-agent review baseline.

    Unlike the multi-agent pipeline, this system performs vulnerability
    assessment in one direct step without intermediate agent collaboration,
    staged inspection, or audit-driven refinement.
    """

    _definition: Dict[str, RoleDefinition] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close()

    async def _close(self):
        self._client = None
        logger.info("Exiting....")

    def __init__(self):
        self._init_definition()

    def _init_definition(self):
        """
        Load role definitions used by the direct-review baseline.
        """
        try:
            with DefinitionParser('./data/role_definition.json') as d:
                self._definition = d.roles
        except OSError as e:
            logger.error(f'Error loading role definition: {e}')
            self._definition = {}

    # 异步函数，用于评审提交的代码
    async def review_commit(self, request: CommitReviewRequest, llm_type: str = 'deepseek') -> Dict:
        """
        Run direct vulnerability review for a single commit.

        The direct baseline uses only one reviewer agent and returns the final
        vulnerability decision without multi-stage verification.
        """
        session = SessionModel(commit_id=request.commit_id)
        session.agent_sequence = ["direct_reviewer"]
        logger.info("Starting the direct agent review process...")
        for agent in session.agent_sequence:
            _agent = agent.replace(" ", "_")
            session = await SessionHandlerDirectReview.run_vulnerability_direct_review(agent, request, session, self._definition, llm_type=llm_type)
        return session.vuln_inspection_results


class SessionHandlerDirectReview:
    @staticmethod
    async def execute_direct_review(agent: str, request: CommitReviewRequest,
                                    session: SessionModel, definition: Dict[str, RoleDefinition],
                                    llm_type: str = 'deepseek') -> SessionModel:
        """
        Entry point for executing the direct-review baseline.
        """
        logger.info("Now running direct review...")
        return await SessionHandlerDirectReview.run_vulnerability_direct_review(agent, request, session, definition, llm_type)
    
    @staticmethod
    async def run_vulnerability_direct_review(agent: str, request: CommitReviewRequest,
                                              session: SessionModel, definition: Dict[str, RoleDefinition],
                                              llm_type: str = 'deepseek') -> SessionModel:
        """
        Run single-step vulnerability assessment and convert the model output
        into the unified session result format.
        """
        logger.info("Building prompt for direct review...")
        prompt = PromptBuilderDirectReview.build_direct_review_prompt(request, session, definition)
        with LLMQueryClient(llm_type=llm_type) as llm_client:
            response = await llm_client.query(session, prompt, agent, 0.5)
        result = ResponseParser.parse_json_from_response(response)
        have_vulnerabilities = result["have_vulnerability"]
        if have_vulnerabilities == "yes":
            cwe_type = result["cwe_type"]
            session.vuln_inspection_results = {
                "vuln_detected": True,
                "cwe_list": cwe_type.split(",")
            }
        elif have_vulnerabilities == "no":
            session.vuln_inspection_results = {
                "vuln_detected": False,
                "cwe_list": []
            }
        else:
            raise ValueError(f"Invalid value for 'have_vulnerability': {have_vulnerabilities} or 'cwe_type': {cwe_type}")
        
        logger.info(f"Direct review result: {session.vuln_inspection_results}")

        compute_cost(session, request, llm_type)

        return session

class PromptBuilderDirectReview:
    @staticmethod
    def build_direct_review_prompt(request: CommitReviewRequest, session: SessionModel,
                                     definition: Dict[str, RoleDefinition] = lambda _: []):
        """
        Build the prompt for the direct-review baseline.

        This prompt is intentionally stricter than the recall-oriented initial
        inspection in the multi-agent pipeline: inconclusive evidence should be
        resolved to "no" to reduce false positives.
        """
        prompt = f"""
        You are a security analyst reviewing a source code commit.

        Your task is to determine whether this commit introduces a new security vulnerability.

        Focus only on vulnerabilities newly introduced by this commit.
        Do not report vulnerabilities that already existed before the commit.
        Do not treat general code quality issues, stylistic problems, or vague risks as vulnerabilities.

        **Commit Analysis Task**:
        1. **Code Changes** (Diff): 
        {request.diff}
        2. **Commit Context**: {request.repo_context}
        3. **Commit Message**: {request.message}

        Decision policy:
        - Output "yes" only if there is sufficient code evidence that this commit introduces a real security vulnerability.
        - Output "no" if the risk is only speculative, weakly supported, unrelated to security, or more likely to reflect a benign bug / code smell / incomplete context.
        - A suspicious API call, unsafe-looking operation, or risky pattern alone is NOT sufficient for "yes".
        - If the commit appears to fix an old vulnerability rather than introduce a new one, output "no".
        - If the evidence is inconclusive, output "no".

        Important checks:
        1. Is the risky behavior actually introduced by this commit?
        2. Is there a plausible vulnerability trigger path?
        3. Is the issue security-relevant rather than just a correctness or robustness issue?
        4. Is there enough evidence to justify a vulnerability label?

        Strict Output Rules:
        - Output valid JSON only.
        - Only output the two top-level keys: "have_vulnerability" and "cwe_type".
        - "have_vulnerability" must be "yes" or "no".
        - If "have_vulnerability" is "yes", "cwe_type" must follow the exact format "CWE-XXX".
        - If "have_vulnerability" is "no", set "cwe_type" to "N/A".
        - Do not output any other fields.
        Provide your response in the following EXACT format (example):
        
        ```json
        {{"have_vulnerability": "yes/no", "cwe_type": "CWE-128"}}
        ```
        """
        return prompt
