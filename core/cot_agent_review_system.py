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

class CotAgentReviewSystem:
    """
    Chain-of-thought review baseline.

    This baseline uses a single reviewer agent that performs explicit step-by-step
    reasoning before making a final vulnerability decision, without multi-agent
    collaboration, staged verification, or audit-driven refinement.
    """

    _definition: Dict[str, RoleDefinition] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close()

    async def _close(self):
        self._client = None
        logger.info("Exiting....")

    # 异步函数，用于评审提交的代码
    async def review_commit(self, request: CommitReviewRequest, llm_type: str = 'deepseek') -> Dict:
        """
        Run chain-of-thought vulnerability review for a single commit.
        """
        session = SessionModel(commit_id=request.commit_id)
        session.agent_sequence = ["cot_reviewer"]
        logger.info("Starting the cot agent review process...")
        for agent in session.agent_sequence:
            _agent = agent.replace(" ", "_")
            session = await SessionHandlerCotReview.run_vulnerability_cot_review(agent, request, session, self._definition, llm_type=llm_type)
        return session.vuln_inspection_results


class SessionHandlerCotReview:
    @staticmethod
    async def execute_cot_review(agent: str, request: CommitReviewRequest,
                                    session: SessionModel, definition: Dict[str, RoleDefinition],
                                    llm_type: str = 'deepseek') -> SessionModel:
        """
        Entry point for executing the CoT baseline.
        """
        logger.info("Now running cot review...")
        return await SessionHandlerCotReview.run_vulnerability_cot_review(agent, request, session, definition, llm_type)
    
    @staticmethod
    async def run_vulnerability_cot_review(agent: str, request: CommitReviewRequest,
                                              session: SessionModel, definition: Dict[str, RoleDefinition],
                                              llm_type: str = 'deepseek') -> SessionModel:
        """
        Run single-agent step-by-step vulnerability reasoning and convert the
        result into the unified session output format.
        """
        logger.info("Building prompt for cot review...")
        prompt = PromptBuilderCotReview.build_cot_review_prompt(request, session, definition)
        with LLMQueryClient(llm_type=llm_type) as llm_client:
            response = await llm_client.query(session, prompt, agent, 0.5)
        result = ResponseParser.parse_json_from_response(response)
        have_vulnerabilities = result["is_vulnerability"]
        if have_vulnerabilities == "yes":
            session.vuln_inspection_results = {
                "vuln_detected": True,
                "cwe_list": []
            }
        elif have_vulnerabilities == "no":
            session.vuln_inspection_results = {
                "vuln_detected": False,
                "cwe_list": []
            }
        else:
            raise ValueError(f"Invalid value for 'have_vulnerability': {have_vulnerabilities}")
        
        logger.info(f"Cot review result: {session.vuln_inspection_results}")
        
        compute_cost(session, request, llm_type)
        
        return session

class PromptBuilderCotReview:
    @staticmethod
    def build_cot_review_prompt(request: CommitReviewRequest, session: SessionModel,
                                     definition: Dict[str, RoleDefinition] = lambda _: []):
        """
        Build the prompt for the chain-of-thought baseline.

        Compared with the direct-review baseline, this prompt explicitly guides
        the model through intermediate reasoning steps before requiring a final
        binary decision.
        """
        prompt = f"""
        You are a security analyst reviewing a source code commit.

        Your task is to determine whether this commit introduces a new security vulnerability.

        Please reason step by step before giving the final answer.
        Be conservative in the final decision: suspicious patterns alone are not enough.
        Only output "yes" if the available code and context provide sufficient evidence that this commit introduces a real security vulnerability.
        If the evidence is inconclusive, output "no".

        Step 1: Summarize the purpose of the commit and the main code changes.
        Step 2: Identify any security-relevant code fragments or risky operations in the commit.
        Step 3: Determine whether the risky behavior is newly introduced by this commit, rather than pre-existing or vulnerability-fixing behavior.
        Step 4: Judge whether the evidence is strong enough to label the commit as vulnerability-inducing.
        Step 5: Give a final binary decision.

        **Commit Analysis Task**:
        1. **Code Changes** (Diff): 
        {request.diff}
        2. **Commit Context**: {request.repo_context}
        3. **Commit Message**: {request.message}

        Decision rules:
        - Output "yes" only if the commit introduces a security-relevant flaw with sufficient supporting evidence.
        - Output "no" if the issue is speculative, weakly supported, non-security-related, or likely to be a benign bug / robustness issue.
        - Output "no" if the commit more likely fixes an old vulnerability than introduces a new one.
        - A suspicious function call or risky pattern alone is not sufficient for "yes".
        Output valid JSON only in the following format:
        ```json
        {{
            "reasoning": {{
                "step1": "...",
                "step2": "...",
                "step3": "...",
                "step4": "...",
                "step5": "..."
            }},
            "is_vulnerability": "yes/no"
        }}
        """
        return prompt
