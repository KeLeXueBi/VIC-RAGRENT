from typing import Dict, List, Optional, Tuple
from loguru import logger

from core.rag_db_handler import RagDbHandler
from core.response_parser import ResponseParser
from core.session_handler import SessionHandler
from enums.agent_type import AgentType
from enums.audit_status import AuditStatus
from models.impl.commit_review_request import CommitReviewRequest
from models.impl.role_definition import RoleDefinition
from models.impl.session_model import SessionModel
from utils.definition_parser import DefinitionParser
from core.compute_cost import compute_cost


class MultiAgentReviewSystem:  # 多 Agent 评审系统
    _long_term_memory: List = []
    _rag_db: str
    # _max_audit_rounds = 5
    _agent_num = 0
    _definition: Dict[str, RoleDefinition] = {}

    async def __aenter__(self):
        logger.debug("Entering MultiAgentReviewSystem context.")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close()

    async def _close(self):
        self._client = None
        logger.info("MultiAgentReviewSystem closed.")

    def __init__(self, rag_db_path="RAG_DIR"):
        # The RAG directory is used to persist final reports for confirmed vulnerabilities,
        # enabling later retrieval and reuse as external knowledge.
        self._rag_db = rag_db_path
        logger.debug(f"Initializing MultiAgentReviewSystem with RAG_DB path: {rag_db_path}")
        self._init_definition()

    def _init_definition(self):
        logger.info("Loading role definitions.")
        try:
            with DefinitionParser('./data/role_definition.json') as d:
                self._definition = d.roles
            logger.info(f"Role definitions loaded successfully. total_roles={len(self._definition)}")
            logger.debug(f"Loaded role names: {list(self._definition.keys())}")
        except OSError as e:
            logger.exception("Failed to load role definition file: ./data/role_definition.json")
            self._definition = {}

    # 异步函数，用于评审提交的代码
    async def review_commit(self, request: CommitReviewRequest, llm_type: str = 'deepseek') -> Dict:
        """
        Run the multi-agent review pipeline for a single commit.

        The current workflow executes a fixed sequence of agents:
        1. code_analyst
        2. target_architect
        3. vulnerability_inspector

        Auditing for code_analyst and target_architect is coordinated in this
        method, while the vulnerability inspection stage handles its own review
        logic internally.
        """
        commit_id = request.commit_id
        logger.info(f"Starting multi-agent review. commit_id={commit_id}, llm_type={llm_type}")
        
        session = SessionModel(commit_id=commit_id)

        # The agent sequence is currently fixed for reproducibility and simplicity.
        session.agent_sequence = ["code_analyst", "target_architect", "vulnerability_inspector"]
        logger.info(
            f"Agent sequence determined. commit_id={commit_id}, "
            f"agent_sequence={session.agent_sequence}"
        )

        for agent in session.agent_sequence:
            _agent = agent.replace(" ", "_")
            session = await SessionHandler.execute_agent_interaction(_agent, request, session, self._definition, llm_type)

            # Auditing for code_analyst and target_architect is orchestrated here.
            # The vulnerability inspection stage has its own built-in review logic
            # inside the corresponding process, so it is not audited separately
            # at this level.
            if _agent != AgentType.VULNERABILITY_INSPECTOR:
                # 审计 Agent 响应
                logger.info(f"Executing auditing for {_agent}")
                audit_response = await SessionHandler.audit_agent_response(_agent, session, self._definition, llm_type)
                audit_result = ResponseParser.parse_audit_response(audit_response)
                session = await SessionHandler.handle_audit_result(audit_result, audit_response, _agent, session,
                                                                   self._definition, self._definition[_agent].questions, llm_type)

        # Check whether any vulnerability candidate was finally confirmed.
        flag = False
        for result in session.vuln_inspection_results["final"]:
            if result["status"] == "confirmed":
                flag = True
                break

        if flag:
            # Generate the final report only when at least one vulnerability is confirmed.
            # This avoids producing and storing unnecessary reports for negative samples.
            # If you want to store negative samples, you can move the corresponding
            # code block to the else branch.
            logger.info("Now generating final report...")
            document = await SessionHandler.generate_final_report(request, session, llm_type)

            logger.info("Vulnerability detected, storing to RAG dictionary...")
            final_results = session.vuln_inspection_results["final"]
            all_vuln_types = []

            # Store one report per confirmed vulnerability type to avoid duplicate
            # insertions when multiple findings share the same category.
            for result in final_results:
                if result["status"] != "confirmed":
                    continue
                vuln_type = result["vuln_type"]
                if vuln_type not in all_vuln_types:
                    RagDbHandler.store_to_rag(request, document, vuln_type, self._rag_db)
                    all_vuln_types.append(vuln_type)

            logger.info("Final report saved to RAG_DIR")

            # Calculate the cost of the review process.
            compute_cost(session, request, llm_type)

            return {
                "commit_id": request.commit_id,
                "vuln_detected": True,
                "vuln_list": session.vuln_inspection_results["final"],
                "cwe_list": all_vuln_types
            }
        else:
            # Calculate the cost of the review process.
            compute_cost(session, request, llm_type)

            # Negative samples are returned directly and are not stored in the RAG database.
            return {
                "commit_id": request.commit_id,
                "vuln_detected": False,
                "vuln_list": None,
                "cwe_list": None
            }
