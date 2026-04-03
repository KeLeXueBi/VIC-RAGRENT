from typing import Dict

from models.impl.commit_review_request import CommitReviewRequest
from core.rag_db_handler import RagDbHandler
from core.response_parser import ResponseParser
from enums.agent_type import AgentType
from models.impl.session_model import SessionModel


class ContextHandler:

    @staticmethod
    def get_secondary_context(request: CommitReviewRequest, vuln_type: str, session: SessionModel, rag_db: str) -> Dict:
        """
        Collect the auxiliary context required by the secondary inspection stage.

        The returned context may include:
        - structural analysis results extracted from the current session, and
        - similar historical cases retrieved from the RAG store.
        """
        context = {
            "cross_file_deps": None,
            "call_graphs": None,
            "similar_cases": []
        }

        if AgentType.CODE_ANALYST.value in [a.agent for a in session.long_term_memory]:
            context["call_graphs"], context[
                "cross_file_deps"] = ContextHandler.extract_call_graphs_and_cross_file_dependence(
                session)

        similar_cases = RagDbHandler.rag_db_query(request, vuln_type)
        if similar_cases:
            context["similar_cases"] = similar_cases

        return context

    @staticmethod
    def extract_call_graphs_and_cross_file_dependence(session: SessionModel):
        """
        Extract call-graph and cross-file dependency information from the
        code analyst's response stored in session memory.
        """
        call_graphs = {}
        cross_file_deps = {}
        for entry in session.long_term_memory:
            if entry.agent == AgentType.CODE_ANALYST:
                response = entry.response
                result = ResponseParser.parse_json_from_response(response)
                call_graphs = result["call_graphs"]
                cross_file_deps = result["code_patterns"]
                break
        return call_graphs, cross_file_deps
