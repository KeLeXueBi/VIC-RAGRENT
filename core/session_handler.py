import json
from typing import Dict, Tuple, List

from sympy import Li

from core.context_handler import ContextHandler
from core.prompt_builder import PromptBuilder
from core.response_parser import ResponseParser
from enums import audit_status
from enums.agent_type import AgentType
from enums.audit_status import AuditStatus
from enums.vulnerable_inspection_phase import VulnInspectionPhase
from models.impl.commit_review_request import CommitReviewRequest
from models.impl.long_term_memory_model import LongTermMemoryModel
from models.impl.role_definition import RoleDefinition
from models.impl.session_model import SessionModel
from core.llm_query_client import LLMQueryClient
from loguru import logger


class SessionHandler:
    max_audit_rounds = 1
    TEMPERATURES = {
        AgentType.CODE_ANALYST.value: 0.2,
        AgentType.TARGET_ARCHITECT.value: 0.2,
        "VI_INITIAL": 0.4,
        "VI_SECONDARY": 0.4,
        "VI_FINAL": 0.1,
        AgentType.DOCUMENTATION_SPECIALIST.value: 0.3,
        AgentType.AUDIT_SUPERVISOR.value: 0.1,
        "RETRY_DEFAULT": 0.2,
    }

    @staticmethod
    async def execute_agent_interaction(agent: str, request: CommitReviewRequest,
                                        session: SessionModel, definition: Dict[str, RoleDefinition],
                                        llm_type: str = 'deepseek',
                                        rag_db: str = 'RAG_DIR') -> SessionModel:
        """
        Execute one step of agent workflow.

        For regular agents, this method builds the prompt queries the LLM,
        and stores the result in long-term memory.

        The vulnerability inspection stage is handled separately because it
        consists of a multi-phase pipeline with its own internal review logic.
        """
        if agent == AgentType.VULNERABILITY_INSPECTOR:
            logger.info("Now running vulnerability inspection...")
            return await SessionHandler.run_vulnerability_inspection(agent, request, session, definition, rag_db, llm_type)
        else:
            prompt, questions = PromptBuilder.build_agent_prompt(agent, request, definition)

            with LLMQueryClient(llm_type=llm_type) as llm_client:
                response = await llm_client.query(session, prompt, agent, SessionHandler.TEMPERATURES[agent])

            session.long_term_memory.append(
                LongTermMemoryModel(
                    agent=agent,
                    prompt=prompt,
                    response=response,
                    status="unchecked",
                    phase=agent,
                    questions=questions
                )
            )
            return session

    
    @staticmethod
    async def run_vulnerability_inspection(agent, request: CommitReviewRequest,
                                           session: SessionModel,
                                           definition: Dict[str, RoleDefinition], rag_db: str, llm_type: str) -> SessionModel:
        """
        Run the staged vulnerability inspection pipeline.

        The pipeline contains three phases:
        1. Initial inspection: identify suspicious vulnerability candidates.
        2. Secondary inspection: validate each candidate with additional context.
        3. Final vote: make the final decision on candidates that passed phase two.

        Unlike the regular agent flow, review and retry logic for vulnerability
        inspection is embedded inside this process because each phase requires
        different prompts, parsing rules, and decision criteria.
        """
        logger.info("Now conducting initial vuln inspection...")
        logger.info("Building prompt for initial inspector...")
        initial_prompt, initial_questions = PromptBuilder.build_vuln_inspection_prompt(request, session,
                                                                                       VulnInspectionPhase.INITIAL,
                                                                                       definition)
        
        with LLMQueryClient(llm_type=llm_type) as llm_client:
            initial_response = await llm_client.query(session, initial_prompt, "VI_INITIAL", SessionHandler.TEMPERATURES["VI_INITIAL"])

        session.long_term_memory.append(
            LongTermMemoryModel(agent="VI_INITIAL",
                                prompt=initial_prompt,
                                response=initial_response,
                                status="unchecked",
                                phase=VulnInspectionPhase.INITIAL,
                                questions=initial_questions)
        )

        # Audit the initial inspection result before using it to guide
        # the downstream stages.
        audit_response = await SessionHandler.audit_agent_response("VI_INITIAL", session, definition, llm_type)

        audit_result = ResponseParser.parse_audit_response(audit_response)
        session = await SessionHandler.handle_audit_result(audit_result, audit_response, "VI_INITIAL", session, definition, initial_questions, llm_type)
        
        initial_result = ResponseParser.parse_vuln_inspection_initial_response(session.long_term_memory[-1].response)

        have_vulnerabilities = initial_result["have_vulnerabilities"]
        details = initial_result["details"]

        if have_vulnerabilities == "no":
            logger.info("No suspicious vulnerabilities found.")
            session.vuln_inspection_results = {
                "final": []
            }
            return session
        elif have_vulnerabilities == "yes":
            logger.info("Suspicious vulnerabilities found.")
        else:
            raise ValueError(f"Invalid value for have_vulnerabilities: {have_vulnerabilities}")

        logger.info("Get initial inspection results.")

        logger.info("Now conducting secondary vuln inspection...")

        for idx, item in enumerate(details):
            filename = item["filename"]
            func_name = item["function_name"]
            code_segment = item["code_segment"]
            vuln_type = item["vulnerability_type"]
            reason = item["reason"]

            # Retrieve supporting context from the RAG store to help the model
            # reassess the candidate in a more informed way.

            second_context = ContextHandler.get_secondary_context(request, vuln_type, session, rag_db)

            prompt, question, vuln_type = PromptBuilder.build_secondary_prompt(request, item, second_context, definition)

            with LLMQueryClient(llm_type=llm_type) as llm_client:
                second_response = await llm_client.query(session, prompt, "VI_SECONDARY", SessionHandler.TEMPERATURES["VI_SECONDARY"])
            
            session.long_term_memory.append(
                LongTermMemoryModel(agent="VI_SECONDARY",
                                    prompt=prompt,
                                    response=second_response,
                                    status="unchecked",
                                    phase=VulnInspectionPhase.SECONDARY,
                                    questions=question)
            )

            # Each secondary result is also reviewed before it is allowed
            # to enter the final decision stage.
            audit_response = await SessionHandler.audit_agent_response("VI_SECONDARY", session, definition, llm_type)
            audit_result = ResponseParser.parse_audit_response(audit_response)
            session = await SessionHandler.handle_audit_result(audit_result, audit_response, "VI_SECONDARY", session, definition, question, llm_type)
            secondary_result = ResponseParser.parse_json_from_response(session.long_term_memory[-1].response)

            details[idx]["secondary_result"] = secondary_result
            details[idx]["vuln_type"] = vuln_type
            is_vulnerability_secondary = str(secondary_result.get("is_vulnerability", "")).strip().lower()
            details[idx]["secondary_pass"] = (is_vulnerability_secondary == "yes")

        # Only candidates that pass the secondary inspection move to final voting.
        vote_candidates = [item for item in details if item.get("secondary_pass", False)]
        logger.info(f"Secondary passed candidates: {len(vote_candidates)}/{len(details)}")

        if not vote_candidates:
            logger.info("No candidates passed secondary inspection. Skipping final voting.")
            session.vuln_inspection_results["final"] = []
            return session

        # Conduct final voting on the candidates that passed secondary inspection.
        logger.info("Now conducting final vuln inspection...")
        final_results = await SessionHandler.conduct_final_vote(request, session, vote_candidates, definition, llm_type)
        if session.vuln_inspection_results is None:
            session.vuln_inspection_results = {}
        session.vuln_inspection_results["final"] = final_results
        return session

    @staticmethod
    async def conduct_final_vote(request: CommitReviewRequest, session, details: List[Dict],
                                 definition: Dict[str, RoleDefinition], llm_type: str) -> List[Dict]:
        # logger.info("Now conducting final vuln inspection...")
        """
        Run the final decision stage for candidates that passed secondary inspection.

        Each candidate is evaluated by the final reviewer and converted into:
        - a binary decision (confirmed or rejected),
        - an average confidence score,
        - and an optional dominant CWE label.

        The current implementation uses a single low-temperature voter to reduce
        randomness, so this stage behaves more like a deterministic final check
        than a diverse ensemble vote.
        """
        votes = {}
        cwe_votes = {}
        counts = {}
        num_voters = 1
        final_results = []

        for idx, item in enumerate(details):
            code_segment = item["code_segment"]
            filename = item.get("filename", "")
            function_name = item.get("function_name", "")
            vuln_type = item.get("vuln_type", item.get("vulnerability_type", "Unknown"))
            secondary_result = item.get("secondary_result", {})
            vote_yes, vote_no = 0, 0
            cwe_candidates = []
            confidence_scores = []

            for voter_idx in range(num_voters):
                prompt, final_question = PromptBuilder.build_voting_prompt(request, code_segment, secondary_result, session, definition)

                with LLMQueryClient(llm_type=llm_type) as llm_client:
                    response = await llm_client.query(session, prompt, "VI_FINAL", SessionHandler.TEMPERATURES["VI_FINAL"])

                session.long_term_memory.append(
                    LongTermMemoryModel(agent="VI_FINAL",
                                        prompt=prompt,
                                        response=response,
                                        status="unchecked",
                                        phase=VulnInspectionPhase.FINAL,
                                        questions=final_question)
                )

                final_json = ResponseParser.parse_json_from_response(response)

                raw_vote = str(final_json.get("is_vulnerability", "")).strip().lower()
                raw_confidence = str(final_json.get("confidence", "")).strip().lower()
                raw_cwe = str(final_json.get("cwe_category", "")).strip()

                # Map confidence labels to numeric scores so that confidence can
                # influence both the final decision and the aggregated score.
                if raw_confidence == "high":
                    conf_score = 1.0
                elif raw_confidence == "medium":
                    conf_score = 0.67
                elif raw_confidence == "low":
                    conf_score = 0.33
                else:
                    conf_score = 0.5
                
                confidence_scores.append(conf_score)

                # A low-confidence answer is treated as support for the opposite
                # decision, which helps down-weight uncertain outputs without
                # discarding them entirely.
                if raw_vote == "yes" and conf_score >= 0.5:
                    vote_yes += 1
                    if raw_cwe not in [None, "null", "", "None"]:
                        cwe_candidates.append(raw_cwe)
                elif raw_vote == "no" and conf_score < 0.5:
                    vote_yes += 1
                    if raw_cwe not in [None, "null", "", "None"]:
                        cwe_candidates.append(raw_cwe)
                elif raw_vote == "no" and conf_score >= 0.5:
                    vote_no += 1
                elif raw_vote == "yes" and conf_score < 0.5:
                    vote_no += 1
                else:
                    logger.exception(f"Unknown vote: {raw_vote} with confidence: {raw_confidence}")
                    raise
            
            status = "confirmed" if vote_yes > vote_no else "rejected"

            major_cwe = None
            if status == "confirmed" and cwe_candidates:
                major_cwe = max(set(cwe_candidates), key=cwe_candidates.count)
            
            avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0

            final_results.append({
                "filename": filename,
                "function_name": function_name,
                "code_segment": code_segment,
                "status": status,
                "confidence": round(avg_confidence, 4),
                "cwe": major_cwe,
                "vuln_type": vuln_type,
            })
        
        logger.info("Get final results.")
        return final_results

    @staticmethod
    async def audit_agent_response(agent: str, session: SessionModel, definition: Dict[str, RoleDefinition], llm_type: str) -> str:
        """
        Review the latest agent response using the audit supervisor prompt.
        """
        logger.info("Generating audit supervisor prompt...")
        last_response = session.long_term_memory[-1]
        if not last_response:
            raise ValueError("No response found for agent: {}".format(agent))

        prompt = PromptBuilder.build_audit_prompt(agent, last_response, definition)
        
        with LLMQueryClient(llm_type=llm_type) as llm_client:
            audit_response = await llm_client.query(session, prompt, agent, SessionHandler.TEMPERATURES[agent])
        return audit_response

    @staticmethod
    async def handle_audit_result(audit_result: Dict, audit_response: str, agent: str,
                                  session: SessionModel, definition: Dict[str, RoleDefinition], question: str, llm_type: str) -> SessionModel:
        """
        Handle the audit decision for the latest agent response.

        If the response is rejected, the original prompt is augmented with the
        supervisor's feedback and retried for a limited number of rounds.
        """
        logger.info("Auditing agent response...")
        if audit_result["status"] == AuditStatus.APPROVED:
            return SessionHandler._audit_approved(agent, session)
        
        logger.warning("Audit rejected. Retrying...")
        for i in range(SessionHandler.max_audit_rounds):
            logger.info(f"Retry attempt {i + 1}...")
            # 增加 prompt
            logger.info("The prompt will be enhanced and retried.")
            original_prompt = session.long_term_memory[-1].prompt
            additional_prompt = audit_result["additional_prompt"]

            # Insert the audit feedback before the output-format section when possible,
            # so the corrective instruction is visible without breaking the final
            # formatting constraints.
            position = original_prompt.find("**Output Format Requirements**")
            if position == -1:
                new_prompt = original_prompt + "\n\nAdditional note: " + additional_prompt
            else:
                str_before_output = original_prompt[:position]
                str_after_output = original_prompt[position:]
                new_prompt = str_before_output + "Additional note: " + additional_prompt + '\n\n' + str_after_output

            new_response = await LLMQueryClient(llm_type=llm_type).query(session, new_prompt, agent, 0.4)

            session.long_term_memory.pop()
            session.long_term_memory.append(
                LongTermMemoryModel(
                    agent=agent,
                    prompt=new_prompt,
                    response=new_response,
                    status="unchecked",
                    phase=agent,
                    questions=question
                )
            )

            new_audit = await SessionHandler.audit_agent_response(agent, session, definition, llm_type)
            new_audit_result = ResponseParser.parse_audit_response(new_audit)

            if new_audit_result["status"] == AuditStatus.APPROVED:
                logger.info("Audit approved!")
                return session

        logger.warning("Maximum retry attempts exceeded.")
        return session

    @staticmethod
    def _audit_approved(agent: str, session: SessionModel) -> SessionModel:
        logger.info("Audit approved!")
        session.long_term_memory[-1].status = "approved"
        return session

    @staticmethod
    async def enhance_prompt_response(session: SessionModel, agent: str, last_response: LongTermMemoryModel, audit_result: Dict, llm_type: str) -> str:
        """
        Generate an enhanced prompt based on the audit result and query the LLM again.
        """
        prompt = PromptBuilder.build_enhanced_prompt(agent, last_response, audit_result)
        with LLMQueryClient(llm_type=llm_type) as llm_client:
            result = await llm_client.query(session, prompt, AgentType.REVIEW_CONDUCTOR.value, SessionHandler.TEMPERATURES["RETRY_DEFAULT"])
        return result

    @staticmethod
    async def generate_final_report(request: CommitReviewRequest, session: SessionModel, llm_type: str) -> str:
        """
        Generate the final natural-language report from the accumulated session memory.
        """
        analysis_results = {}
        for entry in session.long_term_memory:
            agent = entry.agent
            response = entry.response
            analysis_results[agent] = response

        prompt = PromptBuilder.build_report_prompt(request, session, analysis_results)

        with LLMQueryClient(llm_type=llm_type) as llm_client:
            report = await llm_client.query(session, prompt, AgentType.DOCUMENTATION_SPECIALIST.value, SessionHandler.TEMPERATURES[AgentType.DOCUMENTATION_SPECIALIST.value], donot_output_json=True)
        return report
