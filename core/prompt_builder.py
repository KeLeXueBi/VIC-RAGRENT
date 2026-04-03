import json
from typing import Dict, Tuple

from loguru import logger

from core.response_parser import ResponseParser
from enums.agent_type import AgentType
from enums.vulnerable_inspection_phase import VulnInspectionPhase
from models.impl.commit_review_request import CommitReviewRequest
from models.impl.long_term_memory_model import LongTermMemoryModel
from models.impl.role_definition import RoleDefinition
from models.impl.session_model import SessionModel


class PromptBuilder:
    @staticmethod
    def build_agent_prompt(agent: str, request: CommitReviewRequest, definition: Dict[str, RoleDefinition]) -> Tuple[
        str, str]:
        """
        Build the prompt for a regular non-inspection agent.

        This method is used for agents such as code_analyst and target_architect.
        Each prompt includes:
        - the agent role description,
        - the commit message, diff, and repository context,
        - agent-specific questions,
        - and a strict JSON output contract for downstream parsing.
        """
        logger.info(f"Building prompt for {agent}...")
        responsibilities = definition[agent].responsibilities
        _responsibilities = "\n".join(f"- {resp}" for resp in responsibilities)
        focus_areas = definition[agent].analysis_focus
        _focus_areas = "\n".join(f"- {area}" for area in focus_areas)
        questions = definition[agent].questions
        _prompt = f"""
                    **Role**: {definition[agent].role}
                    **Description**: {definition[agent].description}

                    Your responsibilities include:
                    {responsibilities}

                    **Commit Analysis Task**:
                    1. **Commit Message**: {request.message}
                    2. **Code Changes** (Diff): 
                    {request.diff}
                    3. **Commit Context**:
                    {request.repo_context}

                    **Questions**:
                    {questions}

        """
        match agent:
            case AgentType.CODE_ANALYST:
                _prompt += f"""\n
                **Output Format Requirements**:
                    Provide your response in the following EXACT format (example) and please strictly output in the json format as shown in the output example. Do not output any extra information.:
                    ```json
                    {{
                        "language_breakdown": {{"main": "C", "secondary": ["Python"]}},
                        "call_graphs": {{
                            "graph1": {{"func_a": ["func_b", "func_c"], "func_b": [func_d"], "func_c": []}},
                            "graph2": {{"func_e": [], "func_f": []}}
                        }},
                        "code_patterns": {{
                            "data_flows": [
                                {{
                                    "from": "func_b",
                                    "to": "func_a",
                                    "data": "data_name_1"
                                }},
                                {{
                                    "from": "func_g",
                                    "to": "func_h",
                                    "data": "data_name_2"
                                }}
                            ]
                        }}
                    }}
                    ```

                    - Briefly justify each selection based on the commit content
                """
            case AgentType.TARGET_ARCHITECT:
                _prompt += f"""\n
            **Output Format Requirements**:
            Provide your response in the following EXACT format (example) and please strictly output in the json format as shown in the output example. Do not output any extra information.:
                ```json
                    {{
                        "commit_msg_goal_1": {{
                            "description": "fix some bug",
                            "implemented_changes": {{
                                "fully_addressed": ["file1"],
                                "partially_addressed": ["file2"],
                                "not_addressed": ["file3"],
                                "unclear": ["file4"]
                            }}
                        }},
                        "commit_msg_goal_2": {{
                            "description": "add some new feature",
                            "implemented_changes": {{
                                "fully_addressed": ["file5"],
                                "partially_addressed": [],
                                "not_addressed": [],
                                "unclear": []
                            }}
                        }}
                    }}
                    ```

            - List the goals that the commit message is trying to achieve, and the files that are related to them.
                    
            """
            case _:
                raise ValueError(f"Invalid agent: {agent}")
        return _prompt, questions

    @staticmethod
    def build_vuln_inspection_prompt(request: CommitReviewRequest, session: SessionModel,
                                     phase: VulnInspectionPhase = VulnInspectionPhase.INITIAL,
                                     definition: Dict[str, RoleDefinition] = lambda _: []):
        """
        Build the prompt for the initial vulnerability inspection phase.

        This stage is recall-oriented: suspicious candidates should be surfaced
        for later validation rather than filtered too aggressively up front.
        The prompt therefore emphasizes broad detection across the predefined
        vulnerability categories while still requiring a structured JSON output.
        """
        logger.debug("Building initial vuln inspection prompt...")
        long_term_memory = session.long_term_memory
        print_format = "\n".join(
            f"{conv.agent}: {conv.response}"
            for conv in long_term_memory
        )

        questions = """
        - Identify suspicious code fragments that may introduce new security vulnerabilities.
        - Focus on high recall: if a fragment plausibly introduces risk, mark it as suspicious for later verification.
        - Check the commit against the six vulnerability categories: I/O Validation, Memory Safety, Web Security, Authn/Authz, Resource Management, and File/Path Handling.
        """

        """构建漏洞审查提示"""
        if phase == VulnInspectionPhase.INITIAL:
            prompt = f"""
            You are a security analyst reviewing a source code commit.  
            Your task is to determine **whether this commit introduces any new security vulnerabilities.**  
            Focus only on new vulnerabilities introduced by the code changes, not on old vulnerabilities fixed by this commit.

            Focus only on **new vulnerabilities introduced by the commit**, not on vulnerabilities fixed by this commit (if any).

            **Commit Analysis Task**:
            1. **Code Changes** (Diff): 
            {request.diff}
            2. **Commit Context**: {request.repo_context}

            **Extra Information**:
            {print_format}

            Your responsibilities include:
            - Analyze whether the commit will introduce ANY new security vulnerabilities. Focus ONLY on new vulnerabilities that may be introduced by the commit.
            - You may reference both the changed code and the relevant surrounding context to make a determination.
            - Based on the given information, analyze whether the between six vulnerability types exist:
              I/O Validation: Check if there is any unfiltered user input used for formatting output, command execution, SQL construction, or path concatenation. Focus on calls such as printf, sprintf, scanf, exec*, system, strcpy, strcat, etc.
            Memory Safety: Check for unchecked memcpy, malloc, realloc, array index out-of-bounds, use-after-free, and uninitialized pointers.
            Web Security: Check for XSS/HTML injection, CRLF injection, cross-site request forgery (CSRF), XML external entity (XXE) injection, client-side or server-side script execution, remote code execution, SQL injection, denial of service (DoS), information leakage, sensitive data exposure, etc.
            Authn/Authz: Check whether security measures such as check_*, is_admin, and authenticate have been removed or bypassed, or whether access control is missing in new features.
            Resource Management: Check for resource leaks (unclosed files/sockets/threads), deadlock risks, error paths that do not release resources, and loops or I/O-read operations whose exit/termination conditions may never be met (leading to infinite resource usage).
            File/Path Handling: Pay attention to path concatenation involving user input, symlink following, ../ path traversal, command execution via system(), and calls to open and unlink.
            - Do NOT explain how the commit fixes old vulnerabilities, unless the fix itself introduces new risks.
            - If there are any suspicious vulnerabilities, the "have_vulnerabilities" field should be set to `"yes"` and otherwise set to `"no"` and provide the details.

            **Important:**  
            When analyzing, do not restrict yourself only to the changed lines (diff).  
            If a change modifies function behavior, variable usage, or call flow, check the relevant context to determine whether a vulnerability **may now exist** even if the vulnerable code itself is outside the diff.
            Vulnerability type must be one of the six vulnerability types listed above.
            
            **Output Format Requirements**:
            - Output valid JSON only. Do not output any extra text.
            - Use exactly two top-level keys: "have_vulnerabilities" and "details".
            - "have_vulnerabilities" must be "yes" or "no".
            - "details" must be a list.
            - If no suspicious vulnerability is found, set "have_vulnerabilities" to "no" and "details" to [].
            - Each element in "details" must follow this structure:
            {{
                "filename": "...",
                "function_name": "...",
                "code_segment": "...",
                "vulnerability_type": "...",
                "reason": "..."
            }}
            - "vulnerability_type" must be one of:
            "I/O Validation", "Memory Safety", "Web Security", "Authn/Authz", "Resource Management", "File/Path Handling"
            """
            return prompt, questions
        else:
            raise ValueError("Invalid phase")

    @staticmethod
    def build_audit_prompt(agent: str, model: LongTermMemoryModel, definition: Dict[str, RoleDefinition]):
        """
        Build the audit prompt used to review the latest agent response.

        Different agents are reviewed with slightly different standards.
        For example, the initial vulnerability inspection stage is more tolerant
        of uncertainty because it is designed to maximize recall.
        """
        match agent:
            case AgentType.VULNERABILITY_INSPECTOR | "VI_SECONDARY":
                return """
                        Please review whether the response made by the agent answering the question correctly addresses the question posed by the other agent (audit the following agent response for quality): 
                        - Agent: {agent}
                        - Questions: {question}
                        - Response: {response}
        
                        Check for:
                        1. Completeness (address all parts of the question)
                        2. Technical accuracy
                        3. Evidence support (Optimal)
                        4. Actionability (Optimal)
        
                        **Output Format Requirements**:
                        Provide your response in the following EXACT format (example) and please strictly output in the json format as shown in the output example. Do not output any extra information.:
                        If the agent response is rejected, please explain why it was rejected and give the additional prompt.
                        ```json
                        {{
                            "status": "approved/rejected",
                            "reason": "reason why it was approved or rejected",
                            "additional_prompt": "put additional prompt here if rejected"
                        }}
                        ```
                        """.format(
                            agent=agent,
                            question=model.questions,
                            response=model.response
                        )
            case AgentType.CODE_ANALYST:
                return """
                    Please review whether the response made by the agent answering the question correctly addresses the question posed by the other agent (audit the following agent response for quality): 
                    - Agent: {agent}
                    - Questions: {question}
                    - Response: {response}

                    Check for:
                    1. Completeness (address all parts of the question) (As long as it answered the question correctly)
                    2. Technical accuracy
                    3. Evidence support
                    4. Actionability

                    **Output Format Requirements**:
                    Provide your response in the following EXACT format (example) and please strictly output in the json format as shown in the output example. Do not output any extra information.:
                    If the agent response is rejected, please explain why it was rejected and give the additional prompt.
                    ```json
                    {{
                        "status": "approved/rejected",
                        "reason": "reason why it was approved or rejected",
                        "additional_prompt": "put additional prompt here if rejected"
                    }}
                    ```
                    """.format(
                        agent=agent,
                        question=model.questions,
                        response=model.response
                    )
            case AgentType.TARGET_ARCHITECT:
                return """
                    Please review whether the response made by the agent answering the question correctly addresses the question posed by the other agent (audit the following agent response for quality): 
                    - Agent: {agent}
                    - Questions: {question}
                    - Response: {response}

                    Check for:
                    1. Completeness (address all parts of the question) (If the question does not require the agent to answer, the review intensity can be relaxed.)
                    2. Technical accuracy (If the question does not require the agent to answer, the review intensity can be relaxed.)
                    3. Evidence support 
                    4. Actionability

                    **Output Format Requirements**:
                    Provide your response in the following EXACT format (example) and please strictly output in the json format as shown in the output example. Do not output any extra information.:
                    If the agent response is rejected, please explain why it was rejected and give the additional prompt.
                    ```json
                    {{
                        "status": "approved/rejected",
                        "reason": "reason why it was approved or rejected",
                        "additional_prompt": "put additional prompt here if rejected"
                    }}
                    ```
                    """.format(
                        agent=agent,
                        question=model.questions,
                        response=model.response
                    )
            case "VI_INITIAL":
                return """
                    Please review whether the response made by the agent answering the question correctly addresses the question posed by the other agent (audit the following agent response for quality): 
                    - Agent: {agent}
                    - Questions: {question}
                    - Response: {response}

                    Check for:
                    1. Completeness (address all parts of the question)
                    2. Technical accuracy

                    At the preliminary inspection stage, prioritize whether the response identifies plausible suspicious risks.
                    Do not reject a response merely because the evidence is inconclusive, since this stage is intended to maximize recall for later verification.
    
                    **Output Format Requirements**:
                    Provide your response in the following EXACT format (example) and please strictly output in the json format as shown in the output example. Do not output any extra information.:
                    If the agent response is rejected, please explain why it was rejected and give the additional prompt.
                    ```json
                    {{
                        "status": "approved/rejected",
                        "reason": "reason why it was approved or rejected",
                        "additional_prompt": "put additional prompt here if rejected"
                    }}
                    ```
                    """.format(
                        agent=agent,
                        question=model.questions,
                        response=model.response
                    )

    @staticmethod
    def build_enhanced_prompt(agent: str, last_response: LongTermMemoryModel, audit_result: Dict) -> str:
        """
        Build a meta-prompt that asks another model step to improve the original
        prompt using the audit feedback.
        """
        return """
        **Original Prompt**:
        {prompt}

        **Audit Result**:
        {feedback}.
        **Reason**:
        {reason}.

        **Your Task**:
        Please enhance the original prompt by adding more details or examples so that the agent can better understand the task.

        **Output Format Requirements**:
        Provide your response in the following EXACT format (example):
        {{"Additional_Prompt": "put your additional prompt here"}}
        """.format(
            prompt=last_response.prompt,
            feedback=audit_result["feedback"],
            reason=audit_result["reason"]
        )

    @staticmethod
    def build_secondary_prompt(request, code_info, second_context: Dict, definition: Dict[str, RoleDefinition]):
        """
        Build the second-stage vulnerability prompt for a single suspicious candidate.

        This stage is more targeted than the initial inspection:
        it focuses on one candidate, one vulnerability type, and additional
        contextual evidence retrieved from the RAG store.
        """
        logger.info("building secondary prompt...")
        document_call_graphs = second_context["call_graphs"]
        document_cross_file_deps = second_context["cross_file_deps"]
        try:
            vuln_type = code_info["vulnerability_type"]
        except KeyError as e:
            vuln_type = code_info["vulnerability_type"]

        match(vuln_type):
            case "I/O Validation":
                vuln_parse_question = """
                    1. Will the code segment introduce ANY new security vulnerabilities caused by I/O Validation?
                    2. Focus ONLY on new I/O Validation vulnerabilities that may be introduced by the commit.
                    3. Check if all user inputs are properly validated for type, length, and format.
                    4. Verify boundary conditions and edge cases are handled.
                    5. Trace user input from entry points to sensitive operations.
                    6. Identify any unsanitized data reaching critical functions.
                """
                audit_question = """
                    Will the code segment introduce ANY new security vulnerabilities caused by I/O Validation?
                """
            case "Memory Safety":
                vuln_parse_question = """
                    1. Will the code segment introduce ANY new security vulnerabilities caused by Memory Safety?
                    2. Focus ONLY on new Memory Safety vulnerabilities that may be introduced by the commit.
                    3. Analyze all buffer accesses for proper bounds checking.
                    4. Verify string operations use safe functions (strncpy vs strcpy).
                    5. Check for off-by-one errors and boundary conditions.
                    6. Validate pointer arithmetic and dereferencing.
                    7. Check for null pointer dereferences.
                    8. Verify pointer validity before use.
                    9. Identify memory allocation/deallocation pairs.
                    10. Check for double-free, use-after-free vulnerabilities.
                    11. Analyze memory initialization before use.
                    12. Check for integer overflows/underflows.
                    13. Verify size calculations and type conversions.
                    14. Analyze loop termination conditions.
                    15. Identify race conditions in memory access.
                    16. Check proper locking mechanisms for shared memory.
                """
                audit_question = """
                    Will the code segment introduce ANY new security vulnerabilities caused by Memory Safety?
                """
            case "Web Security":
                vuln_parse_question = """
                    1. Will the code segment introduce ANY new security vulnerabilities caused by Web Security?
                    2. Focus ONLY on new Web Security vulnerabilities that may be introduced by the commit.
                    3. Check for XSS, HTML injection, CRLF injection, XML external entity (XXE) injection, client-side or server-side script execution, remote code execution, SQL injection, denial of service (DoS), information leakage, sensitive data exposure, etc.
                """
                audit_question = """
                    Will the code segment introduce ANY new security vulnerabilities caused by Web Security?
                """
            case "Authn/Authz":
                vuln_parse_question = """
                    1. Will the code segment introduce ANY new security vulnerabilities caused by Authn/Authz?
                    2. Focus ONLY on new Authn/Authz vulnerabilities that may be introduced by the commit.
                    3. Check if authentication can be bypassed.
                    4. Identify missing authorization checks.
                    5. Verify permission enforcement at all access points.
                    6. Check for horizontal/vertical privilege escalation.
                """
                audit_question = """
                    Will the code segment introduce ANY new security vulnerabilities caused by Authn/Authz?
                """
            case "Resource Management":
                vuln_parse_question = """
                    1. Will the code segment introduce ANY new security vulnerabilities caused by Resource Management?
                    2. Focus ONLY on new Resource Management vulnerabilities that may be introduced by the commit.
                    3. Identify all resources acquisition points (files, connections, memory).
                    4. Verify proper release in all code paths (including error cases)
                    5. Check for resource exhaustion possibilities.
                    6. Analyze race conditions in resource access.
                    7. Verify proper locking mechanisms.
                    8. Check for deadlock possibilities.
                    9. Verify resource cleanup in exception handlers.
                    10. Validate resource creation/destruction pairs.
                    11. Check for resource reuse safety.
                """
                audit_question = """
                    Will the code segment introduce ANY new security vulnerabilities caused by Resource Management?
                """
            case "File/Path Handling":
                vuln_parse_question = """
                    1. Will the code segment introduce ANY new security vulnerabilities caused by File/Path Handling?
                    2. Focus ONLY on new File/Path Handling vulnerabilities that may be introduced by the commit.
                    3. Analyze all file path constructions.
                    4. Verify path sanitization and validation.
                    5. Check for directory traversal possibilities.
                    6. Verify safe file creation and access patterns.
                    7. Check file permission settings.
                    8. Analyze symbolic link handling.
                    9. Verify secure temporary file creation.
                    10. Check for predictable temporary file names.
                    11. Analyze temporary file cleanup.
                    12. Verify filename and path validation.
                    13. Check for null byte injections.
                    14. Analyze filesystem boundary enforcement.
                """
                audit_question = """
                    Will the code segment introduce ANY new security vulnerabilities caused by File/Path Handling?
                """
            case _:
                raise ValueError(f"Unknown vulnerability type: {vuln_type}")

        prompt = """
        **Description**: {description}

        **Commit Review Task**:
        1. File Context
        {commit_context}
        2. Suspicious Code Segment
        {code_segment}
        3. More Contextual information
        - call graphs
        {document_call_graphs}
        
        - data flow
        {document_cross_file_deps}
        4. Similar Cases
        {similar_cases}

        **Question**:
        {question}

        **Output Format Requirements**:
        Provide your response in the following EXACT format (example), and do NOT include any additional text before or after this block:
        ```json
        {{"is_vulnerability": "Yes/No", "reason": "Put your reason here.", "CWE_category": "CWE-128"}}
        ```
        """.format(
            description=definition[AgentType.VULNERABILITY_INSPECTOR].description,
            code_segment=code_info["code_segment"],
            commit_context=request.repo_context,
            reason=code_info["reason"],
            document_call_graphs=document_call_graphs,
            document_cross_file_deps=document_cross_file_deps,
            similar_cases=second_context["similar_cases"],
            question=vuln_parse_question
        )

        return prompt, audit_question, vuln_type

    @staticmethod
    def build_voting_prompt(request: CommitReviewRequest, potential_code, secondary_result, session: SessionModel,
                            definition: Dict[str, RoleDefinition]) -> Tuple[str, str]:
        """
        Build the final verification prompt for a candidate that passed secondary inspection.

        This prompt is stricter than the earlier stages. Its goal is not to
        maximize recall, but to confirm whether the candidate is truly supported
        by concrete code evidence introduced by the commit.
        """
        questions = """
        1. Determine whether a new vulnerability exists.
        2. If a vulnerability exists, please provide the cwe type.
        """
        # 构建投票提示
        prompt = """
        You are performing the final verification of a vulnerability candidate identified in previous analysis stages.

        Your task is to determine whether the reported code fragment truly represents a vulnerability introduced by this commit.

        **Vulnerability Review Task**:
        1. **Code Changes** (Diff): 
        {diff}
        2. **Commit Context**: 
        {repo_context}
        3. **Secondary Review Result**:
            suspicious code segment: {code_segment}
            reason: {reason}
            cwe_type: {cwe}

        Verification checklist:

        1. Confirm whether the risky behavior is actually introduced by this commit rather than being pre-existing code.
        2. Determine whether the suspicious fragment can realistically lead to a security impact.
        3. Check whether there is a plausible trigger path (input, state, or control flow) that reaches the risky operation.
        4. If the code is safe due to validation, bounds checks, or restricted usage, the candidate should be rejected.
        5. Reject the candidate if the reasoning is speculative and not supported by code evidence.

        Decision rules:

        - Output **Yes** only if the vulnerability is supported by concrete code behavior.
        - Output **No** if the candidate is unsupported, purely hypothetical, or unrelated to the commit.

        **Output Format Requirements**:
        Provide your response in the following EXACT format (example) and please strictly output in the json format as shown in the output example. Do not output any extra information.:
        ```json
        {{
            "is_vulnerability": "yes/no",
            "cwe_category": "CWE-xxx",
            "confidence": "high/medium/low"
        }}
        ```
        """.format(
            role=definition[AgentType.VULNERABILITY_INSPECTOR].role,
            description=definition[AgentType.VULNERABILITY_INSPECTOR].description,
            diff=request.diff,
            repo_context=request.repo_context,
            code_segment=potential_code,
            reason=secondary_result["reason"],
            cwe=secondary_result["CWE_category"]
        )
        return prompt, questions

    @staticmethod
    def build_report_prompt(request: CommitReviewRequest, session: SessionModel, analysis_results: Dict) -> str:
        """
        Build the final report-generation prompt from all intermediate analysis outputs.

        The report prompt aggregates agent responses and the final vulnerability
        inspection results so that the documentation stage can produce a
        human-readable security review report.
        """
        return """
                Generate a comprehensive security review report for commit {commit_id}.

                Analysis Results:
                {analysis_results}

                Vulnerability Inspection Results:
                {vuln_inspection_results}

                **Output Requirements**:
                1. Executive Summary
                2. Detailed Findings
                """.format(
            commit_id=request.commit_id,
            analysis_results=json.dumps(analysis_results, indent=4),
            vuln_inspection_results=json.dumps(session.vuln_inspection_results, indent=4)
        )
