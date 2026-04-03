import asyncio
import argparse
import json
import json.decoder
import os
import sys
from pathlib import Path

import openai
import pandas as pd
from loguru import logger

from core.data_loader import load_commit
from core.metrics import Metrics
from core.multi_agent_review_system import MultiAgentReviewSystem
from core.direct_agent_review_system import DirectAgentReviewSystem
from core.cot_agent_review_system import CotAgentReviewSystem
from core.rag_db_handler import RagDbHandler


DATASET_PATH = "data/V-SZZ_dataset.csv"
PROGRESS_FILE = "progress/main_progress.txt"
RESULT_FILE = "progress/result.txt"
LOG_FILE = "logs/log.log"
ERROR_COMMITS_FILE = "progress/error_commits.txt"
TP_COMMITS_FILE = "progress/true_positive_commits.txt"

def setup_logger():
    logger.remove()

    Path("logs").mkdir(parents=True, exist_ok=True)
    Path("progress").mkdir(parents=True, exist_ok=True)

    log_format_console = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    log_format_file = (
        "{time:YYYY-MM-DD HH:mm:ss} | "
        "{level: <8} | "
        "{process.name}:{thread.name} | "
        "{name}:{function}:{line} | "
        "{message}"
    )

    logger.add(
        sys.stdout,
        level='INFO',
        format=log_format_console,
        colorize=True,
        backtrace=True,
        diagnose=True
    )

    logger.add(
        LOG_FILE,
        level='DEBUG',
        format=log_format_file,
        rotation="100 MB",
        retention="1000 days",
        encoding="utf-8",
        backtrace=True,
        diagnose=False
    )

    logger.info("Logger setup completed.")
    logger.debug(f"Log file path: {LOG_FILE}")

def load_progress() -> list:
    all_processed_commits = []
    try:
        if not os.path.exists(PROGRESS_FILE):
            logger.warning(f"Progress file not found: {PROGRESS_FILE}. Returning empty progress.")
            return []
        with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                processed_commit = line.strip()
                if not processed_commit:
                    continue
                all_processed_commits.append(processed_commit)
        logger.debug(f"Loaded {len(all_processed_commits)} processed commits from progress file.")
        return all_processed_commits
    except Exception:
        logger.exception(f"Failed to load progress file {PROGRESS_FILE}.")
        return []

def save_progress(commit_hash: str):
    try:
        Path(PROGRESS_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(PROGRESS_FILE, 'a', encoding='utf-8') as f:
            f.write(commit_hash + '\n')
        logger.debug(f"Saved progress for commit: {commit_hash}")
    except Exception:
        logger.exception(f"Failed to save progress for commit {commit_hash} to file {PROGRESS_FILE}.")
        raise

def load_dataset(csv_path: str):
    """
    Load the CSV dataset and convert it into a list of record dictionaries.
    
    Expected columns:
    - commit_id
    - repo
    - cve
    - cwe
    - label
    """
    logger.info(f"Loading dataset from: {csv_path}")

    try:
        df = pd.read_csv(csv_path)
        logger.info(f"Dataset loaded successfully. Total rows: {len(df)}")   # 309

        required_columns = {"commit_id", "repo", "cve", "cwe", "label"}
        missing_columns = required_columns - set(df.columns)
        if missing_columns:
            logger.error(f"Dataset is missing required columns: {missing_columns}")
            raise ValueError(f"Dataset is missing required columns: {missing_columns}")
        
        logger.debug(f"Dataset columns: {list(df.columns)}")
        return df.to_dict(orient="records")

    except Exception:
        logger.exception(f"Failed to load dataset from {csv_path}.")
        raise

def load_true_positive_commits() -> set[str]:
    try:
        if not os.path.exists(TP_COMMITS_FILE):
            logger.warning(f"True positive commits file not found: {TP_COMMITS_FILE}. Returning empty set.")
            return set()
        
        with open(TP_COMMITS_FILE, 'r', encoding='utf-8') as f:
            tp_commits = {line.strip() for line in f if line.strip()}
        
        logger.info(f"Loaded {len(tp_commits)} true positive commits from {TP_COMMITS_FILE}.")
        return tp_commits
    except Exception:
        logger.exception(f"Failed to load true positive commits from file {TP_COMMITS_FILE}.")
        raise

def save_true_positive_commits(commit_hash: str):
    try:
        Path(TP_COMMITS_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(TP_COMMITS_FILE, 'a', encoding='utf-8') as f:
            f.write(commit_hash + '\n')
        logger.debug(f"Saved true positive commit: {commit_hash}")
    except Exception:
        logger.exception(f"Failed to save true positive commit {commit_hash} to file {TP_COMMITS_FILE}.")
        raise

def load_error_commits() -> set[str]:
    try:
        if not os.path.exists(ERROR_COMMITS_FILE):
            logger.warning(f"Error commits file not found: {ERROR_COMMITS_FILE}. Returning empty set.")
            return set()
        
        with open(ERROR_COMMITS_FILE, 'r', encoding='utf-8') as f:
            error_commits = {line.strip() for line in f if line.strip()}
        
        logger.info(f"Loaded {len(error_commits)} error commits from {ERROR_COMMITS_FILE}.")
        return error_commits
    except Exception:
        logger.exception(f"Failed to load error commits from file {ERROR_COMMITS_FILE}.")
        raise

def save_error_commits(commit_hash: str):
    try:
        Path(ERROR_COMMITS_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(ERROR_COMMITS_FILE, 'a', encoding='utf-8') as f:
            f.write(commit_hash + '\n')
        logger.debug(f"Saved error commit: {commit_hash}")
    except Exception:
        logger.exception(f"Failed to save error commit {commit_hash} to file {ERROR_COMMITS_FILE}.")
        raise

class Solution:
    @staticmethod
    async def run_detection(method: str, strategy: str):
        logger.info(f"Detection started. method={method}, strategy={strategy}")

        dataset = load_dataset(DATASET_PATH)

        # Load bookkeeping files so the pipeline can resume safely after interruption.
        processed_commits = set(load_progress())
        processed_count = len(processed_commits)

        # Keep track of true positives so their related RAG/vector data can be preserved during cleanup.
        true_positive_commits = load_true_positive_commits()

        # Trigger periodic cleanup to control disk usage and preserve true positive data during long-running experiments.
        processed_since_last_cleanup = 0
        
        # Commits that previously failed to load or process are skipped in later runs.
        error_commits = load_error_commits()

        logger.info(f"Already processed commits: {processed_count}")
        logger.info(f"Total commits in dataset: {len(dataset)}")   # 309

        # Metrics are updated incrementally after each processed sample.
        metrics = Metrics(RESULT_FILE)
        logger.debug(f"Metrics initialized with result file: {RESULT_FILE}")

        for idx, item in enumerate(dataset, start=1):
            repo = item["repo"]

            processing_commit = item["commit_id"].strip()
            cve = item["cve"].strip()
            cwe = item["cwe"].strip()
            ground_truth_flag = int(item["label"])

            logger.info("-" * 100)
            logger.info(f"Index: {idx}, Repo: {repo}, Commit: {processing_commit}, CVE: {cve}, CWE: {cwe}, Label: {ground_truth_flag}")

            processed_commits = set(load_progress())
            if processing_commit in processed_commits:
                logger.info("Commit already processed, skipping.")
                continue

            if processing_commit in error_commits:
                logger.info("Commit already processed in error_commits.txt, skipping.")
                continue
            
            logger.debug(f"Loading commit content for commit {processing_commit}")
            try:
                commit_review_request = load_commit(processing_commit)
            # If commit content is not in UTF-8, it will be skipped.
            except Exception:
                logger.exception(f"Failed to load commit content for commit {processing_commit}.")
                if processing_commit not in error_commits:
                    save_error_commits(processing_commit)
                    error_commits.add(processing_commit)
                continue

            if commit_review_request is None:
                logger.warning("This commit file does not exist, skipping.")
                if processing_commit not in error_commits:
                    save_error_commits(processing_commit)
                    error_commits.add(processing_commit)
                continue

            logger.debug(
                f"Commit content loaded successfully for commit {processing_commit}. "
                "Starting review..."
            )

            if strategy == 'multi':
                async with MultiAgentReviewSystem() as service_agent:
                    logger.debug("Using MultiAgentReviewSystem")
                    result = await Solution._run_review(service_agent, method, commit_review_request)
            elif strategy == 'direct':
                async with DirectAgentReviewSystem() as service_agent:
                    logger.debug("Using DirectAgentReviewSystem")
                    result = await Solution._run_review(service_agent, method, commit_review_request)
            elif strategy == 'cot':
                async with CotAgentReviewSystem() as service_agent:
                    logger.debug("Using CotAgentReviewSystem")
                    result = await Solution._run_review(service_agent, method, commit_review_request)
            else:
                logger.error(f'Invalid strategy specified. Please choose from ["multi", "direct", "cot"].')
                raise ValueError(f'Invalid strategy specified. Please choose from ["multi", "direct", "cot"].')

            if result is None:
                logger.error(f"Failed to get review result for commit {processing_commit}.")
                continue

            logger.debug(f"Review result for commit {processing_commit}: {result}")
            
            # Normalize the result to ensure consistent boolean values.
            normalized_result = dict(result)
            raw_pred = normalized_result.get("vuln_detected", False)

            if isinstance(raw_pred, str):
                normalized_result["vuln_detected"] = raw_pred.strip().lower() == 'yes'
            else:
                normalized_result["vuln_detected"] = bool(raw_pred)

            metrics.update(normalized_result, ground_truth_flag, cwe)

            metrics.log()
            metrics.save()
            logger.debug("Metrics logged and saved successfully.")

            save_progress(processing_commit)

            logger.info(f"Finished processing commit {processing_commit}.")

            predicted_positive = normalized_result.get("vuln_detected", False)
            is_true_positive = predicted_positive and (ground_truth_flag == 1)

            if is_true_positive:
                if processing_commit not in true_positive_commits:
                    save_true_positive_commits(processing_commit)
                    true_positive_commits.add(processing_commit)
                logger.info(f"True positive commit recorded: {processing_commit}")
            else:
                logger.debug(
                    f"Not a true positive. commit_id={processing_commit}, "
                    f"predicted_positive={predicted_positive}, ground_truth_flag={ground_truth_flag}"
                )
            
            # Count processed samples and periodically clean intermediate RAG/vector data.
            processed_since_last_cleanup += 1
            
            # Cleanup is triggered every 5 processed samples.
            if processed_since_last_cleanup >= 5:
                logger.info("*" * 20)
                logger.info(
                    f"Cleanup triggered after {processed_since_last_cleanup} samples. "
                    f"Keeping {len(true_positive_commits)} TP commits."
                )

                RagDbHandler.cleanup_rag_and_vector(keep_commit_ids=true_positive_commits)

                processed_since_last_cleanup = 0

                logger.info("RAG and vector databases cleaned up successfully.")
                logger.info("*" * 20)

            # logger.info("---------------------------------------------------------------------------------------------")
        
        logger.info("=" * 100)

        logger.info("Running final cleanup for RAG/VECTOR directories...")
        RagDbHandler.cleanup_rag_and_vector(keep_commit_ids=true_positive_commits)

        logger.info("Detection finished.")
            
    @staticmethod
    async def _run_review(service_agent, llm_type: str, commit_review_request):
        llm_type_map = {
            "deepseek_v3": "deepseek",
            "gpt-4o-mini": "gpt-4o-mini",
            "qwen-plus": "Qwen",
        }

        if llm_type not in llm_type_map:
            logger.error(f'Invalid llm type specified. Please choose from ["deepseek_v3", "gpt-4o-mini", "qwen-plus"].')
            raise ValueError(f'Invalid llm type specified. Please choose from ["deepseek_v3", "gpt-4o-mini", "qwen-plus"].')
        
        try:
            result = await service_agent.review_commit(commit_review_request, llm_type=llm_type_map[llm_type])
            logger.info(f"Review completed for commit {commit_review_request.commit_id}")
            return result
        except openai.BadRequestError:
            logger.exception(f"OpenAI BadRequestError occurred for commit={commit_review_request.commit_id}.")
            return None
        except json.decoder.JSONDecodeError:
            logger.exception(f"JSON decode error for commit={commit_review_request.commit_id}.")
            return None


if __name__ == "__main__":
    """
        Before starting a new detection run, make sure that:

        1. The dataset file is prepared.
        2. progress/main_progress.txt is prepared:
           - keep existing content to resume a previous run, or
           - clear/delete it to start from scratch.
        3. The progress/result.txt file is prepared or cleared as needed.
        4. The RAG database is prepared or empty.
        5. The VECTOR database is prepared or empty.
        6. The progress/error_commits.txt file is prepared or empty.
        7. The progress/true_positive_commits.txt file is prepared or empty.
        8. The progress/cost.txt file is prepared or empty.
    """

    setup_logger()
    parser = argparse.ArgumentParser(description="Run vulnerability detection on given commit(s).")
    parser.add_argument("-method", "--method", required=False, choices=['deepseek_v3', 'gpt-4o-mini', 'qwen-plus'], default='deepseek_v3',
                        help="Method to use for detecting vulnerabilities.")
    parser.add_argument("-strategy", "--strategy", required=False, choices=['multi', 'direct', 'cot'], default='multi',
                        help="Strategy to use for detecting vulnerabilities.")
    args = parser.parse_args()
    asyncio.run(Solution.run_detection(args.method, args.strategy))
