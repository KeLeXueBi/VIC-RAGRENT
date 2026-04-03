from loguru import logger
from models.impl.commit_review_request import CommitReviewRequest
from models.impl.session_model import SessionModel

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
COST_FILE = BASE_DIR / "progress" / "cost.txt"

PRICE_TABLE = {
    "deepseek": {     # USD per token (cache miss)
        "input_price": 0.28 / 1000000,
        "output_price": 0.42 / 1000000
    }
}

def compute_cost(session: SessionModel, request: CommitReviewRequest, llm_type: str = 'deepseek'):
    if llm_type not in PRICE_TABLE:
        logger.error(f"LLM {llm_type} not supported for cost calculation.")
        return
    
    input_price = PRICE_TABLE[llm_type]["input_price"]
    output_price = PRICE_TABLE[llm_type]["output_price"]

    prompt_tokens = getattr(session, "total_prompt_tokens", 0) or 0
    completion_tokens = getattr(session, "total_completion_tokens", 0) or 0
    latency_time = getattr(session, "total_latency_time", 0) or 0.00

    cost = prompt_tokens * input_price + completion_tokens * output_price

    logger.info(
        f"[COMMIT COST] "
        f"commit={request.commit_id}, "
        f"price={cost:.6f} USD, "
        f"time_cost={latency_time:.2f} s, "
        f"prompt_tokens={prompt_tokens}, "
        f"completion_tokens={completion_tokens}"
    )

    COST_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(COST_FILE, "a", encoding="utf-8") as f:
        f.write(f"{request.commit_id},{cost:.6f},{latency_time:.2f},{prompt_tokens},{completion_tokens}\n")

def static_compute_cost(cost_file: Path = COST_FILE):
    cost_file = Path(cost_file)

    if not cost_file.exists():
        logger.error(f"Cost file {cost_file} does not exist.")
        return
    
    all_cost = 0.00
    time_cost = 0.00
    num = 0

    with open(cost_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(",")
            if len(parts) != 5:
                logger.warning(f"Invalid line in cost file {cost_file}: {line}, skip it.")
                continue

            commit_id, cost, latency_time, prompt_tokens, completion_tokens = parts

            all_cost += float(cost)
            time_cost += float(latency_time)
            num += 1
    
    if num == 0:
        logger.warning(f"No valid cost records found.")
        return

    logger.info(f"Total price: {all_cost:.2f}, total time cost: {time_cost:.2f}")
    logger.info(f"average price: {all_cost / num:.2f}, average time cost: {time_cost / num:.2f}")


if __name__ == "__main__":
    static_compute_cost(COST_FILE)   # python -m core.compute_cost
