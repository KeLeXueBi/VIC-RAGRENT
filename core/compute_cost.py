from loguru import logger
from models.impl.commit_review_request import CommitReviewRequest
from models.impl.session_model import SessionModel

COST_FILE = "progress/cost.txt"

def compute_cost(session: SessionModel, request: CommitReviewRequest, llm_type: str = 'deepseek'):
    if llm_type == 'deepseek':
        imput_price = 0.28 / 1000000     # 0.28$ per 1M tokens (cache miss)
        output_price = 0.42 / 1000000    # 0.42$ per 1M tokens

        cost = session.total_prompt_tokens * imput_price + session.total_completion_tokens * output_price
        latency_time = session.total_latency_time
        logger.info(
            f"[COMMIT COST] "
            f"commit={request.commit_id},"
            f"price={cost:.2f},"
            f"time_cost={latency_time:.2f}"
        )

        with open(COST_FILE, "a") as f:
            f.write(f"{request.commit_id},{cost:.2f},{latency_time:.2f}\n")

    else:
        logger.info(f"LLM {llm_type} not supported for cost calculation.")

def static_compute_cost(file):
    all_cost = 0.00
    time_cost = 0.00
    with open(file, "r") as f:
        for line in f:
            commit_id, cost, latency_time = line.strip().split(",")
            all_cost += float(cost)
            time_cost += float(latency_time)

    print(f"Total price: {all_cost:.2f}, total time cost: {time_cost:.2f}")
    print(f"average price: {all_cost / len(f):.2f}, average time cost: {time_cost / len(f):.2f}")


if __name__ == "__main__":
    static_compute_cost(COST_FILE)
