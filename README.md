# Detecting Vulnerability-Inducing Commits via Multi-Stage Reasoning with LLM-Based Agents

## 1  Project Description
This project proposes an LLM-based multi-agent framework to determine whether a code commit introduces new security vulnerabilities.

## 2  Environment

- Ubuntu (other OSs may also work)
- Python: >= 3.11
- torch 2.6.0 (other versions may also work; must be installed manually, see below)

This project provides a reproducible environment configuration using `pyproject.toml` and `uv.lock`.

You can set up the environment using [uv](https://github.com/astral-sh/uv):

```bash
pip install uv
uv sync
```

Note:
- Due to platform-specific dependencies, **PyTorch and CUDA-related packages are not included** in `uv.lock`.
- Please install PyTorch manually according to your system configuration: https://pytorch.org/get-started/locally/
- This project requires PyTorch for code embedding (RAG module).

### Notes (Windows Compatibility)

On Windows systems, a `UnicodeEncodeError` may occur when saving LLM-generated content to files, because the default system encoding may not be UTF-8.

To avoid this issue, explicitly specify UTF-8 when writing files, for example:

```python
with open(path, "w", encoding="utf-8") as f:
    f.write(content)
```

### API Configuration

The API keys are **not included** in this repository.

Before running the system, please configure your API keys in `config.yaml`, for example:

```yaml
deepseek:
  api-key: "YOUR_API_KEY"
  api-url: "YOUR_API_URL"

openrouter:
  api-key: "YOUR_API_KEY"
  api-url: "YOUR_API_URL"

Qwen:
  api-key: "YOUR_API_KEY"
  api-url: "YOUR_API_URL"
```

## 3  Project Structure

| Directory   | Description                              |
|:------------|:-----------------------------------------|
| core        | Core implementation of the review system |
| data        | Dataset and role definitions             |
| enums       | Enum definitions                         |
| utils       | Utility modules                          |

## 4  Modules

### 4.1  core

| File                            | Description                                                |
|:--------------------------------|:-----------------------------------------------------------|
| `compute_cost.py`               | Calculate the cost and log the cost file.                  |
| `context_handler.py`            | Extract contextual information for vulnerability analysis  |
| `cot_agent_review_system.py`    | Chain-of-thought (CoT) review baseline                     |
| `data_loader.py`                | Load commit message, diff, and context                     |
| `direct_agent_review_system.py` | Direct single-agent review baseline                        |
| `llm_query_client.py`           | Interface for querying LLM APIs                            |
| `metrics.py`                    | Evaluation metrics computation                             |
| `multi_agent_review_system.py`  | Multi-agent collaborative review system                    | 
| `prompt_builder.py`             | Prompt construction module                                 | 
| `rag_db_handler.py`             | RAG-based storage and retrieval for vulnerability cases    |
| `response_parser.py`            | Parse LLM responses                                        |
| `session_handler.py`            | Agent execution workflow                                   |

---

### 4.2  data

| File                     | Description                 |
|:-------------------------|:----------------------------|
| `V-SZZ_dataset.csv`      | Dataset                     |
| `role_definition.json`   | Agent role definitions      |

---

### 4.3  utils

| File                                 | Description                                               |
|:-------------------------------------|:----------------------------------------------------------|
| `config_helper.py`                   | Load API configuration                                    |
| `definition_parser.py`               | Parse role definition                                     |

---

### 4.4  Root Files

| File           | Description                             |
|:---------------|:----------------------------------------|
| `config.yaml`  | API configuration                       |
| `main.py`      | Entry point for experiments             |

---

## 5  Pre-experiment Setup

Before running the system, please prepare the following directories:

| Directory            | Description                                                                                                                                 |
|:---------------------|:--------------------------------------------------------------------------------------------------------------------------------------------|
| `mycodebert`         | Pretrained CodeBERT model (download from [here](https://huggingface.co/mrm8488/codebert-base-finetuned-detect-insecure-code/tree/main))     |
| `logs`               | Log output directory                                                                                                                        |
| `progress`           | Progress tracking (clear for a fresh run)                                                                                                   |
| `RAG_DIR`            | Storage for retrieved vulnerability reports                                                                                                 |
| `VECTOR_DIR`         | Storage for vectorized commit representations                                                                                               |
| `V-SZZ_commits`      | Commit diffs and messages                                                                                                                   |
| `V-SZZ_data_commits` | Source code context for each commit                                                                                                         |

---

## 6 Preparation

### 6.1  Collect Commit Data

Run the following scripts to prepare commit data:

```bash
python get_all_V-SZZ_repository.py
python get_context_V-SZZ.py
```

Notes:
- Set your GitHub API token in `get_all_V-SZZ_repository.py`
- `get_context_V-SZZ.py` contains hard-coded file paths; adjust them to your environment

---

### 6.2  Configuration Adjustments

You may need to update the following paths:

| File                     | Description         |
|:-------------------------|:--------------------|
| `core/data_loader.py`    | Dataset path        |
| `utils/config_helper.py` | config file path    |
| `config.yaml`            | API settings        |

---

## 7  Running the System

```bash
python main.py -method deepseek_v3 -strategy multi
```

---

## 8. Method Overview

This project implements three different vulnerability detection strategies:

- **Direct Reviewer**: A single-agent baseline that directly predicts whether a commit introduces a vulnerability.
- **CoT Reviewer**: A chain-of-thought baseline that performs step-by-step reasoning before making a decision.
- **Multi-Agent Framework**: A collaborative system involving multiple agents (e.g., code analyst, target architect, vulnerability inspector) with staged analysis, auditing, and retrieval augmentation.

The multi-agent framework is designed to improve both detection accuracy and interpretability through structured reasoning and iterative verification.
