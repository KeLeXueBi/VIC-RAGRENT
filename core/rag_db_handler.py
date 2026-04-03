import os
from typing import List, Set
from loguru import logger
from models.impl.commit_review_request import CommitReviewRequest
from transformers import AutoTokenizer, AutoModel
import torch
from torch import nn
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

# Load the tokenizer once at module import time and reuse it across all
# retrieval and storage operations.
tokenizer = AutoTokenizer.from_pretrained("./mycodebert")

class RagDbHandler:
    @staticmethod
    def rag_db_query(request: CommitReviewRequest, vuln_type: str, rag_db: str = 'RAG_DIR', vector_db: str = 'VECTOR_DIR', threshold: float = 0.85):
        """
        Retrieve the most similar historical report for the given commit and
        vulnerability category.

        The current commit diff is first encoded into a vector, then compared
        against all stored vectors under the same vulnerability type. The report
        corresponding to the highest-similarity vector is returned only if the
        similarity exceeds a predefined threshold.
        """
        vuln_type = vuln_type.replace("'", "")
        vuln_type = vuln_type.replace(" ", "_")
        vuln_type = vuln_type.replace("/", "-")
        documents = []
        vector_path = os.path.join(vector_db, vuln_type)
        db_path = os.path.join(rag_db, vuln_type)
        if not os.path.exists(db_path):
            return None

        use_cuda = torch.cuda.is_available()
        device = torch.device("cuda" if use_cuda else "cpu")
        logger.info(f"Device: {device}")
        code_token = tokenizer.encode_plus(str(request.diff), padding='max_length', max_length=512, truncation=True, return_tensors="pt")
        
        # Move tokenized inputs to the same device as the encoder model.
        code_token = {k: v.to(device) for k, v in code_token.items()}  # 将张量移动到设备上
        
        model = CommitEncoder()
        model.to(device)

        model.eval()
        vector = model(code_token)
        vector = vector.detach().cpu().numpy()

        vector = vector.reshape(1, -1)

        vector_dict = {}
        for vector_file in os.listdir(vector_path):
            rag_vector = np.load(os.path.join(vector_path, vector_file))
            commit_file_path = os.path.join(vector_path, vector_file)
            rag_vector = rag_vector.reshape(1, -1)
            sim = cosine_similarity(vector, rag_vector)[0][0]
            vector_dict[commit_file_path] = sim

        if not vector_dict:
            return None
        
        max_sim_commit_file_path, max_sim = max(vector_dict.items(), key=lambda x:x[1])

        # Use a strict similarity threshold to avoid injecting weakly related
        # historical cases into the secondary inspection prompt.
        if max_sim < threshold:
            return None

        commit_vector_file_path = os.path.basename(max_sim_commit_file_path)
        commit = commit_vector_file_path[:-4]
        commit_document_file = f"{commit}.txt"

        with open(os.path.join(db_path, commit_document_file), 'r') as f:
            content = f.read()
            documents.append(content)

        return documents

    @staticmethod
    def store_to_rag(request: CommitReviewRequest, document: str, vuln_type: str, rag_db: str = 'RAG_DIR'):
        """
        Store the final report under the corresponding vulnerability category.

        After the report is saved, the associated commit diff is also encoded
        and written to the vector store for future similarity-based retrieval.
        """
        vuln_type = vuln_type.replace("'", "")
        vuln_type = vuln_type.replace(" ", "_")
        vuln_type = vuln_type.replace("/", "-")
        logger.info(f"Store to RAG: {request.commit_id}, vuln type is {vuln_type}.")
        if not os.path.exists(os.path.join(rag_db, vuln_type)):
            os.makedirs(os.path.join(rag_db, vuln_type))
        with open(os.path.join(rag_db, vuln_type, f"{request.commit_id}.txt"), 'w') as file:
            file.write(document)
        logger.info(f"Store to RAG: {request.commit_id} successfully.")

        # Store the corresponding vector representation for later retrieval.
        RagDbHandler.store_code_vector(request, vuln_type)

    @staticmethod
    def store_code_vector(request: CommitReviewRequest, vuln_type: str, vector_db: str = 'VECTOR_DIR'):
        """
        Encode the commit diff into a vector representation and save it to disk.
        """
        vuln_type = vuln_type.replace("'", "")
        vuln_type = vuln_type.replace(" ", "_")
        vuln_type = vuln_type.replace("/", "-")
        use_cuda = torch.cuda.is_available()
        device = torch.device("cuda" if use_cuda else "cpu")
        logger.info(f"Device: {device}")

        logger.info("Store the code vector...")
        code_token = tokenizer.encode_plus(str(request.diff), padding='max_length', max_length=512, truncation=True, return_tensors="pt")
        
        # Move tokenized inputs to the same device as the encoder model.
        code_token = {k: v.to(device) for k, v in code_token.items()}  # 将张量移动到设备上

        model = CommitEncoder()
        model.to(device)

        model.eval()
        outputs = model(code_token)

        # 将向量存储到文件中
        vector_path = os.path.join(vector_db, vuln_type)
        if not os.path.exists(vector_path):
            os.makedirs(vector_path)
        vector_file = os.path.join(vector_path, f"{request.commit_id}.npy")
        np.save(vector_file, outputs.detach().cpu().numpy().squeeze())
        logger.info(f"Vector saved at {vector_file}")

    @staticmethod
    def cleanup_rag_and_vector(
        keep_commit_ids: Set[str],
        rag_db: str = "RAG_DIR",
        vector_db: str = "VECTOR_DIR"
    ):
        """
        Remove RAG reports and vectors whose commit IDs are not in the retained set.

        In the current pipeline, `keep_commit_ids` is expected to contain
        commit IDs of predicted true positives, so only useful retrieval
        knowledge is preserved across cleanup cycles.
        """
        logger.info(f"Start cleanup for RAG/VECTOR directories. keep count={len(keep_commit_ids)}")

        removed_rag_files = 0
        removed_vector_files = 0

        # Remove report files that should no longer be retained.
        if os.path.exists(rag_db):
            for vuln_type in os.listdir(rag_db):
                vuln_dir = os.path.join(rag_db, vuln_type)
                if not os.path.isdir(vuln_dir):
                    continue

                for filename in os.listdir(vuln_dir):
                    file_path = os.path.join(vuln_dir, filename)
                    if not os.path.isfile(file_path):
                        continue
                    if not filename.endswith(".txt"):
                        continue
                    
                    commit_id = filename[:-4]
                    if commit_id not in keep_commit_ids:
                        try:
                            os.remove(file_path)
                            removed_rag_files += 1
                            logger.debug(f"Removed RAG file: {file_path}")
                        except Exception:
                            logger.exception(f"Failed to remove RAG file: {file_path}")
        
        # Remove vector files that should no longer be retained.
        if os.path.exists(vector_db):
            for vuln_type in os.listdir(vector_db):
                vuln_dir = os.path.join(vector_db, vuln_type)
                if not os.path.isdir(vuln_dir):
                    continue

                for filename in os.listdir(vuln_dir):
                    file_path = os.path.join(vuln_dir, filename)
                    if not os.path.isfile(file_path):
                        continue
                    if not filename.endswith(".npy"):
                        continue
                    
                    commit_id = filename[:-4]
                    if commit_id not in keep_commit_ids:
                        try:
                            os.remove(file_path)
                            removed_vector_files += 1
                            logger.debug(f"Removed VECTOR file: {file_path}")
                        except Exception:
                            logger.exception(f"Failed to remove VECTOR file: {file_path}")

        logger.info(
            f"Cleanup finished. removed_rag_files={removed_rag_files}, "
            f"removed_vector_files={removed_vector_files}, keep_commit_ids={len(keep_commit_ids)}"
        )


class CommitEncoder(nn.Module):
    def __init__(self):
        """
        Load the pretrained CodeBERT-based encoder used for commit-diff embedding.
        """
        super(CommitEncoder, self).__init__()
        self.bert = AutoModel.from_pretrained("./mycodebert")

    def forward(self, inputs):
        """
        Encode the input token batch and return the [CLS] representation
        as the commit-level embedding.
        """
        input_ids = inputs['input_ids']
        attention_mask = inputs['attention_mask']

        # Ensure the input tensors are placed on the same device as the model.
        device = next(self.bert.parameters()).device
        input_ids = input_ids.to(device)
        attention_mask = attention_mask.to(device)

        bert_output = self.bert(input_ids=input_ids, attention_mask=attention_mask, return_dict=False)[0]
        cls = bert_output[:, 0, :]
        return cls
