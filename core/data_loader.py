import os
from pathlib import Path
from models.impl.commit_review_request import CommitReviewRequest
from loguru import logger
from typing import Optional

"""
Example data layout:

context: /home/root/data_commits/<commit_id>/arch/x86/kernel/cpu/bugs.c
msg: /home/root/commits/<commit_id>---message.txt
diff: /home/root/commits/<commit_id>---bugs.c.txt
"""

# Base directories for the local commit data.
context_dir = "/home/root/V-SZZ_data_commits"
message_dir = "/home/root/V-SZZ_commits"
diff_dir = "/home/root/V-SZZ_commits"

def get_context_file_list(commit_id) -> list:
    # Recursively collect all context files associated with the given commit.
    file_list = []
    commit_path = os.path.join(context_dir, commit_id)
    commit_path = Path(commit_path)
    for file_path in commit_path.rglob('*'):
        if file_path.is_file():
            file_name = file_path.relative_to(commit_path)
            file_list.append(str(file_name))
    return file_list

def get_context_content(commit_id, file_list) -> str:
    """
    Load and concatenate repository context files for a commit.

    Each file is prefixed with its filename so downstream prompts can keep
    track of which content comes from which source file.
    """
    commit_path = os.path.join(context_dir, commit_id)
    content_dict = {}
    for file_path in file_list:
        # 去掉路径，只保留文件名
        file_name = os.path.basename(file_path)
        with open(os.path.join(commit_path, file_path), 'r') as f:
            content = f.read()
        content_dict[file_name] = content
    content = ""
    for file_name, file_content in content_dict.items():
        content += "filename: {}\n".format(file_name)
        content += file_content + "\n\n"
    return content

def get_message_content(commit_id) -> str:
    # Load the commit message for the given commit.
    commit_path = os.path.join(message_dir, f"{commit_id}---message.txt")
    with open(commit_path, 'r') as f:
        content = f.read()
    return content

def get_diff_content(commit_id, file_list) -> str:
    """
    Load and concatenate per-file diff content for a commit.

    The diff files are matched by filename using the local dataset naming
    convention: <commit_id>---<file_name>.txt
    """
    commit_path = os.path.join(context_dir, commit_id)
    content_dict = {}
    for file_path in file_list:
        file_name = os.path.basename(file_path)
        diff_path = os.path.join(diff_dir, f"{commit_id}---{file_name}.txt")
        with open(diff_path, 'r') as f:
            content = f.read()
        content_dict[file_name] = content
    content = ""
    for file_name, file_content in content_dict.items():
        content += "filename: {}\n".format(file_name)
        content += file_content + "\n\n"
    return content

def get_commit_review_request(commit_id) -> Optional[CommitReviewRequest]:
    """
    Assemble a CommitReviewRequest from the local dataset files.

    If any required file is missing or unreadable, return None so the caller
    can skip this commit gracefully.
    """
    try:
        file_list = get_context_file_list(commit_id)
        context = get_context_content(commit_id, file_list)
        message = get_message_content(commit_id)
        diff = get_diff_content(commit_id, file_list)
        request = CommitReviewRequest(commit_id=commit_id, message=message, diff=diff, repo_context=context)
        return request
    except Exception as e:
        logger.error(f"Failed to load commit {commit_id}: {e}")
        return None

def load_commit(commit_id) -> Optional[CommitReviewRequest]:
    # Convenience wrapper for loading a commit review request.
    return get_commit_review_request(commit_id)
