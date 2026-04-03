#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clone repositories from the V-SZZ dataset and copy the source files
associated with each target commit into a local context directory.
"""

import os
import time
import subprocess

def sort_txt_file(input_file, output_file):
    """
    Clone repositories from the V-SZZ dataset and copy the source files
    associated with each target commit into a local context directory.
    """
    with open(input_file, 'r') as f:
        lines = f.readlines()   # owner/repo/commit_id
    sorted_lines = sorted(set(lines))
    with open(output_file, 'w') as f:
        f.writelines(sorted_lines)

def safe_clone_repo(owner, repo, max_retries=10):
    """
    Clone a GitHub repository with retry support.

    Retries are used to tolerate transient network failures or temporary
    GitHub-side issues during large-scale dataset collection.
    """
    url = f"https://github.com/{owner}/{repo}.git"

    for attempt in range(1, max_retries + 1):
        print(f"[Clone Attempt {attempt}/{max_retries}] {owner}/{repo}")
        try:
            subprocess.run(["git", "clone", url], check=True, timeout=1200)
            return True
        except subprocess.TimeoutExpired:
            print(f"[Clone Attempt {attempt}/{max_retries}] Timeout expired for {owner}/{repo}")
        except subprocess.CalledProcessError as e:
            print(f"[Clone Attempt {attempt}/{max_retries}] Failed to clone {owner}/{repo}: {e}")
        time.sleep(5)
    return False

def clone_repositories(repo_FILE_PATH):
    """
    Clone repositories and collect commit-specific context files.

    For each entry in the repository list:
    1. Check whether the commit has already been processed.
    2. Verify that the corresponding file list exists.
    3. Reuse or switch the local repository checkout as needed.
    4. Checkout the target commit.
    5. Copy the files listed in the commit file list into the local
       context directory for downstream analysis.
    """
    current_repository = None
    processed_commits = load_processed_commits()

    with open(repo_FILE_PATH, 'r') as f:
        for line in f:
            info = line.strip()
            owner, repo, commit_id = info.split('/')
            if commit_id in processed_commits:
                print(f"Commit {commit_id} has been processed, skip.")
                continue

            if os.path.exists(f"/home/root/V-SZZ_data_commits/{commit_id}"):
                print(f"Commit {commit_id} has been processed, skip.")
                processed_commits.add(commit_id)
                save_processed_commits(processed_commits)
                continue

            print(f"Cloning {owner}/{repo}/{commit_id}")

            # The file list must already exist because it defines which source
            # files should be copied for the target commit context.
            filename_file = f"/home/root/V-SZZ_commits/{commit_id}---filelist.txt"
            print(f"Now checking filename file for {filename_file}")
            if not os.path.exists(filename_file):
                print("Filename file not exists.")
                with open("/home/root/data/V-SZZ_filename_file_not_exists.txt", "a") as f:
                    f.write(f"{owner}/{repo}/{commit_id}\n")
                continue
            
            
            # Use a shared repository workspace and switch repositories only
            # when the current entry belongs to a different repo.
            os.chdir("/home/root/repository")

            if current_repository is None:
                current_repository = repo
            if repo != current_repository:
                print(f"Now delete old repository {current_repository}")
                if os.path.exists(current_repository):
                    subprocess.run(["rm", "-rf", current_repository], check=True)
                current_repository = repo

            if not os.path.exists(repo):
                print(f"Now clone new repository {repo}")
                success = safe_clone_repo(owner, repo)
                if not success:
                    print(f"Repository {owner}/{repo} clone FAILED. Skipping this repository.")
                    with open("/home/root/data/V-SZZ_clone_failed_repos.txt", 'a') as f:
                        f.write(f"{owner}/{repo}\n")
                    current_repository = None
                    os.chdir("/home/root")
                    continue
            else:
                print(f"Repository {repo} already exists, skipping clone.")
            
            os.chdir(f"/home/root/repository/{repo}")
            
            # Checkout the exact commit so the copied files match the historical
            # repository state associated with the dataset entry.
            try:
                subprocess.run(["git", "checkout", commit_id], check=True)
            except subprocess.CalledProcessError:
                os.chdir("/home/root")
                print(f"Fail to checkout commit {commit_id}")
                with open("/home/root/data/V-SZZ_checkout_fail.txt", "a") as f:
                    f.write(f"{owner}/{repo}/{commit_id}\n")
                processed_commits.add(commit_id)
                save_processed_commits(processed_commits)
                continue
            
            target_dir = f"/home/root/V-SZZ_data_commits/{commit_id}"
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)
            
            # Read the file list and copy the corresponding source files into
            # the commit-specific context directory.
            with open(filename_file, 'r') as f:
                filenames = f.readlines()
            for filename in filenames:
                filename = filename.strip()
                print(f"Now get copy file {filename}")
                
                source_file = f"/home/root/repository/{repo}/{filename}"
                if not os.path.exists(source_file):
                    print(f"Source file {source_file} not exists. Skipping...")
                    continue
                subprocess.run(["cp", source_file, target_dir], check=True)
                print(f"Successfully copy file {filename} to {commit_id}")
            os.chdir("/home/root")
            processed_commits.add(commit_id)
            save_processed_commits(processed_commits)
                
def save_processed_commits(processed_commits):
    """
    Save processed commit IDs so the script can resume from previous runs.
    """
    with open("/home/root/data/processed_V-SZZ_commits.txt", "w") as f:
        for commit in processed_commits:
            f.write(f"{commit}\n")

def load_processed_commits():
    """
    Load the set of already processed commit IDs.

    Returns:
        set: Commit IDs that have already been collected.
    """
    processed_commits = set()
    try:
        with open("/home/root/data/processed_V-SZZ_commits.txt", "r") as f:
            for line in f:
                commit = line.strip()
                processed_commits.add(commit)
    except FileNotFoundError:
        pass
    return processed_commits
    

if __name__ == "__main__":
    """
    Script entry point for cloning repositories and collecting commit context.
    """
    repo_FILE_PATH = "/home/root/data/V-SZZ_Repository.txt"
    sort_txt_file(repo_FILE_PATH, repo_FILE_PATH)
    clone_repositories(repo_FILE_PATH)
