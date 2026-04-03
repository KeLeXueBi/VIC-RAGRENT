#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Collect repository/commit identifiers from the V-SZZ dataset and download
the corresponding commit message and patch files from GitHub.
"""

import os
import time
import json
import requests
import pandas as pd

# GitHub credentials. Using a token is recommended to reduce API rate-limit issues.
GITHUB_TOKEN = "YOUR TOKEN HERE"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

def get_all_V_SZZ_repository(file_PATH):
    """
    Extract unique repository/commit entries from the V-SZZ dataset and save
    them in the format: owner/repo/commit_id.
    """
    repositories = set()
    
    # 读取 CSV 文件为 DataFrame
    df = pd.read_csv(file_PATH)
    
    # 遍历 DataFrame 中的每一行
    for index, row in df.iterrows():
        # 从当前行中提取仓库名称
        repo = row["repo"]
        commit_id = row["commit_id"]
        # 将仓库名称添加到集合中，自动处理重复项
        repo = repo_name(repo)
        owner, repo = repo.split('/')
        repositories.add(f"{owner}/{repo}/{commit_id}")
    
    print(f"Total commits: {len(repositories)}")   # 311

    repositories = sorted(repositories)

    # 写入文件
    repositories = list(repositories)
    with open("data/V-SZZ_Repository.txt", "w") as f:
        for repo in repositories:
            f.write(repo + "\n")

def download_patch_files(repo_FILE_PATH):
    """
    Download commit metadata and patch files for all repository/commit entries.

    Progress is recorded so the script can resume from previous runs without
    re-downloading already processed commits.
    """
    with open(repo_FILE_PATH, 'r') as f:
        for line in f:
            progress = load_progress() or []
            info = line.strip()
            owner, repo, commit_id = info.split('/')

            if commit_id in progress:
                print(f"{commit_id} already processed")
                continue

            if os.path.exists(f"/home/root/V-SZZ_commits/{commit_id}---filelist.txt"):
                print(f"{commit_id} already downloaded")
                progress.append(commit_id)
                save_progress(progress)
                continue

            print(f"Downloading {owner}/{repo}/{commit_id}")

            api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_id}"

            for attempt in range(10, 0, -1):
                try:
                    response = requests.get(api_url, headers=HEADERS)
                    if response.status_code == 403:
                        print(f"Rate limited for {commit_id}. Sleeping for 2 seconds...")
                        time.sleep(2)
                        continue

                    if response.status_code == 404:
                        print(f"404 Not Found for {commit_id}. Moving to next commit.")
                        with open(f"/home/root/data/V-SZZ_Failed.txt", 'a', encoding='utf-8') as f:
                            f.write(f"{info}\n")
                        break

                    response.raise_for_status()
                    print(f"Successfully retrieved {commit_id}")
                    download_commit_files(response.json(), commit_id)
                    progress.append(commit_id)
                    save_progress(progress)
                    print(f"Successfully downloaded and saved {commit_id}")
                    time.sleep(2)
                    break

                except Exception as e:
                    print(f"Failed to download {commit_id} on attempt {attempt}: {e}")
                    if attempt == 1:
                        print(f"Max retries reached for {commit_id}. Moving to next commit.")
                        with open(f"/home/root/data/V-SZZ_Failed.txt", 'a', encoding='utf-8') as f:
                            f.write(f"{info}\n")
                    time.sleep(2)  # 等待 2 秒后重试

def download_commit_files(content, commit_id):
    """
    Save the commit message and per-file patch content for a GitHub commit.
    """
    print(f"Now collect commit info: {commit_id}")
    # 保存提交信息
    commit_msg = ""
    commit_msg = content["commit"]["message"]
    with open(f"V-SZZ_commits/{commit_id}---message.txt", 'w', encoding='utf-8') as f:
        f.write(commit_msg)

    # 保存文件变更
    files = content["files"]
    for file in files:
        filename = file["filename"]
        pure_filename = file["filename"].split("/")[-1]
        try:
            patch = file["patch"]
        except KeyError:
            continue
        with open(f"V-SZZ_commits/{commit_id}---filelist.txt", 'a', encoding='utf-8') as f:
            f.write(filename + '\n')
        with open(f"V-SZZ_commits/{commit_id}---{pure_filename}.txt", 'w', encoding='utf-8') as g:
            g.write(patch)

def save_progress(progress_data, filename="progress/V-SZZ_github_progress.json"):
    """
    Save processed commit IDs to a JSON progress file.
    """
    with open(filename, 'w') as f:
        json.dump(progress_data, f)

def load_progress(filename="progress/V-SZZ_github_progress.json"):
    """
    Load processed commit IDs from the progress file.

    Returns:
        list: Previously processed commit IDs, or an empty list if the file
        does not exist yet.
    """
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    else:
        return []

def count_commit_number(file_dir):
    """
    Count how many downloaded commits exist in the given directory.

    The count is based on files ending with `---message.txt`.
    """
    commit_number = 0
    for file in os.listdir(file_dir):
        if file.endswith("---message.txt"):
            commit_number += 1
    print(f"Total commit number: {commit_number}")

def repo_name(repo):
    """
    Map dataset-specific repository aliases to GitHub owner/repository names.
    """
    match repo:
        case 'activemq':
            name = 'apache/activemq'
        case 'commons-compress':
            name = 'apache/commons-compress'
        case 'cordova-plugin-file-transfer':
            name = 'apache/cordova-plugin-file-transfer'
        case 'cxf':
            name = 'apache/cxf'
        case 'lucene-solr':
            name = 'apache/lucene-solr'
        case 'shiro':
            name = 'apache/shiro'
        case 'struts':
            name = 'apache/struts'
        case 'tomcat':
            name = 'apache/tomcat'
        case 'xerces2-j':
            name = 'apache/xerces2-j'
        case 'blynk-server':
            name = 'Husayn1223/blynk-server'
        case 'buck':
            name = 'facebook/buck'
        case 'javamelody':
            name = 'javamelody/javamelody'
        case 'jenkins':
            name = 'jenkinsci/jenkins'
        case 'FFmpeg':
            name = 'FFmpeg/FFmpeg'
        case 'linux-kernel':
            name = 'linux-kernel'
        case 'OpenSSL':
            name = 'openssl/openssl'
        case 'php-src':
            name = 'php/php-src'
        case 'ImageMagick':
            name = 'ImageMagick/ImageMagick'
        case 'ovirt-engine':
            name = 'oVirt/ovirt-engine'
        case 'cxf-fediz':
            name = 'apache/cxf-fediz'
        case 'tikal-multijob-plugin':
            name = 'jenkinsci/jenkins-multijob-plugin'
        case 'spring-amqp':
            name = 'spring-projects/spring-amqp'
        case 'spring-framework':
            name = 'spring-projects/spring-framework'
        case 'undertow':
            name = 'undertow-io/undertow'
        case 'wildfly-core':
            name = 'wildfly/wildfly-core'
        case 'cayenne':
            name = 'apache/cayenne'
        case 'commons-fileupload':
            name = 'apache/commons-fileupload'
        case 'karaf':
            name = 'apache/karaf'
        case 'opentsdb':
            name = 'OpenTSDB/opentsdb'
        case 'spring-data-jpa':
            name = 'spring-projects/spring-data-jpa'
        case 'spring-security':
            name = 'spring-projects/spring-security'
        case 'vertx-web':
            name = 'vert-x3/vertx-web'
        case 'ccm-plugin':
            name = 'jenkinsci/ccm-plugin'
        case 'google-play-android-publisher-plugin':
            name = 'jenkinsci/google-play-android-publisher-plugin'
        case 'mercurial-plugin':
            name = 'jenkinsci/mercurial-plugin'
        case 'onos':
            name = 'opennetworkinglab/onos'
        case 'nifi':
            name = 'apache/nifi'
        case 'guava':
            name = 'google/guava'
        case 'spring-cloud-sso-connector':
            name = 'pivotal-cf/spring-cloud-sso-connector'
        case 'junit-plugin':
            name = 'jenkinsci/junit-plugin'
        case 'monitoring-plugin':
            name = 'jenkinsci/monitoring-plugin'
        case 'sonarqube':
            name = 'SonarSource/sonarqube'
        case 'retrofit':
            name = 'square/retrofit'
        case 'umlet':
            name = 'umlet/umlet'
        case _:
            raise Exception(f"Repo {repo} not found!")
    return name

if __name__ == "__main__":
    """
    Map dataset-specific repository aliases to GitHub owner/repository names.
    """
    file_PATH = "data/V-SZZ_dataset.csv"
    get_all_V_SZZ_repository(file_PATH)
    download_patch_files("data/V-SZZ_Repository.txt")
