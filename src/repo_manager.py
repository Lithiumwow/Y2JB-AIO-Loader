import os
import json
import requests
import fnmatch

CONFIG_DIR = "static/config"
REPO_FILE = os.path.join(CONFIG_DIR, "repos.json")
PAYLOAD_DIR = "payloads"

def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_repos():
    if not os.path.exists(REPO_FILE):
        return {}
    try:
        with open(REPO_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_repos(data):
    ensure_dir(REPO_FILE)
    with open(REPO_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def add_repo_entry(name, data):
    repos = get_repos()
    repos[name] = data
    save_repos(repos)

def delete_repo_entry(name):
    repos = get_repos()
    if name in repos:
        del repos[name]
        save_repos(repos)

def get_github_asset_url(repo_name, asset_pattern, token=None):
    try:
        api_url = f"https://api.github.com/repos/{repo_name}/releases"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"
            
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        releases = response.json()
        for release in releases:
            assets = release.get('assets', [])
            for asset in assets:
                if fnmatch.fnmatch(asset['name'], asset_pattern):
                    print(f"Found {asset_pattern} in release: {release.get('tag_name')}")
                    return asset.get('url') if token else asset.get('browser_download_url')
        print(f"Asset {asset_pattern} not found in recent releases of {repo_name}")
        return None
    except Exception as e:
        print(f"GitHub API Error: {e}")
        return None

def download_file(url, save_path, token=None):
    ensure_dir(save_path)
    try:
        print(f"Downloading {url}...")
        headers = {}
        if token:
            headers["Authorization"] = f"token {token}"
            if "api.github.com" in url:
                headers["Accept"] = "application/octet-stream"

        with requests.get(url, headers=headers, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(save_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True, "Success"
    except Exception as e:
        return False, str(e)

def update_payloads(targets=['all']):
    repos = get_repos()
    results = {"success": True, "updated": [], "errors": []}
    for name, config in repos.items():
        if 'all' not in targets and name not in targets:
            continue
        print(f"Processing {name}...")
        download_url = None
        save_path = config.get('save_path')
        token = config.get('token')
        
        if save_path and save_path.lower().endswith('.elf'):
            filename = os.path.basename(save_path)
            save_path = os.path.join(PAYLOAD_DIR, 'elf', filename)

        if config.get('type') == 'direct':
            download_url = config.get('url')
        elif config.get('type') == 'release':
            repo = config.get('repo')
            pattern = config.get('asset_pattern')
            if repo and pattern:
                download_url = get_github_asset_url(repo, pattern, token)
            else:
                results['errors'].append(f"{name}: Missing repo/pattern config")
                continue
        if download_url and save_path:
            success, msg = download_file(download_url, save_path, token)
            if success:
                results['updated'].append(name)
            else:
                results['errors'].append(f"{name}: {msg}")
        else:
            results['errors'].append(f"{name}: URL not found")
    return results

if __name__ == "__main__":
    update_payloads()