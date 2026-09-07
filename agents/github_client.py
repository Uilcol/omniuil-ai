"""
OmniUil AI Agents — Cliente GitHub (somente leitura)
"""
import requests
from config import GITHUB_TOKEN, GITHUB_REPO

HEADERS = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"} if GITHUB_TOKEN else {}
BASE = f"https://api.github.com/repos/{GITHUB_REPO}"

def get_issues(state="open", limit=10):
    r = requests.get(f"{BASE}/issues", headers=HEADERS, params={"state":state,"per_page":limit})
    if r.status_code != 200: return []
    return [{"number":i["number"],"title":i["title"],"body":(i["body"]or"")[:500],"labels":[l["name"] for l in i["labels"]]} for i in r.json()]

def get_readme():
    r = requests.get(f"{BASE}/readme", headers=HEADERS)
    if r.status_code != 200: return ""
    import base64
    return base64.b64decode(r.json()["content"]).decode("utf-8", errors="ignore")[:3000]

def get_latest_release():
    r = requests.get(f"{BASE}/releases/latest", headers=HEADERS)
    if r.status_code != 200: return {}
    d = r.json()
    return {"tag":d.get("tag_name",""),"name":d.get("name",""),"body":(d.get("body",""))[:500]}

def get_recent_commits(limit=5):
    r = requests.get(f"{BASE}/commits", headers=HEADERS, params={"per_page":limit})
    if r.status_code != 200: return []
    return [{"sha":c["sha"][:7],"message":c["commit"]["message"][:100],"date":c["commit"]["author"]["date"]} for c in r.json()]
