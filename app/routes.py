from flask import Blueprint, render_template, request
import requests
import os

main = Blueprint('main', __name__)

ARTIFACTORY_URL = os.getenv('ARTIFACTORY_URL')
ARTIFACTORY_TOKEN = os.getenv('ARTIFACTORY_TOKEN')
ARTIFACTORY_VULNERABILITY_ENDPOINT = '/xray/api/v1/summary/artifact'

# Example xray response:
# {
#     "artifacts": [{
#         "general": {
#             "name": "example-image",
#             "version": "1.0.0"
#         },
#         "issues": [{
#             "issue_id": "XRAY-123456",
#             "summary": "This is a high severity vulnerability",
#             "description": "This is a high severity vulnerability",
#             "severity": "High",
#             "cves": [{cve: "CVE-2024-123456"}],
#             "impact_path": ["/path/to/impact/path"],
#         }]
#     }]
# }

@main.route("/", methods=["GET", "POST"])
def index():
    vulnerabilities = None
    if request.method == "POST":
        image = request.form.get("image")
        vulnerabilities = fetch_vulnerabilities(image)
    return render_template("index.html", vulnerabilities=vulnerabilities)

def fetch_vulnerabilities(image_name):
    """
    Fetch vulnerabilities for the given Docker image using the Artifactory summary API.
    """
    headers = {
        "Authorization": f"Bearer {ARTIFACTORY_TOKEN}",
        "Content-Type": "application/json"
    }
    # The payload for the summary API
    payload = {
        "components": [
            {"component_id": f"docker://{image_name}"}
        ]
    }

    try:
        response = requests.post(ARTIFACTORY_URL + ARTIFACTORY_VULNERABILITY_ENDPOINT, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = parse_vulnerabilities(data)
        return vulnerabilities
    except requests.RequestException as e:
        print(f"Error fetching vulnerabilities: {e}")
        return None

def parse_vulnerabilities(data):
    """
    Extract and format vulnerabilities from the API response.
    """
    vulnerabilities = []
    for artifact in data.get("artifacts", []):
        for issue in artifact.get("issues", []):
            vulnerabilities.append({
                "issue_id": issue.get("issue_id", "Unknown"),
                "summary": issue.get("summary", "No summary provided"),
                "description": issue.get("description", "No description provided"),
                "severity": issue.get("severity", "Unknown"),
                "cves": [cve.get("cve", "Unknown") for cve in issue.get("cves", [])],
                "impact_path": issue.get("impact_path", [])
            })
    return vulnerabilities