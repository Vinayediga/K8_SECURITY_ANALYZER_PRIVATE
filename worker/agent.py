import logging
import os
import time

import requests
from dotenv import load_dotenv

from worker.extract_graph import extract_graph

load_dotenv()

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
CLUSTER_ID = os.getenv("AGENT_CLUSTER_ID", "")
KUBE_CONTEXT = os.getenv("KUBE_CONTEXT", "")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))
APPROVED_CONTEXTS = {
    "6acb966b1de5db3b53e43130": "kind-k8s-security-lab",
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("k8s-agent")

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {AGENT_TOKEN}",
    "Content-Type": "application/json",
})


def claim_job():
    response = session.post(
        f"{API_URL}/agent/jobs/claim",
        timeout=30,
    )
    response.raise_for_status()
    return response.json().get("job")


def report_failure(job_id, message):
    response = session.post(
        f"{API_URL}/agent/jobs/{job_id}/fail",
        json={"error": message[:1000]},
        timeout=30,
    )
    response.raise_for_status()


def process_job(job):
    job_id = job["id"]

    try:
        if job.get("cluster_id") != CLUSTER_ID:
            raise ValueError("Job cluster does not match configured cluster")

        if job.get("scan_type") != "scan_cluster":
            raise ValueError("Unsupported scan type")

        context = APPROVED_CONTEXTS.get(job["cluster_id"])

        if not context:
            raise ValueError(
                "Cluster has no locally approved Kubernetes context"
            )

        logger.info("Starting scan job %s", job_id)

        graph = extract_graph(context=context)

        if not isinstance(graph, dict):
            raise ValueError("Extractor did not return graph data")

        response = session.post(
            f"{API_URL}/agent/jobs/{job_id}/complete",
            json={"graph": graph},
            timeout=120,
        )
        response.raise_for_status()

        logger.info("Scan job %s completed", job_id)

    except Exception as exc:
        logger.exception("Scan job %s failed", job_id)

        try:
            report_failure(job_id, str(exc))
        except requests.RequestException:
            logger.exception("Could not report job failure")

def main():
    if not all([AGENT_TOKEN, CLUSTER_ID, KUBE_CONTEXT]):
        raise SystemExit(
            "Configure AGENT_TOKEN, AGENT_CLUSTER_ID and KUBE_CONTEXT"
        )

    logger.info("Agent started for cluster %s", CLUSTER_ID)

    while True:
        try:
            job = claim_job()

            if job:
                process_job(job)
            else:
                time.sleep(POLL_INTERVAL)

        except requests.RequestException:
            logger.exception("Backend request failed")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()