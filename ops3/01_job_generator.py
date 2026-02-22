# Databricks notebook source
# MAGIC %md
# MAGIC # Job Generator
# MAGIC 31개의 룰(Detection)에 대해 각각 고유한 개별 Databricks Job을 생성합니다. (1 Job = 1 Task 구조)

# COMMAND ----------
import requests

# Databricks API 통신을 위한 Host & Token 획득
ctx = dbutils.notebook.entry_point.getDbutils().notebook().getContext()
host = ctx.apiUrl().get()
token = ctx.apiToken().get()

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# TODO: 실제 노트북이 위치한 경로로 수정해야 합니다 (예: /Workspace/Repos/user/repo/ops3/02_single_runner)
runner_notebook_path = "/Workspace/Repos/your_repo/ops3/02_single_runner"

# COMMAND ----------
# 1. Active detection rule 조회 
rules_df = spark.sql("""
    SELECT rule_id, rule_group
    FROM sandbox.audit_poc.rule_registry
    WHERE enabled = true
""")
rules = rules_df.collect()

print(f"Loaded {len(rules)} active rules from registry.")

# COMMAND ----------
# 2. Iterate through rules and create Jobs
for r in rules:
    rule_id = r["rule_id"]
    rule_group = r["rule_group"]
    
    # Prefix format you can customize
    job_name = f"Audit_Detection_{rule_id}"
    
    # Define Job payload
    # 단일 Task로 구성되며, 파라미터(window_start_ts, window_end_ts, severity)를 정의합니다.
    job_payload = {
        "name": job_name,
        "tasks": [
            {
                "task_key": f"run_{rule_id}",
                "notebook_task": {
                    "notebook_path": runner_notebook_path,
                    "base_parameters": {
                        "rule_id": rule_id,
                        "window_start_ts": "", # 런타임에 주입받거나, 기본값을 설정할 수 있습니다.
                        "window_end_ts": "",
                        "severity": "medium"   # Default severity
                    }
                },
                # For demo purposes, we define a small Serverless/Generic job cluster.
                # 운영 환경에 맞춰 existing_cluster_id를 쓰거나 Worker Type을 변경하세요.
                "job_cluster_key": "audit_job_cluster",
            }
        ],
        "job_clusters": [
            {
                "job_cluster_key": "audit_job_cluster",
                "new_cluster": {
                    "spark_version": "13.3.x-scala2.12",
                    "node_type_id": "i3.xlarge", 
                    "num_workers": 1
                }
            }
        ],
        "tags": {
            "rule_group": rule_group,
            "pipeline": "audit_poc"
        }
    }
    
    resp = requests.post(
        f"{host}/api/2.1/jobs/create",
        headers=headers,
        json=job_payload
    )
    
    if resp.status_code == 200:
        job_id = resp.json().get("job_id")
        print(f"Created Job for [{rule_id}] - Job ID: {job_id}")
    else:
        print(f"Failed to create job for [{rule_id}]: {resp.text}")

print("Job generation completed.")
