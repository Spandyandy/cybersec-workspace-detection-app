# Databricks notebook source
# MAGIC %md
# MAGIC # Job Generator
# MAGIC 31개의 룰(Detection)에 대해 각각 고유한 개별 Databricks Job을 생성합니다. (1 Job = 1 Task 구조)

# COMMAND ----------
# Databricks Python SDK를 사용하여 Job 생성
from databricks.sdk import WorkspaceClient
from databricks.sdk.service import jobs
from databricks.sdk.service import compute

# 노트북의 현재 컨텍스트를 사용하여 WorkspaceClient 자동 인증
w = WorkspaceClient()

nb_path = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
repo_ws_root = "/".join(nb_path.split("/")[:4])          # e.g., /Repos/<user>/<repo>
runner_notebook_path = f"{repo_ws_root}/ops3/02_single_runner"

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
    try:
        created_job = w.jobs.create(
            name=job_name,
            tags={
                "rule_group": rule_group,
                "pipeline": "audit_poc"
            },
            # Serverless Compute를 사용하기 위해 job_clusters 지정 및 task 내 클러스터 할당을 생략합니다.
            tasks=[
                jobs.Task(
                    task_key=f"run_{rule_id}",
                    notebook_task=jobs.NotebookTask(
                        notebook_path=runner_notebook_path,
                        base_parameters={
                            "rule_id": rule_id,
                            "window_start_ts": "", # 런타임에 주입받거나, 기본값을 설정할 수 있습니다.
                            "window_end_ts": "",
                            "severity": "medium"   # Default severity
                        }
                    ),
                    libraries=[
                        compute.Library(pypi=compute.PythonPyPiLibrary(package="geoip2")),
                        compute.Library(pypi=compute.PythonPyPiLibrary(package="netaddr"))
                    ]
                )
            ]
        )
        print(f"Created Job for [{rule_id}] - Job ID: {created_job.job_id}")
    except Exception as e:
        print(f"Failed to create job for [{rule_id}]: {e}")

print("Job generation completed.")
