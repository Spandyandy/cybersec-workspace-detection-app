# Databricks notebook source
# MAGIC %md
# MAGIC # 01_register_rules
# MAGIC Python 룰 모듈(노트북)들을 `sandbox.audit_poc.rule_registry` 테이블에 등록합니다.

# COMMAND ----------

import re
import os
from datetime import datetime, timezone

# repo root
nb_path = (
    dbutils.notebook.entry_point.getDbutils()
    .notebook()
    .getContext()
    .notebookPath()
    .get()
)
repo_ws_root = "/".join(nb_path.split("/")[:4])   # /Repos/<user>/<repo>
repo_fs_root = f"/Workspace{repo_ws_root}"

def extract_callable_name(py_file_text: str, fallback: str) -> str:
    """
    룰 파일에서 첫 번째 top-level def 이름을 찾아 callable_name으로 사용.
    못 찾으면 fallback(rule_id) 사용.
    """
    m = re.search(r"(?m)^\s*def\s+([A-Za-z_]\w*)\s*\(", py_file_text)
    return m.group(1) if m else fallback

rows = []
for rule_group, lookback in [("binary", 1440), ("behavioral", 43200), ("custom", 1440)]:
    folder_fs = f"{repo_fs_root}/base/detections/{rule_group}"
    
    if os.path.exists(folder_fs):
        for fname in sorted(os.listdir(folder_fs)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue

            rule_id = fname[:-3]
            # Databricks 원본 노트북 직접 호출 (materialized_py 미사용)
            module_path = f"{repo_ws_root}/base/detections/{rule_group}/{rule_id}"

            with open(f"{folder_fs}/{fname}", "r", encoding="utf-8") as f:
                text = f.read()

            callable_name = extract_callable_name(text, fallback=rule_id)

            rows.append((rule_id, True, rule_group, module_path, callable_name, lookback))

df = spark.createDataFrame(
    rows,
    "rule_id string, enabled boolean, rule_group string, module_path string, callable_name string, lookback_minutes int"
)
df.createOrReplaceTempView("new_rules")

# created_at / updated_at은 현재시각으로 채움(없으면 MERGE에서 NULL 이슈)
spark.sql("""
MERGE INTO sandbox.audit_poc.rule_registry t
USING new_rules s
ON t.rule_id = s.rule_id
WHEN MATCHED THEN UPDATE SET
  t.enabled = s.enabled,
  t.rule_group = s.rule_group,
  t.module_path = s.module_path,
  t.callable_name = s.callable_name,
  t.updated_at = current_timestamp()
WHEN NOT MATCHED THEN INSERT (
  rule_id, enabled, rule_group, module_path, callable_name,
  severity, created_at, updated_at
) VALUES (
  s.rule_id, s.enabled, s.rule_group, s.module_path, s.callable_name,
  NULL, current_timestamp(), current_timestamp()
)
""")

display(spark.sql("SELECT rule_group, COUNT(*) cnt FROM sandbox.audit_poc.rule_registry GROUP BY rule_group ORDER BY rule_group"))
display(spark.sql("SELECT rule_id, rule_group, module_path, callable_name, enabled FROM sandbox.audit_poc.rule_registry ORDER BY rule_group, rule_id"))


# COMMAND ----------

# MAGIC %sql
# MAGIC INSERT INTO sandbox.audit_poc.rule_checkpoint (
# MAGIC   rule_id,
# MAGIC   last_success_end_ts,
# MAGIC   last_attempt_start_ts,
# MAGIC   last_attempt_end_ts,
# MAGIC   last_status,
# MAGIC   last_error,
# MAGIC   updated_at
# MAGIC )
# MAGIC SELECT
# MAGIC   r.rule_id,
# MAGIC   NULL,
# MAGIC   NULL,
# MAGIC   NULL,
# MAGIC   NULL,
# MAGIC   NULL,
# MAGIC   current_timestamp()
# MAGIC FROM sandbox.audit_poc.rule_registry r
# MAGIC LEFT ANTI JOIN sandbox.audit_poc.rule_checkpoint c
# MAGIC ON r.rule_id = c.rule_id;

# COMMAND ----------

# MAGIC %md
# MAGIC # 02_job_generator
# MAGIC 등록된 Detection 룰을 바탕으로 각각 고유한 개별 Databricks Job을 생성합니다. (1 Job = 1 Task 구조)

# COMMAND ----------

# Databricks Python SDK를 사용하여 Job 생성
from databricks.sdk import WorkspaceClient
from databricks.sdk.service import jobs
from databricks.sdk.service import compute
from datetime import datetime

# 위젯으로 keep_history 옵션 받기 (디폴트는 false)
try:
    dbutils.widgets.dropdown("keep_history", "false", ["false", "true"], "Keep previous jobs")
    keep_history_str = dbutils.widgets.get("keep_history").strip().lower()
except Exception:
    keep_history_str = "false"

keep_history = keep_history_str in ["true", "1", "t", "yes", "y"]

# 노트북의 현재 컨텍스트를 사용하여 WorkspaceClient 자동 인증
w = WorkspaceClient()

runner_notebook_path = f"{repo_ws_root}/dasis_notebooks/runners/single_runner"

# 1. Active detection rule 조회 
rules_df = spark.sql("""
    SELECT rule_id, rule_group
    FROM sandbox.audit_poc.rule_registry
    WHERE enabled = true
""")
rules = rules_df.collect()

print(f"Loaded {len(rules)} active rules from registry.")
print(f"Option keep_history: {keep_history}")

# COMMAND ----------

# 2. Iterate through rules and create Jobs
current_dt_str = datetime.now().strftime("%Y%m%d_%H%M%S")

for r in rules:
    rule_id = r["rule_id"]
    rule_group = r["rule_group"]
    
    # Prefix format you can customize
    base_job_name = f"Audit_Detection_{rule_id}"
    
    if keep_history:
        job_name = f"{base_job_name}_{current_dt_str}"
    else:
        job_name = base_job_name
    
    # Define Job payload
    # 단일 Task로 구성되며, 파라미터(window_start_ts, window_end_ts, severity)를 정의합니다.
    try:
        if not keep_history:
            # 기존에 생성된 동일한 이름의 Job을 찾아 삭제하여 replace 효과를 냄
            for existing_job in w.jobs.list(name=job_name):
                print(f"Deleting existing job: {existing_job.job_id} ({job_name})")
                w.jobs.delete(job_id=existing_job.job_id)

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
                    )
                )
            ]
        )
        print(f"Created Job for [{rule_id}] - Job ID: {created_job.job_id}")
    except Exception as e:
        print(f"Failed to create job for [{rule_id}]: {e}")

print("Job generation completed.")

