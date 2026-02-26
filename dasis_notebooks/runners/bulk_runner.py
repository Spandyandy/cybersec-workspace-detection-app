# Databricks notebook source
# MAGIC %md
# MAGIC # Bulk Job Runner
# MAGIC `pipeline: audit_poc` 태그가 달린 현존하는 모든 Security Detection Job들을 한 번에 실행시킵니다.  
# MAGIC 타겟 `rule_group`을 선택하여 실행할 수 있으며, 선택적 매개변수를 통해 개별 Job의 기본 Parameter(`window_start_ts`, `severity` 등)를 임시로 덮어쓰기(Override)할 수 있습니다.
# MAGIC 입력값이 비어있다면, Job에 원래 세팅되어 있는 기본 파라미터를 그대로 사용하여 동작합니다.

# COMMAND ----------
from databricks.sdk import WorkspaceClient

w = WorkspaceClient()

# 1. Fetch distinct rule_groups from registry
rg_df = spark.sql("""
    SELECT DISTINCT rule_group 
    FROM sandbox.audit_poc.rule_registry 
    WHERE enabled = true AND rule_group IS NOT NULL
""")
rule_groups = [row["rule_group"] for row in rg_df.collect()]
rule_groups.insert(0, "ALL") # 'ALL' 옵션을 가장 앞에 추가

# 2. Define Bulk Runner Widgets
dbutils.widgets.dropdown("target_rule_group", "ALL", rule_groups) 
dbutils.widgets.dropdown("is_dry_run", "True", ["True", "False"])

# Optional Override Parameters
dbutils.widgets.text("run_window_start_ts", "")
dbutils.widgets.text("run_window_end_ts", "")
dbutils.widgets.text("run_severity", "")

target_rule_group = dbutils.widgets.get("target_rule_group").strip()
is_dry_run = dbutils.widgets.get("is_dry_run").strip() == "True"
run_window_start = dbutils.widgets.get("run_window_start_ts").strip()
run_window_end = dbutils.widgets.get("run_window_end_ts").strip()
run_severity = dbutils.widgets.get("run_severity").strip()

print(f"Target Group: {target_rule_group} | Dry Run: {is_dry_run}")
if run_window_start or run_window_end or run_severity:
    print(f"Override Parameters -> Start: '{run_window_start}', End: '{run_window_end}', Severity: '{run_severity}'")
else:
    print("Using Default Job Parameters.")

# COMMAND ----------
# 3. Retrieve All Relevant Jobs
all_jobs = w.jobs.list(expand_tasks=True)

audit_jobs = []
for j in all_jobs:
    # `pipeline: audit_poc` 태그가 있는 Job만 필터링
    if j.settings.tags and j.settings.tags.get("pipeline") == "audit_poc":
        rg = j.settings.tags.get("rule_group", "UNKNOWN")
        
        # 입력된 target 조건과 일치하는지 확인
        if target_rule_group == "ALL" or rg == target_rule_group:
            audit_jobs.append(j)

print(f"\nFound {len(audit_jobs)} jobs matching target_rule_group: '{target_rule_group}'")

if is_dry_run or len(audit_jobs) == 0:
    # Show Jobs to be affected (empty-safe)
    dry_run_rows = [
        {"job_id": j.job_id, "job_name": j.settings.name, "rule_group": j.settings.tags.get("rule_group")}
        for j in audit_jobs
    ]
    dry_run_schema = "job_id long, job_name string, rule_group string"
    dry_run_df = spark.createDataFrame(dry_run_rows, dry_run_schema) if dry_run_rows else spark.createDataFrame([], dry_run_schema)

    print("\n[DRY RUN] The following jobs would be triggered:")
    display(dry_run_df)
    dbutils.notebook.exit("DRY_RUN completed. Set is_dry_run to 'False' to trigger jobs.")

# COMMAND ----------
# 4. Trigger the Jobs Safely over the Cluster
success_runs = []
fail_runs = []

# Optional Override Dictionary Constructor
job_params_override = {}
if run_window_start:
    job_params_override["window_start_ts"] = run_window_start
if run_window_end:
    job_params_override["window_end_ts"] = run_window_end
if run_severity:
    job_params_override["severity"] = run_severity

for j in audit_jobs:
    try:
        # API 2.1 WorkspaceClient triggers Run-Now context
        if job_params_override:
            # Overrides are merged with Notebook tasks arguments
            # If job_parameters is present, Databricks replaces those specific fields dynamically per run.
            run_response = w.jobs.run_now(job_id=j.job_id, job_parameters=job_params_override)
        else:
            # Runs with existing configured Job Defaults
            run_response = w.jobs.run_now(job_id=j.job_id)
            
        success_runs.append({
            "job_id": j.job_id,
            "job_name": j.settings.name,
            "rule_group": j.settings.tags.get("rule_group"),
            "run_id": run_response.run_id # Triggered specific Run Instance ID
        })
        print(f"✅ Triggered Job [{j.settings.name}] -> Run ID: {run_response.run_id}")
        
    except Exception as e:
        fail_runs.append({
            "job_id": j.job_id,
            "job_name": j.settings.name,
            "error_message": str(e)
        })
        print(f"❌ Failed to trigger [{j.settings.name}]: {e}")

# COMMAND ----------
# 5. Summary View
print(f"\nSuccessfully Triggered: {len(success_runs)} | Failed: {len(fail_runs)}")

if success_runs:
    success_df = spark.createDataFrame(success_runs)
    display(success_df.orderBy("rule_group", "job_name"))

if fail_runs:
    fail_df = spark.createDataFrame(fail_runs)
    print("\n⚠️ Failed Run Attempts:")
    display(fail_df)
