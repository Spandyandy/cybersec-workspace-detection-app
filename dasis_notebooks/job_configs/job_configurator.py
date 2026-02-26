# Databricks notebook source
# MAGIC %md
# MAGIC # Global Job Configurator
# MAGIC `pipeline: audit_poc` 태그가 달린 모든 Databricks Job을 스캔하고 모니터링합니다.  
# MAGIC 특정 `rule_group` 단위로 Job Parameter, Cron Schedule, Pause Status 등을 일괄(Bulk) 업데이트할 수 있습니다.

# COMMAND ----------

from databricks.sdk import WorkspaceClient
from databricks.sdk.service import jobs

w = WorkspaceClient()

# 1. Fetch distinct rule_groups from registry
rg_df = spark.sql("""
    SELECT DISTINCT rule_group 
    FROM sandbox.audit_poc.rule_registry 
    WHERE enabled = true AND rule_group IS NOT NULL
""")
rule_groups = [row["rule_group"] for row in rg_df.collect()]
rule_groups.insert(0, "ALL") # 'ALL' 옵션을 가장 앞에 추가

# 2. Define Bulk Update Widgets
dbutils.widgets.dropdown("target_rule_group", "ALL", rule_groups) 
dbutils.widgets.dropdown("action_type", "DRY_RUN", ["DRY_RUN", "UPDATE_PARAMS", "UPDATE_SCHEDULE", "PAUSE_JOBS", "UNPAUSE_JOBS"])

# Parameters for UPDATE_PARAMS
dbutils.widgets.text("new_window_start_ts", "")
dbutils.widgets.text("new_window_end_ts", "")
dbutils.widgets.text("new_severity", "")

# Parameters for UPDATE_SCHEDULE
dbutils.widgets.text("new_cron_expression", "")  # e.g., "0 0 * * * ?" (매일 자정)

target_rule_group = dbutils.widgets.get("target_rule_group").strip()
action_type = dbutils.widgets.get("action_type").strip()
new_window_start = dbutils.widgets.get("new_window_start_ts").strip()
new_window_end = dbutils.widgets.get("new_window_end_ts").strip()
new_severity = dbutils.widgets.get("new_severity").strip()
new_cron = dbutils.widgets.get("new_cron_expression").strip()

print(f"Target Group: {target_rule_group} | Action: {action_type}")

# COMMAND ----------

# DBTITLE 1,Jobs Parameters & Configs
# 2. Scan and Display All Relevant Jobs
all_jobs = w.jobs.list(expand_tasks=True)

audit_jobs = []
for j in all_jobs:
    # `pipeline: audit_poc` 태그가 있는 Job만 필터링
    if j.settings.tags and j.settings.tags.get("pipeline") == "audit_poc":
        rg = j.settings.tags.get("rule_group", "UNKNOWN")
        
        # 스케줄 정보 파싱
        schedule_status = "UNSCHEDULED"
        pause_status = "N/A"
        if j.settings.schedule:
            schedule_status = j.settings.schedule.quartz_cron_expression
            pause_status = j.settings.schedule.pause_status.value

        # Base Parameters 파싱 (단일 Task 가정)
        base_params = {}
        if j.settings.tasks and len(j.settings.tasks) > 0:
            task = j.settings.tasks[0]
            if task.notebook_task and task.notebook_task.base_parameters:
                base_params = task.notebook_task.base_parameters
                
        audit_jobs.append({
            "job_id": j.job_id,
            "job_name": j.settings.name,
            "rule_group": rg,
            "schedule": schedule_status,
            "status": pause_status,
            "rule_id": base_params.get("rule_id", ""),
            "window_start": base_params.get("window_start_ts", ""),
            "window_end": base_params.get("window_end_ts", ""),
            "severity": base_params.get("severity", "")
        })

# 상태 출력 (empty-safe)
jobs_schema = "job_id long, job_name string, rule_group string, schedule string, status string, rule_id string, window_start string, window_end string, severity string"
if audit_jobs:
    jobs_df = spark.createDataFrame(audit_jobs, jobs_schema)
else:
    jobs_df = spark.createDataFrame([], jobs_schema)
display(jobs_df.orderBy("rule_group", "job_name"))

# COMMAND ----------

# 3. Filter Target Jobs for Bulk Action
target_jobs = []
for j in audit_jobs:
    if target_rule_group == "ALL" or j["rule_group"] == target_rule_group:
        target_jobs.append(j["job_id"])

print(f"\nFound {len(target_jobs)} jobs matching target_rule_group: '{target_rule_group}'")

if action_type == "DRY_RUN" or len(target_jobs) == 0:
    dbutils.notebook.exit("DRY_RUN - 변경없음.")

# COMMAND ----------

# 4. Execute Bulk Update Actions
success_count = 0

for j_id in target_jobs:
    try:
        # 기존 Job Settings 조회
        current_job = w.jobs.get(job_id=j_id)
        new_settings = current_job.settings
        
        updated = False
        
        if action_type == "UPDATE_PARAMS":
            if new_settings.tasks and len(new_settings.tasks) > 0:
                task = new_settings.tasks[0]
                if task.notebook_task and task.notebook_task.base_parameters is not None:
                    # Update parameters if explicit value is given
                    if new_window_start:
                        task.notebook_task.base_parameters["window_start_ts"] = new_window_start
                        updated = True
                    if new_window_end:
                        task.notebook_task.base_parameters["window_end_ts"] = new_window_end
                        updated = True
                    if new_severity:
                        task.notebook_task.base_parameters["severity"] = new_severity
                        updated = True

        elif action_type == "UPDATE_SCHEDULE":
            if new_cron:
                # 스케줄이 없었던 경우 새로 객체 생성
                if not new_settings.schedule:
                    new_settings.schedule = jobs.CronSchedule(
                        quartz_cron_expression=new_cron,
                        timezone_id="UTC",
                        pause_status=jobs.PauseStatus.UNPAUSED
                    )
                else:
                    new_settings.schedule.quartz_cron_expression = new_cron
                updated = True
                
        elif action_type == "PAUSE_JOBS":
            if new_settings.schedule:
                new_settings.schedule.pause_status = jobs.PauseStatus.PAUSED
                updated = True
                
        elif action_type == "UNPAUSE_JOBS":
            if new_settings.schedule:
                new_settings.schedule.pause_status = jobs.PauseStatus.UNPAUSED
                updated = True

        # 변경사항이 있으면 API 호출
        if updated:
            w.jobs.update(job_id=j_id, new_settings=new_settings)
            success_count += 1
            print(f"✅ Successfully updated Job {j_id}")

    except Exception as e:
        print(f"❌ Failed to update Job {j_id}: {e}")

print(f"\nBulk Update Complete: {success_count} / {len(target_jobs)} jobs successfully updated.")
