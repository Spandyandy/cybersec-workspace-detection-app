# Databricks notebook source
# MAGIC %md
# MAGIC # Single Runner
# MAGIC 단일 Detection 룰을 실행하며, Dedupe 여부를 파악한 뒤 개별 Delta Table과 Unified Delta Table에 MERGE 합니다.

# COMMAND ----------
import builtins
import time
import sys
import pyspark.sql.functions as F
from delta.tables import DeltaTable

# 1. Define and parse Input Parameters
# 필수 파라미터인 window_start_ts, window_end_ts, severity를 주입 받습니다.
dbutils.widgets.text("rule_id", "")
dbutils.widgets.text("window_start_ts", "")
dbutils.widgets.text("window_end_ts", "")
dbutils.widgets.text("severity", "Medium")

rule_id = dbutils.widgets.get("rule_id").strip()
window_start_ts = dbutils.widgets.get("window_start_ts").strip()
window_end_ts = dbutils.widgets.get("window_end_ts").strip()
severity = dbutils.widgets.get("severity").strip()

if not rule_id:
    raise ValueError("rule_id is required parameter")

run_id = f"{rule_id}_{int(time.time())}"
print(f"Starting run for rule_id: {rule_id} | Window: {window_start_ts} ~ {window_end_ts} | Severity: {severity}")

# COMMAND ----------
# 2. Add dependencies and Materialized Py root path to sys.path
# 노트북의 Base Root를 맞추기 위한 작업
common = dbutils.import_notebook("lib.common")
builtins.detect = common.detect
builtins.Output = common.Output
builtins.dbutils = dbutils
builtins.spark = spark
builtins.F = F

nb_path = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
repo_ws_root = "/".join(nb_path.split("/")[:4])          
repo_fs_root = f"/Workspace{repo_ws_root}"               
materialized_fs_root = f"{repo_fs_root}/materialized_py" 

if materialized_fs_root not in sys.path:
    sys.path.insert(0, materialized_fs_root)

# COMMAND ----------
# 3. Retrieve rule logic metadata (notebook path & callable name)
meta_df = spark.sql(f"""
    SELECT module_path, callable_name
    FROM sandbox.audit_poc.rule_registry
    WHERE rule_id = '{rule_id}'
      AND enabled = true
""")
meta = meta_df.collect()

if not meta:
    dbutils.notebook.exit(f"Rule [{rule_id}] disabled or not found in registry.")

module_path = meta[0]["module_path"]
callable_name = meta[0]["callable_name"]

# COMMAND ----------
# 4. Execute Rule Logic
mod = dbutils.import_notebook(module_path)
fn = getattr(mod, callable_name)

# AS-IS runner와 동일하게 window range를 넘겨서 룰 추출 스크립트 실행
df = fn(earliest=window_start_ts, latest=window_end_ts)
row_count = df.count()
print(f"Rule [{rule_id}] returned {row_count} findings.")

if row_count == 0:
    dbutils.notebook.exit("SUCCESS")

# COMMAND ----------
# 5. Build Standardized Payload Fields & Dedupe Key

# Payload 컬럼만을 조합하기 위해 제외할 메타데이터 컬럼 목록
_EXCLUDE_FROM_DEDUPE = {
    "observed_at", "run_id", "window_start_ts", "window_end_ts", 
    "severity", "rule_id", "dedupe_key"
}

out_df = (
    df
    .withColumn("rule_id", F.lit(rule_id))
    .withColumn("run_id", F.lit(run_id))
    .withColumn("window_start_ts", F.lit(window_start_ts))
    .withColumn("window_end_ts", F.lit(window_end_ts))
    .withColumn("severity", F.lit(severity))
    .withColumn("observed_at", F.current_timestamp())
)

# Sort payload columns explicitly to guarantee stable SHA256 hashes
payload_cols = sorted([c for c in out_df.columns if c not in _EXCLUDE_FROM_DEDUPE])

# Create Dedupe Key from concatenation of pure payload columns (메타데이터를 제외한 실제 컬럼 해싱)
out_df = out_df.withColumn(
    "dedupe_key",
    F.sha2(
        F.concat_ws("||", *[F.coalesce(F.col(c).cast("string"), F.lit("")) for c in payload_cols]), 
        256
    )
)

# COMMAND ----------
# 6. MERGE into Individual Table (`findings_{id}`)
individual_tbl = f"sandbox.audit_poc.findings_{rule_id}"

spark.sql(f"CREATE TABLE IF NOT EXISTS {individual_tbl} USING DELTA")

individual_target = DeltaTable.forName(spark, individual_tbl)

# 중복된 dedupe_key가 있을 경우 추가 Insert 방어
(
    individual_target.alias("t")
    .merge(
        out_df.alias("s"),
        "t.dedupe_key = s.dedupe_key AND t.rule_id = s.rule_id"
    )
    .whenNotMatchedInsertAll()
    .execute()
)
print(f"MERGE into Individual Table [{individual_tbl}] - DONE")

# COMMAND ----------
# 7. Build Unified Format & MERGE into Unified Table (`findings_unified`)

UNIFIED_TBL = "sandbox.audit_poc.findings_unified"

# Ensure unified table structure
spark.sql(f"""
    CREATE TABLE IF NOT EXISTS {UNIFIED_TBL} (
        event_ts TIMESTAMP,
        event_date DATE,
        rule_id STRING,
        run_id STRING,
        window_start_ts STRING,
        window_end_ts STRING,
        severity STRING,
        observed_at TIMESTAMP,
        payload_json STRING,
        dedupe_key STRING
    ) USING DELTA
""")

def _resolve_event_ts_col(df_frame):
    for c in ["EVENT_TIME", "event_time", "event_ts", "EVENT_TS", "timestamp", "time"]:
        if c in df_frame.columns:
            return F.col(c).cast("timestamp")
    return F.current_timestamp()

event_ts_expr = _resolve_event_ts_col(out_df)

if not payload_cols:
    payload_json_expr = F.lit("{}")
else:
    payload_json_expr = F.to_json(F.struct(*[F.col(c) for c in payload_cols]))

unified_df = (
    out_df.select(
        event_ts_expr.alias("event_ts"),
        F.to_date(event_ts_expr).alias("event_date"),
        F.col("rule_id"),
        F.col("run_id"),
        F.col("window_start_ts"),
        F.col("window_end_ts"),
        F.col("severity"),
        F.col("observed_at"),
        payload_json_expr.alias("payload_json"),
        F.col("dedupe_key"),  # 앞서 생성한 고유 dedupe_key 유지
    )
)

unified_target = DeltaTable.forName(spark, UNIFIED_TBL)

# 중복된 dedupe_key가 있을 경우 추가 Insert 방어
(
    unified_target.alias("t")
    .merge(
        unified_df.alias("s"),
        "t.dedupe_key = s.dedupe_key AND t.rule_id = s.rule_id"
    )
    .whenNotMatchedInsertAll()
    .execute()
)

print(f"MERGE into Unified Table [{UNIFIED_TBL}] - DONE")
dbutils.notebook.exit("SUCCESS")
