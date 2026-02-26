# Databricks notebook source
# MAGIC %md
# MAGIC # Single Runner
# MAGIC 단일 Detection 룰을 실행하며, Dedupe 여부를 파악한 뒤 개별 Delta Table과 Unified Delta Table에 MERGE 합니다.

# COMMAND ----------

import subprocess
import sys
# Ensure missing serverless libraries are installed at runtime
subprocess.check_call([sys.executable, "-m", "pip", "install", "geoip2", "netaddr", "--quiet"])

import builtins
import time
import datetime
import traceback
import pyspark.sql.functions as F
from delta.tables import DeltaTable

start_time_ms = int(time.time() * 1000)

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
if not window_end_ts:
    window_end_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
if not window_start_ts:
    try:
        end_dt = datetime.datetime.strptime(window_end_ts, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        end_dt = datetime.datetime.now(datetime.timezone.utc)
    start_dt = end_dt - datetime.timedelta(hours=24)
    window_start_ts = start_dt.strftime("%Y-%m-%d %H:%M:%S")

run_id = f"{rule_id}_{int(time.time())}"
print(f"Starting run for rule_id: {rule_id} | Window: {window_start_ts} ~ {window_end_ts} | Severity: {severity}")

def finalize_run(status: str, row_count: int = 0, error_msg: str = None):
    try:
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms

        finished_at = datetime.datetime.fromtimestamp(end_time_ms / 1000.0, tz=datetime.timezone.utc)
        started_at = datetime.datetime.fromtimestamp(start_time_ms / 1000.0, tz=datetime.timezone.utc)
        
        log_df = spark.createDataFrame([{
            "run_id": run_id,
            "rule_id": rule_id,
            "window_start_ts": window_start_ts if window_start_ts else None,
            "window_end_ts": window_end_ts if window_end_ts else None,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": status,
            "row_count": int(row_count),
            "duration_ms": int(duration_ms),
            "runner_version": "1.0",
            "error_message": str(error_msg) if error_msg else None,
            "created_at": finished_at
        }])
        
        # cast window_start_ts / end_ts to timestamp
        log_df = log_df.withColumn("window_start_ts", F.col("window_start_ts").cast("timestamp")) \
                       .withColumn("window_end_ts", F.col("window_end_ts").cast("timestamp"))
                       
        log_df.write.format("delta").mode("append").saveAsTable("sandbox.audit_poc.rule_run_log")

        log_df.createOrReplaceTempView("current_run")
        
        merge_sql = """
            MERGE INTO sandbox.audit_poc.rule_checkpoint t
            USING current_run s
            ON t.rule_id = s.rule_id
            WHEN MATCHED THEN UPDATE SET
                t.last_attempt_start_ts = s.started_at,
                t.last_attempt_end_ts = s.finished_at,
                t.last_status = s.status,
                t.last_error = s.error_message,
                t.updated_at = s.finished_at,
                t.last_success_end_ts = IF(s.status = 'SUCCESS', s.finished_at, t.last_success_end_ts)
            WHEN NOT MATCHED THEN INSERT (
                rule_id, last_success_end_ts, last_attempt_start_ts, last_attempt_end_ts, last_status, last_error, updated_at
            ) VALUES (
                s.rule_id, IF(s.status = 'SUCCESS', s.finished_at, NULL), s.started_at, s.finished_at, s.status, s.error_message, s.finished_at
            )
        """
        spark.sql(merge_sql)
    except Exception as finalize_err:
        print(f"Failed during finalize_run: {finalize_err}")


# COMMAND ----------

# 2. Add dependencies and Materialized Py root path to sys.path
# 노트북의 Base Root를 맞추기 위한 작업
common = dbutils.import_notebook("lib.common")
builtins.detect = common.detect
builtins.Output = common.Output
# Detection 노트북이 하단 테스트 블록에서 직접 호출하는 헬퍼도 주입
if hasattr(common, "get_time_range_from_widgets"):
    builtins.get_time_range_from_widgets = common.get_time_range_from_widgets
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

# 3. Retrieve rule logic metadata (module path & callable name)
# NOTE: avoid SQL string interpolation for rule_id; use DataFrame API filter instead.
meta = (
    spark.table("sandbox.audit_poc.rule_registry")
    .where((F.col("rule_id") == F.lit(rule_id)) & (F.col("enabled") == F.lit(True)))
    .select("module_path", "callable_name")
    .limit(1)
    .collect()
)

if not meta:
    err_msg = f"Rule [{rule_id}] disabled or not found in registry."
    finalize_run("FAILED", 0, err_msg)
    dbutils.notebook.exit(err_msg)

module_path = meta[0]["module_path"]
callable_name = meta[0]["callable_name"]

# COMMAND ----------

# 4. Execute Rule Logic
row_count = 0

# materialized 룰 모듈 import 시 하단의 테스트 블록(if __name__ == "__main__" or widget)
# 이 자동 실행되지 않도록 widget 값을 비워 side-effect를 막습니다.
try:
    dbutils.widgets.text("window_start_ts", "")
    dbutils.widgets.text("window_end_ts", "")
except Exception:
    pass

try:
    mod = dbutils.import_notebook(module_path)
    fn = getattr(mod, callable_name)

    # materialized python 모듈 callable 실행
    df = fn(earliest=window_start_ts, latest=window_end_ts)
    row_count = df.count()

    print(f"Rule [{rule_id}] returned {row_count} findings.")

    if row_count == 0:
        finalize_run("SUCCESS", row_count)
        dbutils.notebook.exit("SUCCESS")

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

    # 6. MERGE into Individual Table (`findings_{id}`)
    individual_tbl = f"sandbox.audit_poc.findings_{rule_id}"

    def _ensure_table_columns(table_name: str, source_df):
        existing_cols = {c.lower() for c in spark.table(table_name).columns}
        missing_defs = []
        for field in source_df.schema.fields:
            if field.name.lower() not in existing_cols:
                missing_defs.append(f"`{field.name}` {field.dataType.simpleString()}")

        if missing_defs:
            spark.sql(f"ALTER TABLE {table_name} ADD COLUMNS ({', '.join(missing_defs)})")
            print(f"Schema evolved for {table_name}: {', '.join(missing_defs)}")

    if not spark.catalog.tableExists(individual_tbl):
        # 첫 생성 시 source schema를 그대로 사용해 MERGE 키 누락을 방지
        out_df.limit(0).write.format("delta").mode("overwrite").saveAsTable(individual_tbl)
    else:
        _ensure_table_columns(individual_tbl, out_df)

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
        # Prefer event timestamps emitted by detection logic.
        # Many rules emit EVENT_DATE (already normalized), so include it before fallback.
        for c in [
            "EVENT_TIME", "event_time", "event_ts", "EVENT_TS",
            "EVENT_DATE", "event_date",
            "timestamp", "time"
        ]:
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

    _ensure_table_columns(UNIFIED_TBL, unified_df)

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
    
    finalize_run("SUCCESS", row_count)
    dbutils.notebook.exit("SUCCESS")

except Exception as e:
    # dbutils.notebook.exit("SUCCESS") raises a control-flow exception in Databricks.
    # Do not convert it to FAILED status.
    if str(e).startswith("Notebook exited:"):
        raise

    err_str = str(e) + "\n" + traceback.format_exc()
    # Safely truncate error message
    err_str = err_str[:10000]

    finalize_run("FAILED", row_count, err_str)
    raise e
