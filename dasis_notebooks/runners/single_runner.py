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

# 3. Retrieve rule logic metadata (notebook path & callable name)
meta_df = spark.sql(f"""
    SELECT module_path, callable_name
    FROM sandbox.audit_poc.rule_registry
    WHERE rule_id = '{rule_id}'
      AND enabled = true
""")
meta = meta_df.collect()

if not meta:
    err_msg = f"Rule [{rule_id}] disabled or not found in registry."
    finalize_run("FAILED", 0, err_msg)
    dbutils.notebook.exit(err_msg)

module_path = meta[0]["module_path"]
callable_name = meta[0]["callable_name"]

# COMMAND ----------

# 4. Execute Rule Logic
row_count = 0
try:
    mod = dbutils.import_notebook(module_path)
    fn = getattr(mod, callable_name)

    # AS-IS runner와 동일하게 window range를 넘겨서 룰 추출 스크립트 실행
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
    
    finalize_run("SUCCESS", row_count)
    dbutils.notebook.exit("SUCCESS")

except Exception as e:
    err_str = str(e) + "\n" + traceback.format_exc()
    # Safely truncate error message
    err_str = err_str[:10000]
        
    finalize_run("FAILED", row_count, err_str)
    raise e
