# Databricks Audit 기반 Cybersecurity Findings 파이프라인 운영 가이드

본 문서는 Databricks `cybersec-workspace-detection-app`의 **Detection Rule(탐지 룰)** 을 관리하고 스케줄링하기 위한 파이프라인 구조와 유지보수 방법에 대해 설명합니다.
최근 아키텍처 개편을 통해 **1 룰 = 1 개별 Databricks Job** 구조로 변경되었으며, `Serverless Compute`와 `job_configurator`를 활용한 동적 파라미터 관리에 최적화되어 있습니다. 기존의 단일 통합 구동 방식의 구형 버전 문서는 최신화되어 본 문서로 전면 대체됩니다.

---

## 1. 아키텍처 중심 구조

파이프라인은 탐지 룰을 중앙 레지스트리에 등록하고, 개별 Job을 동적으로 생성하여 독립적인 런타임 환경에서 각각 스케줄링 및 실행되도록 구성됩니다.

### 1-1. 메타데이터 및 상태 관리 테이블
- **`sandbox.audit_poc.rule_registry`**: 룰의 활성화 여부(`enabled`), 룰 그룹, 코드 실행 엔트리포인트를 관장하는 중앙 레지스트리.
- **`sandbox.audit_poc.rule_checkpoint`**: 증분 실행(Incremental Run)을 위한 상태 테이블. 최근 성공한 실행 윈도우 기록을 관리합니다.
- **`sandbox.audit_poc.rule_run_log`**: 각 룰 Job의 상세 실행 이력, 처리 건수, 성공/실패, 발생 에러 로그를 기록 및 적재하는 테이블.

### 1-2. 결과 (Findings) 적재 테이블
- **`sandbox.audit_poc.findings_{rule_id}`**: 개별 룰별로 떨어지는 원본 수준의 결과들. (Append/MERGE 혼합 구조)
- **`sandbox.audit_poc.findings_unified`**: 통합 대시보드 및 알럿 연동을 위해 모든 룰의 결과를 공통 스키마로 표준화한 테이블. Payload는 `payload_json`에 담기며, 컬럼 해싱을 통한 `dedupe_key`로 동일 윈도우 내 중복 재처리에서 발생하는 데이터 중복을 완벽하게 방어합니다.

---

## 2. 주요 운영 노트북 및 파일 역할 (`dasis_notebooks/`)

### 2-1. `job_generator/job_generator.py` (셋업 및 등록 통합)
이 노트북은 파이프라인의 기초 셋업과 Job 발급을 담당하며 내부적으로 크게 3개의 스텝(셀)으로 나뉩니다.
1. **`00_materialize_rules_as_py`**: `base/detections/` 하위 코드를 Databricks 환경에서 안전하게 Import 할 수 있도록 순수 Python 파일(`.py`) 형태로 컴파일 및 `materialized_py/` 폴더에 변환(Materialize)합니다.
2. **`01_register_rules`**: Materialize된 룰들을 읽어 `rule_registry` DB에 등록 혹은 상태를 갱신하고, 최초 등록 규칙의 경우 `rule_checkpoint` 초기 상태 row를 구성합니다.
3. **`02_job_generator`**: 레지스트리에 등록된 활성화 룰(`enabled=true`)들을 기반으로, 각각 1개의 Databricks Job(예: `Audit_Detection_{rule_id}`)을 발급 및 생성합니다.

### 2-2. `runners/single_runner.py` (실제 규칙 실행기)
앞서 생성된 개별 Databricks Job이 호출하는 **단일 실행기(Single Runner)** 입니다. 
실행 시점의 `window_start_ts`, `window_end_ts` 파라미터를 받아 실제 룰 로직을 추출하고, 그 결과를 개별 `findings_{rule_id}` 테이블과 통합 뷰 격인 `findings_unified` 테이블에 나란히 MERGE 합니다. 최종 처리 성공/실패 내역은 `rule_run_log`와 `rule_checkpoint`에 꼼꼼하게 반영하여 추후 실행을 대비합니다.

### 2-3. `job_configs/job_configurator.py` (일괄 관리기)
독립적으로 생성된 30여 개 이상의 잡(Job)들을 단일 UI 위젯에서 일괄 관리(Bulk Update) 할 수 있는 도우미 노트북입니다.
특정 `rule_group` 단위로 기간 파라미터를 변경하거나, CRON 스케줄을 일괄 지정하고, 필요시 특정 룰 그룹 전체를 한 번에 PAUSE / UNPAUSE 활성화 제어할 수 있습니다.

---

## 3. 요건별 대처법 및 유지보수 가이드 (운영 Runbook)

### 3-1. 신규 탐지 룰(Detection Rule) 추가 시 
새로운 위협이나 로그 패턴을 탐지하는 룰을 추가해야 할 경우 다음 순서를 따릅니다.

1. **규칙 파일 작성**: 레포지토리의 `base/detections/<rule_group>/` (예: `binary`, `behavioral` 폴더) 경로에 새로운 파이썬 룰 파일을 생성하고 탐지 파이스파크 코드를 작성합니다.
2. **룰 변환 및 룰 레지스트리 갱신**
   - Databricks 작업 공간 내 `dasis_notebooks/job_generator/job_generator.py` 노트북을 엽니다.
   - 안쪽의 **`00_materialize_rules_as_py`** 섹션과 **`01_register_rules`** 섹션만 순차적으로 직접 실행합니다.
3. **신규 Job 생성**
   - 이어서 동일 노트북 내 하단에 위치한 **`02_job_generator`** 셀을 실행하면 새로 등록된 룰에 대해서만 개별 Databricks Job이 생성됩니다.
4. **스케줄 및 파라미터 구성**
   - `dasis_notebooks/job_configs/job_configurator.py` 노트북을 오픈합니다.
   - 대상 룰 그룹(혹은 전체)의 크론 스케줄(`UPDATE_SCHEDULE` 액션) 과 구동 파라미터를 사용자가 원하시는 주기에 맞추어 업데이트 해줍니다.

### 3-2. 기존 룰의 로직 변경 및 수정 시
탐지 조건이나 로직을 일부 변경해야 하여 `base/detections/...` 내에 위치한 소스 코드를 조정한 경우의 대처법입니다.
- 잡(Job)을 삭제하거나 새롭게 다시 Job Generator를 통해 덮어씌울 필요가 없습니다.
- 코드 수정 및 레포지토리 동기화(Pull) 후, `job_generator.py` 의 **`00_materialize_rules_as_py` 단계(첫 번째 셀)만 단 1회 실행**해 주면 됩니다. 
- 이후 예약된 스케줄러가 타겟 Job을 다시 실행할 때 최신 `.py` 모듈을 Import 하여 구동하게 되므로 로직 갱신이 곧바로 적용됩니다.

### 3-3. 특정 룰 일시정지 (비활성화) 방법
특정 기간 혹은 디버깅 이유로 룰을 정지하고 싶다면 두가지 방법이 모두 가능합니다.
- **추천 방식 (Job 스케줄러 단위 통제)**: `job_configurator.py` 에서 중단할 대상 그룹을 선택하고 `PAUSE_JOBS` 액션을 실행하여 스케줄러 단에서 편하게 비활성화 합니다. 일시중단했다가 나중에 언제든 `UNPAUSE_JOBS` 로 재개 하기가 매우 간편합니다.
- **원천 레지스트리 비활성화 (물리 삭제 대체 방식)**: 더 이상 런타임에 쓰이지 않아야 하는 아웃데이팅 룰이라면 `sandbox.audit_poc.rule_registry` 테이블 자체에서 SQL명령어로 `UPDATE ... SET enabled = false WHERE rule_id = '...'` 처리를 해둡니다. 

### 3-4. 과거 기간 재처리 (Backfill) 구동 방법
- `findings_unified` 에 적재 프로세스 진행시 `dedupe_key`(이벤트 Payload 전체 컬럼들의 Hash값)를 사용해 MERGE 하도록 구축했으므로, 동일 이벤트를 중복 적재할 위험이 원천 차단 되어있습니다.
- 이에 따라 데이터 유실이나 정책 변경에 의해 특정 과거 구간 구간을 다시 구동하고 싶다면:
  - 수정 및 점검하려는 개별 Job의 화면에서 'Run Now with Different Parameters' 옵션을 눌러 들어갑니다.
  - 파라미터 칸에 조회를 원하시는 `window_start_ts`와 `window_end_ts` 값을 수동으로 입력 후 재실행 버튼을 클릭합니다.
  - 과거 데이터를 리스캔하여 중복없이 병합 적재(MERGE) 해 주게 됩니다.
