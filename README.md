# 司法鉴定检材流转与复核服务

本项目是面向司法鉴定机构的 Python 后端服务，用于登记委托或移送案件、接收带封识的检材、记录保管位置与流转、执行专业检验、安排复核并处理环境和质量告警。案件、检材、检验记录和领用审批都保存在本地 SQLite 中，关键写入带版本或幂等键，适合在单个 Linux 应用容器内运行。

## 运行环境

- Python 3.11
- FastAPI 与 Uvicorn
- SQLite 3，由 Python 标准库提供

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `data/forensics.db`，也可以通过 `FORENSICS_DATABASE_PATH` 指向其他 `.db`、`.sqlite` 或 `.sqlite3` 文件。

## 初始化与启动

```bash
python -m app.cli init-db
python -m app.cli check-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查为 `GET /api/system/health`。首次使用可调用 `POST /api/auth/bootstrap` 创建管理员，再通过 `POST /api/auth/login` 取得 Bearer 会话令牌。鉴定业务接口统一位于 `/api/forensics`。

## 测试与构建检查

```bash
python -m pytest
python -m compileall -q app tests
```

下面两条命令分别检查 HTTP 入口和完整的入库演示链路：

```bash
python -m app.cli smoke
python -m app.cli demo
```

## 业务边界

- `app/forensics/intake.py` 管理分阶段批次受理：委托清单导入、分次实收封装登记、逐项差异快照、复核决定、补正轨迹、原子立案与逐件核对。
- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料与受理状态。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 分阶段批次受理

针对一次性送达数十个封装、委托清单与现场实物不一致的场景，受理流程拆分为独立阶段，退回的检材不会进入保管台账：

1. **导入委托清单**：`POST /api/forensics/intake/batches`。按来源文件内容哈希去重，同一文件重传返回既有批次（`replayed=true`）且不复制数据。
2. **分次登记实收封装**：`POST /api/forensics/intake/batches/{id}/rounds`，可分多轮录入。同一批次内扫描记录键 `scan_key` 重传只计数不复制。
3. **逐项差异**：系统按委托编号、封识号、检材类别、数量和必填文书重算差异，代码包括 `package_missing`（缺件）、`quantity_mismatch`（数量不符）、`category_mismatch`（类别不符）、`missing_document`（文书缺失）、`duplicate_seal`（封识号跨委托编号重复）、`unexpected_package`（无委托项）、`quantity_unknown`。每轮差异写入 `intake_review_snapshots` 快照历史。
4. **复核决定**：单项可 `accepted`、`pending_correction`、`returned`（`POST /intake/review-items/{id}/decision`）；零争议项可批量决定（`POST /intake/batches/{id}/decisions`）。复核单项带独立版本号，版本过期时拒绝覆盖，且不会覆盖另一位复核人的结论。
5. **补正轨迹**：暂存待补正项可补交实物扫描件或文书（`POST /intake/review-items/{id}/corrections`），差异消除后回到待决定队列，全过程留痕。
6. **原子立案**：`POST /intake/batches/{id}/confirm` 要求所有单项均已决定、接收项零差异，在一个事务内生成正式案件与检材并直接置为 `accepted`；退回项只写入退回清单，不生成检材、不进入保管台账。
7. **逐件核对**：`GET /intake/batches/{id}/reconciliation` 汇总清单行数、封装数、接收/退回数量，并核对案件档案、检材台账、保管流水与退回清单是否逐件一致（`reconciliation_checks`、`all_checks_passed`）。

权限上，登记员角色拥有 `intake.write`，审核员（curator）拥有 `intake.review`，审计员仅 `intake.read`。可用 `python -m app.cli intake-demo` 走通完整链路。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务、领用申请采用版本号防止旧请求覆盖新状态；批次受理的复核单项使用独立版本号并记录决定人，批量决定只匹配仍处于待决定状态的行；入库、移库、取样和传感读数使用业务键去重，批次委托导入按来源文件哈希、实收封装按扫描记录键去重。正式案件与检材只能由批次确认事务原子生成，并回链受理批次与复核单项。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
