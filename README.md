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

- `app/forensics/intake.py` 管理分阶段批次受理：委托清单导入、分次实收登记、逐项差异、复核决定、补正轨迹与原子建案。
- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料与受理状态。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 批次受理

批次受理接口位于 `/api/forensics/intake`，按四个阶段推进，登记员持有 `intake.write`，复核人员持有 `intake.review`，审计人员持有 `intake.read`：

1. `POST /batches` 导入电子委托清单（须带来源文件名与 SHA-256 哈希）。同一来源文件哈希重传直接回放原批次，不会复制清单或差异。
2. `POST /batches/{id}/rounds` 分次登记实收封装，支持多轮登记；同一来源记录哈希或同一扫描记录键（`scan_record_key`）重传只计数不入库。系统依据委托编号、封识号、检材类别、数量和必填文书，逐项计算 `matched / missing / surplus / duplicate_seal / quantity_mismatch / category_mismatch / document_missing / entrust_mismatch / mixed` 差异，已下结论的项目在后续轮次中冻结，不会被重新配对。
3. `POST /batches/{id}/submit-review` 提交复核。复核人员可对单项 `POST /lines/{id}/decision` 执行接收、暂存待补正、退回或补正后重开；`POST /batches/{id}/decisions` 对无争议（`matched` 且未决）项目批量决定，任一项目版本过期、已被其他复核人处理或存在差异时整批拒绝。差异行使用乐观版本号，版本过期或他人已下结论时一律 409，不会覆盖另一位复核人的结论。
4. 暂存项通过 `POST /lines/{id}/corrections` 登记补正（补传文书、数量/类别补正确认或缺件补传封装），系统保留前后快照、决定理由（`intake_decision_events`）和完整补正轨迹（`intake_corrections`），补正后项目回到待复核。

`POST /batches/{id}/generate-cases` 只能针对“已接收”项目，按委托编号在单事务内原子生成正式案件（直接 `accepted`）与保管检材，并在差异行上回填 `generated_specimen_id`；退回与暂存项不会生成检材，同委托编号不可重复建案。全部项目处置且已接收项均已建案后，批次才能 `conclude`。

每轮导入与重算都会写入不可变差异快照（`intake_snapshots`）。`GET /batches/{id}/summary` 返回委托清单、实收、决定、建案与退回的数量汇总，并给出逐件核对结果（`checks` 与 `balanced`）：委托项和封装是否全部落在差异行、已接收数量是否等于保管台账检材数量、退回项是否确实未进入台账、轮次登记数量是否对得上。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
