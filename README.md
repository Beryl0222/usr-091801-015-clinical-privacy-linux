# 诊疗隐私用途管控

针对“未遮挡产科手术照片外流”暴露的管控缺口，本服务把电子病历访问、教学观摩、科研导出、
现场拍摄与紧急救治全部纳入**带用途的授权链**：每次访问都携带患者关系、业务目的与最小字段范围；
教学/科研/传播用途必须绑定患者知情同意的具体版本与期限；撤回即时阻断未完成与已签发的导出；
紧急救治走 break-glass，要求理由、短时授权、事后复核与主动通知。

服务**不保存原始影像**：导出登记仅记录 SHA-256 文件哈希、操作者、时间、授权链与交付对象，
交付物附带 HMAC 水印令牌；密钥轮换后旧密钥降级为仅验证，旧文件哈希仍可验证并追溯完整授权链。
审计为追加式哈希链，任何改写、删除、乱序都会被 `verify()` 检出；事件取证可双人冻结台账，
任何管理员都无法抹除自己的操作。

## 运行

```bash
python3 service.py --check          # 基础配置与审计链自检
python3 service.py --port 8000      # 启动 HTTP 服务
npm test                            # 全部 46 项契约/场景/HTTP 测试
# 或：python3 -m unittest -v service_contract service_scenarios service_http
```

## 模块结构

| 文件 | 职责 |
| --- | --- |
| `privacy/policy.py` | 角色矩阵 × 业务目的 × 患者关系 × 最小字段的纯函数策略引擎；同意版本/期限/范围校验；缓存有效期（60s） |
| `privacy/audit.py` | 追加式哈希链台账：前向哈希、完整性校验、双人冻结、授权链重建 |
| `privacy/watermark.py` | 含操作者与时间的 HMAC-SHA256 水印；密钥环轮换（active / verify-only / revoked） |
| `privacy/app.py` | 领域编排：人员关系、知情同意、敏感访问、break-glass、导出生命周期、事件、保留删除 |
| `privacy/encoding.py` | 可拨快时钟、规范 JSON、内容哈希（测试确定性） |
| `service.py` | HTTP 入口与路由（健康检查契约保持不变） |
| `service_contract.py` | 基础健康检查契约测试 |
| `service_scenarios.py` | 安全部门 35 项模拟场景（领域层） |
| `service_http.py` | 8 项 HTTP 端到端契约 |

## 策略矩阵要点

- 角色 → 目的：`physician/nurse/anesthetist` 限 treatment(+emergency)；`intern/medical_student`
  仅 teaching；`researcher` 仅 research；`admin` **无任何临床目的**；`security` 仅安全调查。
- 目的规则：treatment 要求诊疗关系且禁止导出；teaching/research 要求**绑定同意版本**、
  脱敏后方可导出；emergency 豁免关系但只能凭短时紧急授权。
- 缓存应答在服务端重新校验：超过 60 秒的缓存令牌一律以 `cache-expired` 拒绝。
- 重复导出：同一文件哈希 + 操作者 + 目的 + 交付对象 + 授权的活跃登记被拒（`duplicate-export`）。

## 关键流程

**知情同意与撤回**：`POST /consents` 登记版本/用途/字段范围/有效期；
`POST /consents/{id}/revoke` 撤回后立即把全部同源活跃导出置为 `blocked`，
后续访问与导出均返回 `consent-revoked`（并发撤回测试验证撤回后的请求无一漏放）。

**Break-glass**：`POST /emergencies`（理由，TTL 900 秒）→ `/emergencies/{id}/view` 短时访问；
发起即向隐私官、患者通道、质控三方发主动通知；到期访问返回 `emergency-expired`；
`/emergencies/{id}/review` 由质控/安全做事后复核（justified / flagged）。

**导出与水印**：`POST /exports`（`content_b64` 仅用于即时哈希，不落任何存储）→ 返回
`watermark`（含 file_hash、operator、issued_at、consent 版本、kid、HMAC 签名）。
`POST /exports/verify` 用文件哈希验证水印并返回从创世记录起的**完整授权链**；
`POST /exports/trace` 按哈希追踪全部同源导出与交付对象。

**密钥轮换**：`POST /keys/rotate` 后旧密钥变 `verify-only`，历史文件旧哈希照常验证；
被 `revoke` 的 kid 立即失效；篡改水印载荷或用错文件哈希均验证失败。

**事件、冻结与删除**：`POST /incidents` 报告违规拍摄/外泄并自动关联同源导出；
`POST /audit/freeze` 需两名不同管理员令牌，冻结后除安全事件报告外的写入一律 423 拒绝；
`POST /purges` 按保留政策（教学 180 天 / 科研 365 天 / 质控 90 天 / 安全调查 7 年）
检查保留期与法律保全，`POST /purges/{id}/confirm` 双人确认后登记交付对象删除证明，
哈希与授权链永久保留，删除本身同样不可抹除。

## HTTP 错误码

- `403` 策略拒绝（`error` 给出机器可读原因：`purpose-denied` / `no-relation` /
  `field-overreach` / `consent-revoked` / `consent-expired` / `cache-expired` /
  `duplicate-export` / `emergency-expired` / `legal-hold` / `retention-active` 等）
- `423` 审计台账冻结中；`422` 水印或哈希链校验失败；`400` 参数问题；`404` 未暴露路由

只读端点：`GET /health`、`GET /state`、`GET /audit/entries`、`GET /notifications`。
