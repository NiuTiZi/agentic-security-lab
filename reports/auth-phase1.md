# 阶段1验收报告：AUTH-01~10、12、13（固定请求模式）

- 日期: 2026-09-17T16:38:28
- 模式: 固定请求回放（不涉及真实模型；模型建议以固定解析器模拟）
- 组件: Keycloak 26.7.4 独立进程 / FastAPI 四服务（backend:8000, agent:8100/8200, tools:8300）
- 测试凭据: 经受控测试通道加载（6.10），仅记录脱敏摘要

| 用例 | 结果 | 子项 |
| --- | --- | --- |
| AUTH-01 合法链路 | **PASS** | ✓ 任务创建+Agent对话+工具执行成功<br>✓ 六层链路全部通过（客户端认证:pass -> 令牌签发:pass -> JWT 验证:pass -> scope 检查:pass -> 任务与用户授权:pass -> 业务执行:pass）<br>✓ 返回订单数据 ORD-1001 |
| AUTH-02 错误客户端凭据 | **PASS** | ✓ 错误密钥 -> 401 不签发（error=unauthorized_client）<br>✓ 未注册 client_id -> 401 不签发（error=invalid_client） |
| AUTH-03 名称不能代替认证 | **PASS** | ✓ 请求体携带合法 Agent 名称但无令牌 -> 401（code=missing_token） |
| AUTH-04 篡改令牌 | **PASS** | ✓ 改写 scope/azp 后签名不符 -> 401 invalid_signature（code=invalid_signature） |
| AUTH-05 无效令牌三子例 | **PASS** | ✓ 过期令牌（签名有效）-> 401 token_expired（code=token_expired）<br>✓ 其他签发方令牌（master realm）-> 401 拒绝（code=unknown_signing_key；令牌iss=http://127.0.0.1:8080/realms/master）<br>✓ 错误 audience 令牌（其余有效）-> 401 audience_mismatch（code=audience_mismatch；令牌aud=['other-service', 'account']） |
| AUTH-06 超范围 scope | **PASS** | ✓ 混入未注册 scope -> 组件拒绝（400 invalid_scope，整组不签发）（error=invalid_scope）<br>✓ 合法子集单独申请仍可用（组件行为=整组拒绝而非缩减）（与组件行为表 V5 一致）<br>✓ 未授予操作的执行拒绝由 AUTH-07 机制覆盖（无该 scope 令牌无法通过工具端 scope 检查）（见 AUTH-07） |
| AUTH-07 scope 不足 | **PASS** | ✓ 退款Agent令牌调用 order.read -> 认证通过、授权拒绝(403)（code=insufficient_scope） |
| AUTH-08 越权三子例 | **PASS** | ✓ 请求体替换 user_id + 他人订单 -> 对象级授权拒绝（code=object_ownership（请求体身份字段不作为授权依据））<br>✓ A 的执行凭据 + B 的任务编号 -> 绑定不符拒绝（code=task_binding_mismatch）<br>✓ 任务范围外订单（ORD-2001）-> 拒绝（code=order_not_in_scope） |
| AUTH-09 撤销与停用 | **PASS** | ✓ 两阶段停用完成（应用侧+授权服务）（phases={'app_side': 'ok', 'oauth_server': 'ok'}）<br>✓ 停用后未过期令牌+有效任务 -> 403 agent_disabled（记录撤销原因）（reason=Agent 已被停用（应用侧准入拒绝））<br>✓ 停用期间新令牌申请亦失败（401）（error=invalid_client）<br>✓ 撤销前调用成功（对照）<br>✓ 撤销后同凭据调用 -> 403 task_revoked（在线状态核验，非令牌过期）（reason=任务已被撤销） |
| AUTH-10 直接 API 调用 | **PASS** | ✓ 材料齐全的直接调用成功（保护在 API 层）<br>✓ 直接调用无令牌 -> 401<br>✓ 直接调用缺任务凭据 -> 403 missing_task_credential（code=missing_task_credential） |
| AUTH-12 建议不等于授权 | **PASS** | ✓ 查询任务中提议退款 -> 不执行、不扩权（code=operation_not_in_task；失败层=任务与用户授权，层1-4未到达）<br>✓ 未生成任何新任务/授权（任务集合不变） |
| AUTH-13 任务绑定 | **PASS** | ✓ A 的凭据 + B 的任务编号 -> 绑定不符拒绝（code=task_binding_mismatch）<br>✓ A 的会话对 B 任务发起对话 -> 会话归属核验拒绝（结果不串给其他用户） |

## 实现口径说明

1. 错误码分层：缺失/无效令牌 → 401（missing_token/invalid_signature/unknown_signing_key/token_expired/audience_mismatch）；身份有效但 scope 不足 → 403 insufficient_scope；任务绑定/撤销/停用/对象授权 → 403（task_binding_mismatch/task_revoked/agent_disabled/object_ownership/order_not_in_scope 等），响应含失败层与原因。
2. 对象可见性策略：演示环境对越权对象返回明确 403 原因（便于定位阻断层）；生产可选 404 隐藏策略，需在方案文档中声明。
3. 错误签发方子例：master realm 令牌在可信 JWKS 中无对应签名密钥，首个失败点为 unknown_signing_key（签发方信任边界即密钥边界）；其 iss 亦不匹配，iss 声明检查作为第二道防线存在。
4. AUTH-06 组件行为：Keycloak 26.7.4 对超范围 scope 请求整组拒绝（HTTP 400 invalid_scope），与组件行为表 V5 一致；未授予操作的执行拒绝由 scope 检查层保证（AUTH-07 机制）。
5. 执行凭据不经网页展示与模型上下文：由可信后台经内部通道推送 Agent 运行层；本报告验证所用凭据来自受控测试通道，报告中不出现原文。
6. 撤销即时性：应用授权状态为执行前在线核验（无跨请求缓存），撤销/停用后的下一次调用即被拒绝（AUTH-09）。