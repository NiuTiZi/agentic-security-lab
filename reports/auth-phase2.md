# 阶段2验收报告：委托链、审批、幂等与凭据盗用实验

生成时间：2026-09-17T16:38:51

模式：固定请求回放（不涉及真实模型）。测试执行凭据经受控测试通道加载，仅展示脱敏摘要。

| 编号 | 子项 | 结果 | 证据 |
| --- | --- | --- | --- |
| AUTH-14 | 合法委托成功（客服对话提交，子任务签发给退款 Agent） | PASS | 父任务 T-0210 -> 子任务 T-0211（pending） |
| AUTH-14 | 审批人批准（绑定子任务/工具/订单/金额） | PASS | 审批参数={'order_id': 'ORD-1002', 'amount_limit_cents': 5000} |
| AUTH-14 | 退款 Agent 按审批执行模拟退款成功 | PASS | 退款单 rf-T-0211，金额 ¥50 |
| AUTH-14 | 委托金额超父任务确认值 -> 拒绝（委托只能收缩权限） | PASS | code=delegate_amount_exceeds_parent |
| AUTH-14 | 子任务换订单执行 -> 拒绝（订单绑定子任务） | PASS | code=order_not_in_subtask |
| AUTH-14 | 子任务提高金额执行 -> 拒绝（审批与授权不覆盖提额） | PASS | code=amount_exceeds_limit |
| AUTH-14 | 撤销父任务后子任务执行 -> 拒绝（级联约束） | PASS | code=parent_task_revoked |
| AUTH-14 | 未审批先执行 -> 拒绝（approval_required） | PASS | code=approval_required |
| AUTH-14 | 重复执行同一子任务 -> 幂等返回，不重复退款 | PASS | 退款单 rf-T-0211（与首次相同） |
| AUTH-14 | 修改金额产生新子任务 -> 旧审批不覆盖，未审批仍拒绝 | PASS | 新子任务 T-0217（10元）未沿用 T-0216（20元）的审批 |
| AUTH-14 | 新子任务独立审批后可执行（金额以新审批为准） | PASS | 退款 ¥10 完成 |
| AUTH-11 | 合法查询任务完成（防护启用不影响正常业务） | PASS |  |
| AUTH-11 | 合法资料检索完成 | PASS |  |
| AUTH-11 | 合法退款全链路完成（确认->委托->审批->执行） | PASS | 退款单 rf-T-0221 ¥20 完成 |
| CRED-01 | Agent 认证通过（JWT 验证层 pass） | PASS | 持有者令牌本身有效，认证层无法区分盗用 |
| CRED-01 | 缺任务执行凭据 -> 业务授权拒绝（两层结果分开报告） | PASS | code=missing_task_credential，失败层=任务与用户授权 |
| CRED-02 | 任务有效期内范围内查询成功（持有者令牌的局限） | PASS | 盗用者同时持有令牌与有效任务凭据时可冒用完成任务 |
| CRED-02 | 更换任务范围外订单 -> 拒绝 | PASS | code=order_not_in_scope |
| CRED-02 | 扩大操作（docs.read）-> 拒绝 | PASS | code=insufficient_scope（令牌 scope 仍限定 order.read） |
| CRED-03 | 撤销任务后同材料重放 -> 应用授权拒绝（非令牌过期） | PASS | code=task_revoked——令牌未过期，失败源于在线状态核验 |
| CRED-04 | 统一入口两阶段停用完成 | PASS |  |
| CRED-04 | 停用后已有令牌调用 -> 拒绝（应用侧在线核验） | PASS | code=agent_disabled |
| CRED-04 | 停用期间新令牌申请亦失败（授权服务侧） | PASS | error=invalid_client |

## 结论要点

1. 委托与执行权限分离：客服 Agent 持 refund.delegate 仅能提交委托；退款执行需要退款 Agent 的 refund.execute 令牌与受限子任务凭据。
2. 受限子任务：更换订单（order_not_in_subtask）、提高金额（amount_exceeds_limit）、撤销父任务（parent_task_revoked）分别被拒，子任务不能扩大父任务授权范围。
3. 审批绑定子任务、工具与关键参数：修改金额产生的新子任务不沿用旧审批（approval_required），需独立批准。
4. 幂等：同一子任务重复执行返回既有退款单，不重复产生业务操作。
5. Bearer 令牌防护边界：令牌+有效任务凭据可冒用完成范围内操作（CRED-02）；任务撤销（CRED-03）与 Agent 停用（CRED-04）通过在线状态核验阻断，均非依赖令牌自然过期。