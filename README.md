# blockchain-demo

一个**从零实现、单机离线运行**的拜占庭容错（BFT）权益证明区块链。
不依赖任何外部 RPC、托管节点、公链或云服务，也不封装 geth / hardhat /
foundry / bitcoin-core 等现成链客户端——共识、网络、状态机、罚没全部
在本仓库内实现，唯一的第三方依赖是通用密码学库 `cryptography`（Ed25519）。

## 特性

- **本地多进程网络**：≥4 个验证节点作为独立 OS 进程运行，通过本机
  127.0.0.1 TCP（JSON-lines gossip）互相通信，持续出块。
- **Tendermint 风格 BFT 共识**：每个高度经历
  `Propose → Prevote → Precommit → Commit`，按质押加权，>2/3 法定人数。
  - 任意 ≤1/3 节点宕机、延迟或作恶时，诚实节点继续出块；
  - 同一高度绝不会最终确认两个冲突区块（安全性由 >2/3 法定人数交集保证）；
  - 故障超过 1/3 时链安全停摆（不分叉），恢复后继续。
- **双签检测与罚没**：同一验证人在同一 (高度, 轮次, 投票类型) 对两个不同
  区块签名（双投/双提案）会被其他节点检测为**矛盾证据（evidence）**，
  打包进后续区块，确定性地罚没其质押（每次 1/2，直至 0，失去投票权）。
- **账户模型与转账交易**：采用账户模型（account model），每个账户持有
  **余额（balance）与 nonce**。交易是 **secp256k1 椭圆曲线数字签名（ECDSA）**
  的转账：账户地址由公钥派生（`sha256(pubkey)[-20:]`），交易携带公钥与签名，
  节点据此验证地址归属与签名（强制 low-S，防签名延展性）。**未签名、签名无效、
  余额不足、nonce 不匹配的交易绝不会被纳入最终确认区块**；转账确认后付款方
  余额减少、收款方余额增加、付款方 nonce 递增，所有诚实节点状态完全一致，
  且每笔入账都有同区块内对应的扣款（总量守恒，无凭空入账）。
- **合约账户与存储槽**：除外部账户（EOA）外支持**合约账户**。`deploy` 交易
  部署字节码（合约地址由创建者 + nonce 确定性派生），`call` 交易在一个确定性
  微型栈式 VM 中执行合约（`PUSH1/ADD/POP/SSTORE/SLOAD/STOP`，32 字节字、
  步数上限、栈下溢即失败回滚）。合约拥有独立的 **storage（键/值均为 32 字节
  存储槽）**；调用故障（非法操作码等）整笔回滚，不写入存储、不转移资金。
- **状态承诺与可验证包含证明（轻客户端）**：每个区块头提交
  **`app_state_root`**——一棵 256 位**稀疏 Merkle 树（sparse Merkle trie）**
  的根，账户叶子编码 `{balance, nonce, code, storage_root}`，合约的每个存储槽
  再由该合约自己的 storage trie 提交；区块头同时提交 `txs_root` /
  `evidence_root`（对交易/证据列表的 Merkle 根），**块哈希 = 区块头哈希**。
  提议者对 dry-run 后的状态计算根并写入头；诚实节点独立重放并**校验头中的根
  与自己导出的状态根一致**，不一致即对该块投 nil，提交前再做一次同样校验。
  因此**轻客户端仅凭区块头、>2/3 precommit 投票与可信验证人公钥，就能独立判定
  任一账户余额/nonce 或任一合约存储槽的值**：它不信任节点返回的数值，只验证
  最终性证明与 Merkle 包含证明。正确证明必然通过；对余额、存储槽值或证明路径
  的任何篡改都使验证失败；**无法伪造一个未被该区块状态根承诺的账户或存储值**
  （等价于寻找 SHA-256 碰撞）。缺席也可证明（不存在账户/未写入槽位的非成员证明）。
- **持久化与同步**：区块落盘（`chain.jsonl`），重启可恢复；落后节点通过
  携带 >2/3 precommit 证明的区块同步追上，同步时逐块验证最终性证明。

## 快速开始

```bash
uv sync                                        # 安装依赖（Python 3.12+）

# 初始化 4 个验证节点，node3 配置为拜占庭（会对每个提案/投票双签）
uv run blockchain-demo init --nodes 4 --byzantine 3 --force

# 启动 4 个验证节点进程（前台，Ctrl-C 停止）
uv run blockchain-demo start-all

# 停止所有节点
uv run blockchain-demo stop
```

另开终端：

```bash
uv run blockchain-demo status                  # 各节点高度/质押/罚没记录
uv run blockchain-demo tx --from 0 --to 1 --amount 1000   # 提交一笔 ECDSA 转账
uv run blockchain-demo balances                # 各节点上各账户的余额与 nonce
uv run blockchain-demo status                  # 观察高度增长与罚没记录

# 部署一个计数器合约（字节码 60005500 = PUSH1 0; SSTORE; STOP，把 calldata 存入槽0）
uv run blockchain-demo deploy --from 0 --code 60005500
#   -> 打印派生的合约地址，例如 7dce64a5985f237c...
# 调用合约，calldata=42 写入存储槽 0
uv run blockchain-demo call --from 0 --to <合约地址> --calldata 42

# 轻客户端证明：节点只返回区块头 + >2/3 precommit + Merkle 证明，
# CLI 用本地 genesis 验证人公钥独立验证最终性与包含关系
uv run blockchain-demo proof storage --address <合约地址> --slot 0
uv run blockchain-demo proof balance --address acc0     # accN 或 hex 地址
uv run blockchain-demo proof balance --address abab…    # 可证明该账户不存在
```

预期观察到的现象：

1. 四个节点高度持续增长，且同一高度的区块哈希完全一致；
2. 拜占庭节点（node3）双签被检测，质押被逐步罚没至 0（`SLASHED ...` 记录）；
3. 转账被打包进区块：付款账户余额减少、收款账户余额增加、付款账户 nonce
   递增，`balances` 在所有节点上对同一账户显示完全相同的余额与 nonce；
4. `kill` 掉任意一个诚实节点，链继续出块（3/4 > 2/3）；重启该节点后
   自动从磁盘恢复并同步追上。

## 架构

```
src/blockchain_demo/
├── crypto.py      # Ed25519（验证人）+ secp256k1 ECDSA（账户）密钥/签名、
│                  #   地址派生、规范 JSON 编码、SHA-256（ECDSA 强制 low-S）
├── merkle.py      # 256 位稀疏 Merkle 树（SMT）：update/root/prove/verify_proof，
│                  #   叶/内部节点域分离、层级绑定、零子树哈希；列表 Merkle 根
├── contract.py    # 确定性微型栈式 VM（PUSH1/ADD/POP/SSTORE/SLOAD/STOP）、
│                  #   32 字节存储字、步数上限；合约地址 = H(creator,nonce)
├── types.py       # 交易（transfer/deploy/call，ECDSA）/区块头/投票/提案/证据的
│                  #   构造、签名与校验；块哈希 = 区块头哈希（头提交各 Merkle 根）
├── state.py       # 状态机：账户（余额/nonce/code/storage）、账户 trie 与每合约
│                  #   storage trie、state_root、account/storage 证明、合约执行、
│                  #   验证人质押、罚没；区块原子化状态转移
├── light.py       # 轻客户端：仅凭区块头 + precommit 投票 + 可信公钥验证最终性，
│                  #   仅凭 state_root + Merkle 证明验证余额/nonce 与合约存储槽
├── consensus.py   # BFT 共识引擎：Propose/Prevote/Precommit、超时、锁定、
│                  #   +2/3 法定人数、双签检测；提议者写状态根，验证者校验状态根
├── network.py     # asyncio TCP gossip（全网状连接、消息去重、断线重连）
├── node.py        # 节点：mempool、证据池、提交（dry-run + 状态根校验）、落盘、
│                  #   区块同步、RPC（status/accounts/nonce/block/prove_*/tx）
└── cli.py         # init/run/start-all/stop/tx/deploy/call/proof/status/balances
```

### 账户模型与交易有效性

- **双签名体系**：验证人（共识投票/提案）用 Ed25519；**账户转账用
  secp256k1 ECDSA**。账户地址 = `sha256(SEC1 公钥)[-20:]`，交易在签名体中
  携带公钥，节点先由公钥重算地址并核对 `sender`，再用 ECDSA 验签；签名
  统一为 low-S，消除延展性。
- **交易校验门禁**：一笔交易只有同时满足以下条件才会被接受并最终确认：
  1. 带有有效 ECDSA 签名（未签名/签名错误/公钥与地址不符一律拒绝）；
  2. `nonce` 严格等于账户当前 nonce（防重放、防跳号）；
  3. 付款账户余额 ≥ 转账金额。
  这些检查在 mempool 准入、提议区块的 dry-run（诚实验证人对非法区块投
  nil）、以及提交落盘前三处独立执行，形成纵深防御。
- **原子化状态转移**：`apply_block` 在草稿副本上执行全部交易与罚没，全部
  成功才采纳结果——含任意一条非法交易的整块被拒绝、无任何部分生效，因此
  不可能出现「有入账、无扣款」。状态转移只在提交时发生，所有诚实节点从
  相同区块导出完全一致的余额与 nonce。

### 状态承诺、包含证明与轻客户端

- **区块头即承诺**：区块 = `{header, txs, evidence}`，**块哈希 = 区块头哈希**。
  头部除 `height/prev_hash/...` 外，提交三个 Merkle 根：
  - `txs_root` / `evidence_root`：对交易列表、证据列表的二叉 Merkle 根，
    使区块体无法在不改块哈希的情况下被篡改；
  - `app_state_root`：执行完该块后整个状态的 **256 位稀疏 Merkle 树（SMT）根**。
- **稀疏 Merkle 树**：键为 `sha256(地址)`，账户叶子是规范 JSON
  `{balance, nonce, code, storage_root}`；合约账户的 `storage_root` 是该合约
  自己一棵 SMT（键/值均为 32 字节存储槽字）的根。叶子节点与内部节点用不同
  域分隔前缀并混入层级，杜绝第二原像混淆；未写入的键落在「空叶子」上，因此
  **缺席（账户不存在 / 槽位未写）可用同一条包含路径证明**。证明是一串
  「兄弟哈希 + 方向」，验证方仅凭 (键, 值, 证明) 即可重算根，无需触碰整棵树。
- **状态根不可谎报**：提议者对 dry-run 后的状态计算 `app_state_root` 并写入头；
  每个诚实验证者独立重放区块、重算根，并**校验头部根与自己导出的根一致**，
  不一致就对该块投 nil（提交前在 `commit_block` 再校验一次，纵深防御）。
  于是一个状态根错误的块不可能在诚实节点上最终确认。
- **轻客户端验证**（`light.py`）：客户端只信任一组**验证人公钥**（如 genesis
  验证人集）和**区块头**。给定一个已最终确认区块，它
  1. 用 >2/3 质押的有效 Ed25519 precommit（签名覆盖 `hash(header)`）判定
     **最终性**——票数不足、投给别的块哈希、或签名伪造都不成立；
  2. 从头部取 `app_state_root`，用账户包含证明核验某地址的 **balance/nonce/code**；
  3. 对合约存储槽，串联两条证明：账户证明绑定 `storage_root`，槽位证明把该槽
     的 32 字节值绑定到该 `storage_root`。
  它从不问节点「余额是多少」并相信答案，而是索要**证明**并自行验算。正确证明
  必然通过；**篡改余额、nonce、存储槽值、证明路径兄弟哈希或方向，验证一律失败**；
  证明键与地址绑定，A 账户的证明不能拿去证明 B 账户；**无法为状态根未承诺的
  账户或存储值伪造证明**（除非攻破 SHA-256）。

### 共识要点

- **法定人数**：某区块获得 >2/3 总质押的 precommit 即最终确认，不可回滚。
  两个冲突区块要同时被确认，至少需要 >1/3 的质押双签——而这会留下可
  验证的密码学证据并被罚没。
- **锁定机制**：节点在某轮看到某区块的 +2/3 prevote（polka）后锁定该
  区块，后续轮次只为它投票，除非看到更晚轮次的其他 polka（解锁规则），
  与 Tendermint 一致。
- **活性**：每轮提议者按 `(height + round) % |validators|` 轮换；提议、
  prevote、precommit 均有超时，超时后进入下一轮。轮次/高度迁移通过
  事件循环延迟执行（`call_soon`），保证共识状态迁移的原子性。
- **双签证据**：任何节点收到同一验证人在同一 (type, height, round) 的
  两张不同投票（或同一 (height, round) 的两个不同提案）即构造证据并
  gossip；证据被打包进区块后在状态转移中确定性罚没（质押减半，可多次
  直至归零），全部诚实节点独立验证证据有效性。

## 测试

```bash
uv run pytest tests/ -q
```

覆盖：密码学原语（Ed25519 与 secp256k1 ECDSA、地址派生、low-S）、交易/投票/
证据校验、状态机与罚没、以及完整共识集成测试——4 节点（1 个拜占庭）在进程内
与真实 TCP 两种环境下运行多个高度，断言：诚实节点最终确认的链完全一致
（无冲突）、作恶者被检测并罚没、1 个节点宕机时链继续推进、节点重启从磁盘
恢复。账户模型专项断言：转账后付款方扣款/收款方入账/付款方 nonce 递增且
所有诚实节点余额与 nonce 一致；未签名、伪造签名、余额不足、nonce 不匹配
（过期/跳号）的交易在提交时被拒且永不出现在任何最终区块；区块原子性
（含一条非法交易则整块不生效）；总量守恒（无无对应扣款的入账）。

状态承诺与轻客户端专项（`test_merkle.py` / `test_contract.py` /
`test_light.py`）断言：相同数据得相同根、任何改动改根、插入后删除恢复原根；
包含/缺席证明对全部存在键与缺失键成立；**篡改叶值（余额/nonce/存储槽值）、
篡改证明路径上任意兄弟哈希或方向、把一个地址/键的证明重放到另一个、用缺席
路径伪造成「富有账户」或「已写槽位」，验证全部失败**；最终性需要 >2/3 质押
对**确切区块头哈希**的有效 precommit（票数不足、投给别的哈希、伪造签名、
未知验证人都不成立）；合约部署/调用确定性写存储、故障整笔回滚、独立节点导出
相同状态根。

## 限制（演示性质）

- 仅适用于本地测试网：无 P2P 发现、无 NAT 穿透、无 DoS 防护；
- 罚没证据仅在被打包进区块时生效（当前高度的证据通常进入下一个区块）；
- 合约 VM 为教学用最小子集（无 gas 计费、无跨合约调用）；状态证明只绑定到
  最新已最终确认区块，未实现验证人集合变更后的轻客户端顺序接力（同一固定
  验证人集内可独立验证任意高度）；同步仍为全量区块下载（轻客户端路径已具备，
  但全节点同步未改为只同步区块头）。
