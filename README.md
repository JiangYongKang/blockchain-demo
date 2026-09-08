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
- **转账交易**：Ed25519 签名的转账交易，带 nonce 防重放。
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
uv run blockchain-demo tx --from 0 --to 1 --amount 1000   # 提交一笔转账
uv run blockchain-demo status                  # 观察高度增长与罚没记录
```

预期观察到的现象：

1. 四个节点高度持续增长，且同一高度的区块哈希完全一致；
2. 拜占庭节点（node3）双签被检测，质押被逐步罚没至 0（`SLASHED ...` 记录）；
3. 转账被打包进区块，余额在链上更新；
4. `kill` 掉任意一个诚实节点，链继续出块（3/4 > 2/3）；重启该节点后
   自动同步追上。

## 架构

```
src/blockchain_demo/
├── crypto.py      # Ed25519 密钥/签名、规范 JSON 编码、SHA-256
├── types.py       # 交易/区块/投票/提案/双签证据的构造、签名与校验
├── state.py       # 状态机：余额、nonce、验证人质押、罚没（确定性状态转移）
├── consensus.py   # BFT 共识引擎：Propose/Prevote/Precommit、超时、锁定、
│                  #   +2/3 法定人数、双签检测（所有状态迁移经事件循环原子化）
├── network.py     # asyncio TCP gossip（全网状连接、消息去重、断线重连）
├── node.py        # 节点：mempool、证据池、提交、落盘、区块同步、RPC
└── cli.py         # init / run / start-all / tx / status
```

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

覆盖：密码学原语、交易/投票/证据校验、状态机与罚没、以及完整共识集成
测试——4 节点（1 个拜占庭）在进程内与真实 TCP 两种环境下运行多个高度，
断言：诚实节点最终确认的链完全一致（无冲突）、作恶者被检测并罚没、
1 个节点宕机时链继续推进。

## 限制（演示性质）

- 仅适用于本地测试网：无 P2P 发现、无 NAT 穿透、无 DoS 防护；
- 罚没证据仅在被打包进区块时生效（当前高度的证据通常进入下一个区块）；
- 状态未做 Merkle 化，同步为全量区块下载。
