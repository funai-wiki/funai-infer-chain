# Stacks Inference Service

## 概述

Stacks Inference Service 是一个专门处理推理交易的服务，它接收推理任务，管理推理节点，并将任务状态持久化到 SQLite 数据库中。

## 功能特性

- **推理任务管理**: 接收、分配、跟踪推理任务
- **推理节点管理**: 注册、监控推理节点状态
- **状态持久化**: 使用 SQLite 数据库存储任务和节点信息
- **RESTful API**: 提供 HTTP API 接口
- **事件驱动**: 基于事件的任务处理机制

## 快速开始

### 1. 启动推理服务

```bash
# 使用默认配置启动
cargo run --bin stacks-signer -- run-inference-service --config ./config/signer.toml

# 指定数据库路径
cargo run --bin stacks-signer -- run-inference-service \
  --config ./config/signer.toml \
  --database ./data/inference.db \
  --api-port 8080 \
  --api-host 0.0.0.0
```

### 2. 命令行参数

- `--config`: 配置文件路径（必需）
- `--database`: SQLite 数据库文件路径（可选，默认在配置目录下）
- `--api-port`: API 服务器端口（默认: 8080）
- `--api-host`: API 服务器主机（默认: 127.0.0.1）
- `--debug`: 启用调试日志

### 3. 数据库结构

推理服务使用 SQLite 数据库存储以下信息：

#### inference_tasks 表
- `task_id`: 任务ID（主键）
- `user_address`: 用户地址
- `user_input`: 用户输入
- `context`: 上下文信息
- `fee`: 交易费用
- `nonce`: 交易 nonce
- `infer_fee`: 推理费用
- `max_infer_time`: 最大推理时间
- `model_type`: 模型类型
- `status`: 任务状态
- `created_at`: 创建时间
- `updated_at`: 更新时间
- `output`: 推理输出（可选）
- `confidence`: 置信度（可选）
- `completed_at`: 完成时间（可选）
- `inference_node_id`: 推理节点ID（可选）

#### inference_nodes 表
- `node_id`: 节点ID（主键）
- `endpoint`: 节点端点
- `public_key`: 节点公钥
- `status`: 节点状态
- `supported_models`: 支持的模型类型
- `performance_score`: 性能评分
- `last_heartbeat`: 最后心跳时间

## API 接口

### 推理节点接口

#### 注册推理节点
```http
POST /api/v1/nodes/register
Content-Type: application/json

{
  "node_id": "node-001",
  "endpoint": "http://192.168.1.100:5000",
  "public_key": "03a1b2c3...",
  "supported_models": ["deepseek", "llama"],
  "performance_score": 0.95
}
```

#### 节点心跳
```http
POST /api/v1/nodes/heartbeat
Content-Type: application/json

{
  "node_id": "node-001",
  "status": "online"
}
```

#### 获取任务
```http
GET /api/v1/nodes/{node_id}/tasks
```

### 任务管理接口

#### 完成任务
```http
POST /api/v1/tasks/complete
Content-Type: application/json

{
  "task_id": "task-001",
  "output": "推理结果",
  "confidence": 0.85,
  "inference_node_id": "node-001"
}
```

#### 查询任务状态
```http
GET /api/v1/tasks/{task_id}/status
```

### 系统接口

#### 获取统计信息
```http
GET /api/v1/stats
```

#### 获取所有节点
```http
GET /api/v1/nodes
```

#### 健康检查
```http
GET /health
```

## 任务状态

推理任务有以下状态：

- `pending`: 任务已提交，等待推理节点处理
- `in_progress`: 任务已被推理节点领取，正在处理
- `completed`: 任务已完成，等待提交给矿工
- `submitted`: 任务已提交给矿工
- `failed`: 任务失败
- `timeout`: 任务超时

## 节点状态

推理节点有以下状态：

- `online`: 在线
- `offline`: 离线
- `busy`: 忙碌
- `maintenance`: 维护中

## 配置示例

```toml
# signer.toml
[signer]
stacks_private_key = "your_private_key_here"
endpoint = "http://localhost:20443"
network = "testnet"

[inference]
# 推理服务配置（可选）
database_path = "./data/inference.db"
api_port = 8080
api_host = "127.0.0.1"
```

## 开发指南

### 添加新的模型类型

在 `libsigner/src/events.rs` 中的 `InferModelType` 枚举中添加新类型：

```rust
pub enum InferModelType {
    DeepSeek(Option<String>),
    Llama(Option<String>),
    Mistral(Option<String>),
    Gemma(Option<String>),
    GptNeoX(Option<String>),
    YourNewModel(Option<String>),  // 添加新模型
    Unknown(Option<String>),
}
```

### 扩展 API 接口

在 `stacks-signer/src/inference_api.rs` 中添加新的路由处理：

```rust
async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        // 添加新路由
        (&Method::GET, "/api/v1/your-endpoint") => {
            self.handle_your_endpoint(req).await
        }
        // ... 其他路由
    }
}
```

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查数据库文件路径和权限
   - 确保目录存在且可写

2. **API 服务器启动失败**
   - 检查端口是否被占用
   - 确认防火墙设置

3. **推理节点无法注册**
   - 检查节点 ID 是否唯一
   - 验证 JSON 格式是否正确

### 日志级别

使用 `--debug` 参数启用详细日志：

```bash
RUST_LOG=debug cargo run --bin stacks-signer -- run-inference-service --config ./config/signer.toml --debug
```

## 性能优化

1. **数据库优化**
   - 定期清理旧任务
   - 使用索引优化查询

2. **内存管理**
   - 限制内存中的任务数量
   - 定期刷新节点状态

3. **网络优化**
   - 使用连接池
   - 实现请求限流

## 安全考虑

1. **API 安全**
   - 实现身份验证
   - 使用 HTTPS
   - 限制请求频率

2. **数据安全**
   - 加密敏感数据
   - 定期备份数据库
   - 访问控制

3. **网络安全**
   - 防火墙配置
   - 网络隔离
   - 监控异常访问 