# OpenClaw 安全过滤器 - 结构化版本

## 📁 项目结构

```
openclaw_security/
├── __init__.py                 # 主包初始化
├── core/                       # 核心模块
│   ├── __init__.py
│   ├── config.py              # 安全配置和等级定义
│   └── filter.py              # 核心过滤逻辑
├── api/                        # API服务
│   ├── __init__.py
│   ├── flask_server.py        # Flask API服务器
│   └── fastapi_server.py      # FastAPI高性能服务器
├── client/                     # 客户端SDK
│   ├── __init__.py
│   └── sdk.py                 # 客户端SDK
├── examples/                   # 使用示例
│   ├── __init__.py
│   └── integration_examples.py # 集成示例
├── deployment/                 # 部署配置
│   ├── __init__.py
│   ├── Dockerfile             # Docker镜像配置
│   ├── docker-compose.yml     # 容器编排
│   ├── nginx.conf             # 负载均衡配置
│   └── README.md              # 部署指南
├── tests/                      # 测试模块
│   ├── __init__.py
│   └── test_core.py           # 核心功能测试
└── docs/                       # 文档
    ├── __init__.py
    └── ...                    # 详细文档
```

## 🚀 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 直接使用
```python
from openclaw_security import filter_openclaw_output

# 简单过滤
safe_content = filter_openclaw_output("用户手机号13812345678")
print(safe_content)  # 用户手机号138****5678
```

### 3. 启动API服务

#### Flask版本（简单易用）
```bash
python -m openclaw_security.api.flask_server
```

#### FastAPI版本（高性能）
```bash
python -m openclaw_security.api.fastapi_server
```

### 4. 客户端调用
```python
from openclaw_security import OpenClawSecurityClient

client = OpenClawSecurityClient("http://localhost:5000")
result = client.filter_content("用户手机号13812345678")
print(result.filtered_content)
```

## 📋 API接口

### 基础端点
- `GET /health` - 健康检查
- `POST /filter` - 内容过滤
- `POST /batch_filter` - 批量过滤
- `POST /check_security` - 安全检查
- `GET /stats` - 统计信息

### 请求示例
```bash
curl -X POST http://localhost:5000/filter \
  -H "Content-Type: application/json" \
  -d '{"content": "用户手机号13812345678", "user_id": "demo"}'
```

### 响应示例
```json
{
  "success": true,
  "filtered_content": "用户手机号138****5678",
  "is_blocked": false,
  "action_taken": "masked",
  "security_level": "confidential",
  "risk_score": 5.0
}
```

## 🐳 Docker部署

### 单容器部署
```bash
cd openclaw_security/deployment
docker build -t openclaw-security .
docker run -p 5000:5000 openclaw-security
```

### 完整服务栈
```bash
cd openclaw_security/deployment
docker-compose up -d
```

## 🔧 集成方式

### 1. 装饰器集成
```python
from openclaw_security import secure_output

@secure_output(api_url="http://localhost:5000")
def my_function():
    return "用户手机号13812345678"

result = my_function()  # 自动过滤
```

### 2. 中间件集成
```python
from openclaw_security import SecurityMiddleware

middleware = SecurityMiddleware("http://localhost:5000")
safe_content = middleware.process_response(response.content)
```

### 3. 快速函数
```python
from openclaw_security import quick_filter, quick_security_check

# 快速过滤
safe_content = quick_filter("敏感内容")

# 快速安全检查
is_safe = quick_security_check("待检查内容")
```

## 🛡️ 安全等级

| 等级 | 名称 | 处理方式 | 示例 |
|------|------|----------|------|
| L1 | 公开信息 | 直接放行 | 技术文档 |
| L2 | 内部公开 | 添加水印 | 项目进度 |
| L3 | 高度敏感 | 脱敏处理 | 手机号、邮箱 |
| L4 | 极度敏感 | 完全阻断 | API密钥、密码 |

## 📊 脱敏效果

- **手机号**: 13812345678 → 138****5678
- **邮箱**: user@domain.com → u***@domain.com
- **身份证**: 110101199001011234 → 110101****1234
- **银行卡**: 6222021234567890123 → 6222****0123

## 🧪 测试

### 运行测试
```bash
# 核心功能测试
python -m pytest openclaw_security/tests/

# 完整测试
python -m pytest openclaw_security/tests/ -v
```

### 性能测试
```python
from openclaw_security.examples.integration_examples import performance_test_example
performance_test_example()
```

## 📈 性能指标

- **处理速度**: ~1.7毫秒/次
- **吞吐量**: ~591次/秒
- **内存占用**: <100MB
- **CPU使用**: <5%

## 🔒 安全特性

- ✅ 四级安全分类
- ✅ 智能脱敏处理
- ✅ 实时内容拦截
- ✅ 完整审计日志
- ✅ 用户行为追踪
- ✅ 风险评分系统

## 📞 技术支持

- **GitHub**: https://github.com/Immortlll/MotoMap-security
- **文档**: 查看 `openclaw_security/docs/` 目录
- **示例**: 查看 `openclaw_security/examples/` 目录

## 🔄 版本历史

- **v1.0.0** - 初始版本，包含核心安全过滤功能
- 支持多级API服务
- 完整的客户端SDK
- Docker化部署
- 详细文档和示例

---

**注意**: 建议在生产环境中使用Docker部署，并配置适当的监控和日志系统。
