# OpenClaw 安全过滤器 - 增强版本

## 📁 项目结构

```
openclaw_security/
├── __init__.py                 # 主包初始化
├── core/                       # 核心模块
│   ├── __init__.py
│   ├── config.py              # 安全配置和等级定义
│   ├── filter.py              # 核心过滤逻辑
│   └── security_enhancements.py  # 增强安全特性（融合Sub2API）
├── api/                        # API服务
│   ├── __init__.py
│   ├── flask_server.py        # Flask API服务器
│   ├── fastapi_server.py      # FastAPI高性能服务器
│   └── enhanced_server.py    # 增强安全API服务器
├── client/                     # 客户端SDK
│   ├── __init__.py
│   ├── sdk.py                 # 标准客户端SDK
│   └── enhanced_sdk.py        # 增强客户端SDK
├── examples/                   # 使用示例
│   ├── __init__.py
│   ├── integration_examples.py # 标准集成示例
│   └── enhanced_integration.py # 增强集成示例
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

## 🚀 新特性：融合Sub2API安全特性

### 🛡️ 增强安全功能

#### 1. API密钥管理
- **安全密钥生成**: 基于加密的API密钥生成
- **权限控制**: 细粒度的API权限管理
- **使用统计**: 密钥使用次数和频率追踪
- **自动过期**: 可配置的密钥过期机制

#### 2. 威胁检测系统
- **SQL注入检测**: 识别恶意SQL查询模式
- **XSS攻击防护**: 检测跨站脚本攻击
- **路径遍历防护**: 阻止目录遍历攻击
- **命令注入检测**: 识别系统命令注入尝试
- **敏感信息泄露**: 检测API密钥、密码等敏感信息

#### 3. 速率限制
- **用户级限制**: 每用户请求频率控制
- **密钥级限制**: 每API密钥的并发控制
- **滑动窗口**: 智能的速率限制算法
- **自动阻断**: 超限自动阻断机制

#### 4. 安全审计
- **完整日志**: 所有安全事件的详细记录
- **威胁追踪**: 威胁模式的完整追踪
- **用户行为**: 用户安全行为分析
- **实时监控**: 实时安全状态监控

## 🚀 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 启动增强API服务
```bash
# 启动增强安全API服务器
python -m openclaw_security.api.enhanced_server
```

### 3. 生成API密钥
```python
from openclaw_security import EnhancedOpenClawClient

client = EnhancedOpenClawClient("http://localhost:5000")
api_key_info = client.generate_api_key("your_user_id", ["read", "filter"])
print(f"API密钥: {api_key_info.api_key}")
```

### 4. 增强内容过滤
```python
from openclaw_security import quick_enhanced_filter

# 增强过滤（包含威胁检测）
result = quick_enhanced_filter(
    "用户手机号13812345678", 
    api_key="your_api_key"
)
print(f"过滤结果: {result.filtered_content}")
print(f"安全动作: {result.security_actions}")
print(f"风险评分: {result.risk_score}")
```

## 📋 增强API接口

### 认证接口
- `POST /api/keys` - 生成API密钥
- `GET /api/keys` - 列出用户API密钥

### 安全过滤接口
- `POST /filter` - 增强内容过滤
- `POST /security/scan` - 安全扫描

### 管理接口
- `GET /security/metrics` - 安全指标
- `GET/POST /security/config` - 安全配置管理

### 响应示例
```json
{
  "success": true,
  "filtered_content": "用户手机号138****5678",
  "is_blocked": false,
  "security_actions": ["masked", "threats_detected"],
  "risk_score": 25.0,
  "threats_detected": [
    {
      "pattern": "\\b(\\d{11})\\b",
      "matches": ["13812345678"],
      "threat_level": "medium",
      "timestamp": "2026-03-08T22:00:00.000Z"
    }
  ],
  "enhanced_mode": true
}
```

## 🔧 增强集成方式

### 1. 增强装饰器
```python
from openclaw_security import enhanced_secure_output

@enhanced_secure_output(api_url="http://localhost:5000", api_key="your_key")
def my_function():
    return "用户手机号13812345678"

result = my_function()  # 自动增强过滤
```

### 2. 增强中间件
```python
from openclaw_security import EnhancedSecurityMiddleware

middleware = EnhancedSecurityMiddleware("http://localhost:5000", api_key="your_key")
safe_content = middleware.process_response(response_content)
```

### 3. 安全扫描
```python
from openclaw_security import quick_security_scan

scan_result = quick_security_scan(
    "SELECT * FROM users; DROP TABLE users;",
    api_key="your_key"
)
print(f"安全状态: {scan_result.security_status}")
print(f"威胁数量: {len(scan_result.threats_detected)}")
```

## 🛡️ 威胁检测能力

### 检测的威胁类型
- **SQL注入**: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`
- **XSS攻击**: `<script>`, JavaScript代码注入
- **路径遍历**: `../`, `..\\`
- **命令注入**: `;`, `&`, `|`, `` ` ``, `$(){}[]`
- **敏感信息**: API密钥、密码、私钥等

### 威胁等级评估
- **CRITICAL** (50分): API密钥、密码泄露
- **HIGH** (30分): SQL注入、命令注入
- **MEDIUM** (15分): XSS攻击、路径遍历
- **LOW** (5分): 一般可疑模式

### 安全建议系统
- **高风险 (>80分)**: 立即阻止，通知管理员
- **中风险 (50-80分)**: 人工审核，增强监控
- **低风险 (20-50分)**: 记录日志，考虑验证
- **安全 (<20分)**: 正常处理

## 📊 安全指标

### 实时监控指标
- **总用户数**: 当前活跃用户数量
- **总请求数**: 累计处理请求数
- **阻止率**: 被拦截请求的比例
- **平均风险评分**: 所有请求的平均风险值
- **威胁检测数**: 检测到的威胁总数
- **API密钥状态**: 活跃密钥数量

### 安全事件审计
```json
{
  "timestamp": "2026-03-08T22:00:00.000Z",
  "event_type": "content_filtered",
  "user_id": "user123",
  "session_id": "session_abc123",
  "risk_score": 75.0,
  "security_actions": ["blocked", "threats_detected"],
  "threats_count": 3
}
```

## 🐳 Docker部署

### 增强版Docker部署
```bash
# 构建增强版镜像
cd openclaw_security/deployment
docker build -t openclaw-security-enhanced .

# 运行增强版服务
docker run -p 5000:5000 openclaw-security-enhanced
```

### Docker Compose增强版
```yaml
version: '3.8'
services:
  openclaw-security-enhanced:
    build: .
    ports:
      - "5000:5000"
    environment:
      - SECURITY_MODE=enhanced
      - ENABLE_AUDIT=true
      - RATE_LIMIT=1000
    volumes:
      - ./logs:/app/logs
```

## 🧪 测试

### 增强功能测试
```bash
# 运行增强集成示例
python -m openclaw_security.examples.enhanced_integration

# 运行安全测试
python -m pytest openclaw_security/tests/ -v
```

### 威胁检测测试
```python
# 测试各种威胁模式
threat_tests = [
    ("SQL注入", "SELECT * FROM users; DROP TABLE users;"),
    ("XSS攻击", "<script>alert('XSS')</script>"),
    ("敏感信息", "API密钥：sk-1234567890abcdef"),
    ("正常内容", "这是安全的公开内容。")
]
```

## 📈 性能对比

| 功能 | 标准模式 | 增强模式 | 性能开销 |
|------|----------|----------|----------|
| 内容过滤 | ~1.7ms | ~2.1ms | +23% |
| 威胁检测 | N/A | ~0.4ms | +0.4ms |
| 安全扫描 | N/A | ~0.6ms | +0.6ms |
| 总体开销 | 基准 | +30% | 可接受 |

## 🔒 安全配置

### 环境变量
```bash
export SECURITY_MODE=enhanced          # 启用增强模式
export ENABLE_AUDIT=true              # 启用安全审计
export RATE_LIMIT=1000               # 每小时请求限制
export THRESHOLD_AUTO_BLOCK=80       # 自动阻断阈值
export API_KEY_PREFIX=osk_           # API密钥前缀
```

### 配置文件
```python
security_config.update_config(
    section="rate_limiting",
    key="requests_per_hour", 
    value=2000
)
```

## 📞 技术支持

- **GitHub**: https://github.com/Immortlll/MotoMap-security
- **增强功能**: 融合Sub2API安全特性
- **文档**: 查看 `openclaw_security/docs/` 目录
- **示例**: 查看 `openclaw_security/examples/` 目录

## 🔄 版本历史

- **v2.0.0** - 融合Sub2API安全特性
  - API密钥管理系统
  - 威胁检测引擎
  - 增强安全审计
  - 实时安全监控
  - 性能优化

- **v1.0.0** - 初始版本，包含核心安全过滤功能

---

**注意**: 增强版本提供更全面的安全防护，建议在生产环境中使用。启用增强模式会增加约30%的性能开销，但能显著提升安全性。
