# OpenClaw 数据安全分级防护系统

## 概述

这是一个专为OpenClaw设计的数据安全分级防护系统，通过在输出端设置"安全阀门"，防止敏感数据泄露。系统采用四级安全分类机制，提供自动检测、脱敏处理和审计功能。

## 安全等级划分

| 等级 | 名称 | 定义 | 泄露影响 | 处理策略 |
|------|------|------|----------|----------|
| L4 | 极度敏感 (Top Secret) | 核心凭据、API密钥、私钥、系统权限信息 | 毁灭性打击 | 完全阻断 |
| L3 | 高度敏感 (Confidential) | 个人隐私、身份证号、手机号、健康记录 | 法律合规风险 | 脱敏处理 |
| L2 | 内部公开 (Internal) | 业务逻辑、项目进度、内部架构 | 竞争优势削弱 | 受控输出 |
| L1 | 公开信息 (Public) | 通用知识、已发布文档 | 无影响 | 自由输出 |

## 核心功能

### 1. 敏感数据检测
- **正则表达式匹配**: 检测固定格式的敏感信息
- **关键词检测**: 基于敏感词库的内容识别
- **风险评分**: 综合评估内容安全风险

### 2. 防护处理
- **完全阻断**: L4级别内容直接拦截
- **智能脱敏**: L3级别自动掩码处理
- **水印添加**: L2级别添加内部水印
- **直接放行**: L1级别内容无处理

### 3. 审计追踪
- **完整日志**: 记录所有过滤操作
- **用户追踪**: 关联用户ID和操作时间
- **风险统计**: 提供安全风险分析

## 快速开始

### 基本使用

```python
from security_filter import filter_openclaw_output, SecurityException

# OpenClaw输出内容
content = "用户联系方式：13812345678，邮箱：user@example.com"

try:
    # 安全过滤
    safe_content = filter_openclaw_output(content, user_id="user_001")
    print(safe_content)
    # 输出：用户联系方式：13****5678，邮箱：u***@example.com
except SecurityException as e:
    print(f"内容被拦截：{e}")
```

### 高级使用

```python
from security_filter import SecurityFilter

# 创建过滤器实例
filter_instance = SecurityFilter(enable_audit=True)

# 过滤内容
result = filter_instance.filter_content(
    content="数据库密码：admin123",
    user_id="admin_user"
)

print(f"安全等级: {result.security_level.value}")
print(f"风险评分: {result.risk_score}")
print(f"处理动作: {result.action_taken}")
print(f"过滤结果: {result.filtered_content}")
```

## 文件结构

```
outselect-layer/
├── security_config.py      # 安全配置和等级定义
├── security_filter.py      # 核心过滤逻辑
├── example_usage.py        # 使用示例和测试
├── README.md              # 项目文档
└── requirements.txt       # 依赖包列表
```

## 配置说明

### 自定义检测规则

在 `security_config.py` 中可以修改：

```python
# 添加新的正则规则
DETECTION_RULES = {
    SecurityLevel.L4_TOP_SECRET: [
        r'(?i)custom_secret_pattern["\']?\s*[:=]\s*["\']?([^\s"\']+)["\']?',
        # ... 其他规则
    ]
}

# 添加敏感关键词
SENSITIVE_KEYWORDS = {
    SecurityLevel.L3_CONFIDENTIAL: [
        '自定义敏感词',
        # ... 其他关键词
    ]
}
```

### 脱敏策略定制

在 `security_filter.py` 中的 `_mask_sensitive_content` 方法可以自定义脱敏逻辑：

```python
def _mask_sensitive_content(self, content: str, level: SecurityLevel) -> str:
    # 自定义脱敏逻辑
    if level == SecurityLevel.L3_CONFIDENTIAL:
        # 实现自定义脱敏算法
        pass
    return content
```

## 集成方案

### 1. 中间件集成

```python
# Flask中间件示例
from flask import Flask, request, jsonify
from security_filter import SecurityFilter

app = Flask(__name__)
security_filter = SecurityFilter()

@app.before_request
def security_check():
    if request.endpoint == 'openclaw_output':
        # 在OpenClaw输出前进行安全检查
        pass

@app.after_request
def security_filter_response(response):
    if request.endpoint == 'openclaw_output':
        # 过滤响应内容
        content = response.get_data(as_text=True)
        result = security_filter.filter_content(content)
        response.set_data(result.filtered_content)
    return response
```

### 2. 装饰器集成

```python
from functools import wraps
from security_filter import filter_openclaw_output

def security_filter_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if isinstance(result, str):
            return filter_openclaw_output(result)
        return result
    return wrapper

@security_filter_decorator
def openclaw_process(input_data):
    # OpenClaw处理逻辑
    return output_data
```

## 性能优化

### 1. 模式预编译
系统自动预编译所有正则表达式，提高检测效率。

### 2. 批量处理
```python
def batch_filter(contents, user_id="batch_user"):
    filter_instance = SecurityFilter()
    return [filter_instance.filter_content(content, user_id) for content in contents]
```

### 3. 异步处理
```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def async_filter(content, user_id):
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        return await loop.run_in_executor(
            executor, filter_openclaw_output, content, user_id
        )
```

## 监控和告警

### 1. 风险阈值设置

```python
# 设置风险阈值
RISK_THRESHOLD = 50.0  # 风险评分超过50时触发告警

def check_risk_alert(result):
    if result.risk_score > RISK_THRESHOLD:
        send_security_alert(result)
```

### 2. 审计日志分析

```python
import json
from datetime import datetime, timedelta

def analyze_security_logs(days=7):
    # 分析最近7天的安全日志
    cutoff_date = datetime.now() - timedelta(days=days)
    # 生成安全报告
    pass
```

## 最佳实践

### 1. 部署建议
- 在OpenClaw输出管道的最后阶段集成安全过滤器
- 启用完整的审计日志记录
- 定期更新敏感词库和检测规则

### 2. 规则维护
- 定期审查和更新检测规则
- 根据实际泄露案例调整敏感词库
- 监控误报率并优化算法

### 3. 性能监控
- 监控过滤器的响应时间
- 设置性能告警阈值
- 定期进行压力测试

## 故障排除

### 常见问题

1. **误报过多**
   - 检查正则表达式是否过于宽泛
   - 调整敏感词库
   - 优化风险评分算法

2. **性能问题**
   - 检查正则表达式复杂度
   - 考虑使用缓存机制
   - 优化批量处理逻辑

3. **漏报问题**
   - 增加新的检测规则
   - 扩展敏感词库
   - 考虑使用机器学习模型

## 扩展开发

### 1. 机器学习增强
```python
# 可以集成轻量级NLP模型进行语义分析
from transformers import pipeline

classifier = pipeline("text-classification", model="microsoft/DialoGPT-medium")
```

### 2. 分布式部署
```python
# 支持Redis集群的分布式过滤
import redis
from redis.cluster import RedisCluster

redis_client = RedisCluster(host="redis-cluster", port=6379)
```

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 贡献指南

欢迎提交Issue和Pull Request来改进这个项目。

## 联系方式

如有问题或建议，请联系开发团队。
