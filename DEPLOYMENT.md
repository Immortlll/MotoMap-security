# OpenClaw 安全过滤器部署指南

## 🚀 快速接入方案

### 1. API服务接入（推荐）

#### 启动服务
```bash
# Flask 版本（简单易用）
python api_server.py

# FastAPI 版本（高性能）
python fastapi_server.py
```

#### 客户端调用
```python
from client_sdk import OpenClawSecurityClient

# 初始化客户端
client = OpenClawSecurityClient("http://localhost:5000")

# 过滤内容
result = client.filter_content("用户手机号13812345678", user_id="demo")
print(result.filtered_content)  # 用户手机号138****5678
```

### 2. Python包集成

#### 直接导入
```python
from security_filter import filter_openclaw_output

# 便捷过滤
safe_content = filter_openclaw_output("用户手机号13812345678")
```

#### 装饰器方式
```python
from client_sdk import secure_output

@secure_output(api_url="http://localhost:5000")
def my_function():
    return "用户手机号13812345678"

# 自动过滤输出
result = my_function()  # 用户手机号138****5678
```

### 3. Docker容器化部署

#### 单容器部署
```bash
# 构建镜像
docker build -t openclaw-security .

# 运行容器
docker run -p 5000:5000 openclaw-security
```

#### Docker Compose部署
```bash
# 启动完整服务栈
docker-compose up -d

# 包含：API服务 + 负载均衡 + Redis缓存 + 监控
```

## 📋 API接口文档

### 基础接口

#### 健康检查
```http
GET /health
```

#### 内容过滤
```http
POST /filter
Content-Type: application/json

{
  "content": "待过滤的内容",
  "user_id": "用户ID（可选）",
  "return_details": "是否返回详细信息（可选）"
}
```

#### 批量过滤
```http
POST /batch_filter
Content-Type: application/json

{
  "contents": ["内容1", "内容2", ...],
  "user_id": "用户ID（可选）",
  "return_details": "是否返回详细信息（可选）"
}
```

#### 安全检查
```http
POST /check_security
Content-Type: application/json

{
  "content": "待检查的内容",
  "user_id": "用户ID（可选）"
}
```

#### 统计信息
```http
GET /stats
```

### 响应格式

#### 成功响应
```json
{
  "success": true,
  "filtered_content": "过滤后的内容",
  "is_blocked": false,
  "action_taken": "masked",
  "security_level": "confidential",
  "risk_score": 5.0,
  "timestamp": "2026-03-08T21:00:00.000Z"
}
```

#### 错误响应
```json
{
  "error": "错误描述",
  "code": 400
}
```

## 🔧 集成示例

### Flask应用集成
```python
from flask import Flask, request, jsonify
from client_sdk import SecurityMiddleware

app = Flask(__name__)
middleware = SecurityMiddleware("http://localhost:5000")

@app.route('/api/process', methods=['POST'])
def process_data():
    data = request.get_json()
    content = data.get('content', '')
    
    # 安全过滤
    safe_content = middleware.process_response(content, user_id="flask_app")
    
    return jsonify({"result": safe_content})

if __name__ == '__main__':
    app.run()
```

### FastAPI应用集成
```python
from fastapi import FastAPI
from client_sdk import OpenClawSecurityClient

app = FastAPI()
client = OpenClawSecurityClient("http://localhost:5000")

@app.post("/api/process")
async def process_data(content: str):
    # 异步过滤
    result = await client.filter_content_async(content)
    return {"result": result.filtered_content}
```

### Django应用集成
```python
# middleware.py
from client_sdk import SecurityMiddleware

class SecurityFilterMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.security = SecurityMiddleware("http://localhost:5000")
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # 过滤响应内容
        if hasattr(response, 'content'):
            safe_content = self.security.process_response(response.content)
            response.content = safe_content
        
        return response

# settings.py
MIDDLEWARE = [
    'app.middleware.SecurityFilterMiddleware',
    ...
]
```

## 🐳 生产环境部署

### 环境配置
```bash
# 生产环境变量
export FLASK_ENV=production
export LOG_LEVEL=INFO
export REDIS_URL=redis://localhost:6379
```

### 使用Gunicorn
```bash
# 启动生产服务器
gunicorn -w 4 -b 0.0.0.0:5000 api_server:app

# 配置文件
# gunicorn.conf.py
bind = "0.0.0.0:5000"
workers = 4
worker_class = "sync"
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
```

### Nginx配置
```nginx
upstream openclaw_security {
    server 127.0.0.1:5000;
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://openclaw_security;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # 超时设置
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

### Kubernetes部署
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw-security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: openclaw-security
  template:
    metadata:
      labels:
        app: openclaw-security
    spec:
      containers:
      - name: api
        image: openclaw-security:latest
        ports:
        - containerPort: 5000
        env:
        - name: FLASK_ENV
          value: "production"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: openclaw-security-service
spec:
  selector:
    app: openclaw-security
  ports:
  - port: 80
    targetPort: 5000
  type: LoadBalancer
```

## 📊 监控和日志

### 日志配置
```python
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/security.log'),
        logging.StreamHandler()
    ]
)
```

### Prometheus监控
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'openclaw-security'
    static_configs:
      - targets: ['localhost:5000']
    metrics_path: '/metrics'
```

### 健康检查
```bash
# 健康检查脚本
#!/bin/bash
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/health)
if [ $response -eq 200 ]; then
    echo "Service is healthy"
    exit 0
else
    echo "Service is unhealthy"
    exit 1
fi
```

## 🔒 安全配置

### API密钥认证
```python
# 添加API密钥验证
@app.before_request
def verify_api_key():
    api_key = request.headers.get('X-API-Key')
    if api_key != 'your-secret-key':
        return jsonify({'error': 'Invalid API key'}), 401
```

### 速率限制
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/filter')
@limiter.limit("100 per minute")
def filter_endpoint():
    # 处理逻辑
    pass
```

### HTTPS配置
```bash
# 生成SSL证书
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# 启动HTTPS服务
python api_server.py --certfile cert.pem --keyfile key.pem
```

## 🚨 故障排除

### 常见问题

1. **连接超时**
   ```python
   # 增加超时时间
   client = OpenClawSecurityClient(timeout=60)
   ```

2. **内存不足**
   ```python
   # 批量处理限制
   if len(contents) > 100:
       raise Exception("Batch size too large")
   ```

3. **CPU占用过高**
   ```python
   # 使用异步处理
   from client_sdk import OpenClawSecurityAsync
   client = OpenClawSecurityAsync()
   ```

### 调试模式
```bash
# 启用调试日志
export LOG_LEVEL=DEBUG
python api_server.py
```

### 性能优化
```python
# 连接池配置
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=3
)
session.mount('http://', adapter)
```

## 📈 扩展功能

### Redis缓存
```python
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def cached_filter(content):
    cache_key = f"filter:{hash(content)}"
    cached = redis_client.get(cache_key)
    if cached:
        return cached.decode('utf-8')
    
    result = filter_content(content)
    redis_client.setex(cache_key, 3600, result)
    return result
```

### 机器学习增强
```python
from transformers import pipeline

# 加载NLP模型
classifier = pipeline("text-classification", model="microsoft/DialoGPT-medium")

def ml_enhanced_filter(content):
    # 传统规则过滤
    rule_result = filter_content(content)
    
    # ML语义分析
    ml_result = classifier(content)
    
    # 结合结果
    if ml_result[0]['score'] > 0.8:
        return enhance_security_level(rule_result)
    
    return rule_result
```

## 📞 技术支持

如需技术支持，请：
1. 查看日志文件 `/app/logs/security.log`
2. 检查健康状态 `GET /health`
3. 提交Issue到GitHub仓库
4. 联系开发团队

---

**注意**: 在生产环境中部署前，请确保：
- 配置适当的安全认证
- 设置监控和告警
- 定期更新依赖包
- 备份重要数据
