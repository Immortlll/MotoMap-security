"""
OpenClaw 安全过滤器增强模块
融合Sub2API的安全特性，提供更全面的安全防护
"""

import hashlib
import hmac
import time
import secrets
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from datetime import datetime, timedelta
import re

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """增强的安全等级"""
    L1_PUBLIC = "public"
    L2_INTERNAL = "internal" 
    L3_CONFIDENTIAL = "confidential"
    L4_TOP_SECRET = "top_secret"
    L5_CRITICAL = "critical"  # 新增：关键级别

class ThreatLevel(Enum):
    """威胁等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityContext:
    """安全上下文"""
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str
    request_count: int = 0
    last_request_time: float = 0
    risk_score: float = 0.0
    blocked_requests: int = 0

class EnhancedSecurityFilter:
    """增强的安全过滤器，融合Sub2API的安全特性"""
    
    def __init__(self):
        self.user_contexts: Dict[str, SecurityContext] = {}
        self.rate_limits: Dict[str, Dict] = {}
        self.api_keys: Dict[str, Dict] = {}
        self.blocked_ips: set = set()
        self.suspicious_patterns: List[re.Pattern] = []
        
        # 初始化安全规则
        self._init_security_rules()
    
    def _init_security_rules(self):
        """初始化安全规则"""
        # 基于Sub2API的安全增强规则
        self.suspicious_patterns = [
            # SQL注入模式
            re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)", re.IGNORECASE),
            # XSS模式
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            # 路径遍历
            re.compile(r"\.\./|\.\.\\"),
            # 命令注入
            re.compile(r"[;&|`$(){}[\]]", re.IGNORECASE),
            # 大量敏感信息模式
            re.compile(r"(\b(api[_-]?key|secret[_-]?key|password|token|private[_-]?key)\b.*[:=]\s*[^\s]{8,}", re.IGNORECASE),
        ]
    
    def generate_secure_api_key(self, user_id: str, permissions: List[str] = None) -> Tuple[str, str]:
        """
        生成安全的API密钥
        基于Sub2API的密钥管理机制
        """
        prefix = "osk_"  # OpenClaw Security Key
        random_part = secrets.token_urlsafe(32)
        api_key = f"{prefix}{random_part}"
        
        # 存储密钥信息
        self.api_keys[api_key] = {
            "user_id": user_id,
            "permissions": permissions or ["read", "filter"],
            "created_at": datetime.now().isoformat(),
            "last_used": None,
            "usage_count": 0,
            "rate_limit": 1000,  # 每小时请求数
            "concurrency_limit": 10  # 并发限制
        }
        
        # 生成密钥哈希用于验证
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        logger.info(f"Generated API key for user {user_id}: {key_hash[:16]}...")
        return api_key, key_hash
    
    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """验证API密钥"""
        if api_key not in self.api_keys:
            return None
        
        key_info = self.api_keys[api_key]
        key_info["last_used"] = datetime.now().isoformat()
        key_info["usage_count"] += 1
        
        return key_info
    
    def check_rate_limit(self, user_id: str, api_key: str) -> Tuple[bool, str]:
        """
        检查速率限制
        基于Sub2API的速率控制机制
        """
        if user_id not in self.user_contexts:
            self.user_contexts[user_id] = SecurityContext(
                user_id=user_id,
                session_id=secrets.token_urlsafe(16),
                ip_address="",
                user_agent=""
            )
        
        context = self.user_contexts[user_id]
        current_time = time.time()
        
        # 检查API密钥限制
        key_info = self.api_keys.get(api_key, {})
        rate_limit = key_info.get("rate_limit", 1000)
        
        # 简单的滑动窗口速率限制
        if current_time - context.last_request_time > 3600:  # 1小时窗口
            context.request_count = 0
        
        if context.request_count >= rate_limit:
            return False, f"Rate limit exceeded: {rate_limit} requests/hour"
        
        context.request_count += 1
        context.last_request_time = current_time
        
        return True, "OK"
    
    def detect_suspicious_patterns(self, content: str) -> List[Dict]:
        """
        检测可疑模式
        融合Sub2API的安全检测机制
        """
        detected_threats = []
        
        for pattern in self.suspicious_patterns:
            matches = pattern.findall(content)
            if matches:
                threat_level = self._assess_threat_level(pattern, content)
                detected_threats.append({
                    "pattern": pattern.pattern,
                    "matches": matches,
                    "threat_level": threat_level.value,
                    "timestamp": datetime.now().isoformat()
                })
        
        return detected_threats
    
    def _assess_threat_level(self, pattern: re.Pattern, content: str) -> ThreatLevel:
        """评估威胁等级"""
        pattern_str = pattern.pattern
        
        if any(keyword in pattern_str.lower() for keyword in ["select", "insert", "update", "delete"]):
            return ThreatLevel.HIGH
        elif any(keyword in pattern_str.lower() for keyword in ["script", "javascript"]):
            return ThreatLevel.MEDIUM
        elif any(keyword in pattern_str.lower() for keyword in ["api_key", "secret", "password"]):
            return ThreatLevel.CRITICAL
        else:
            return ThreatLevel.LOW
    
    def apply_security_filters(self, content: str, context: SecurityContext) -> Dict:
        """
        应用多层安全过滤器
        融合我们的数据分级和Sub2API的安全机制
        """
        result = {
            "original_content": content,
            "filtered_content": content,
            "security_actions": [],
            "threats_detected": [],
            "risk_score": 0.0,
            "blocked": False
        }
        
        # 1. 检测可疑模式
        threats = self.detect_suspicious_patterns(content)
        if threats:
            result["threats_detected"] = threats
            result["security_actions"].append("threats_detected")
            
            # 根据威胁等级调整风险分数
            for threat in threats:
                if threat["threat_level"] == ThreatLevel.CRITICAL.value:
                    result["risk_score"] += 50
                elif threat["threat_level"] == ThreatLevel.HIGH.value:
                    result["risk_score"] += 30
                elif threat["threat_level"] == ThreatLevel.MEDIUM.value:
                    result["risk_score"] += 15
                else:
                    result["risk_score"] += 5
        
        # 2. 应用原有的数据分级过滤
        from .filter import SecurityFilter
        original_filter = SecurityFilter()
        filter_result = original_filter.filter_content(content, context.user_id)
        
        # 3. 合并结果
        result["filtered_content"] = filter_result.filtered_content
        result["risk_score"] = max(result["risk_score"], filter_result.risk_score)
        
        if filter_result.is_blocked:
            result["blocked"] = True
            result["security_actions"].append("data_blocked")
        
        # 4. 额外的安全检查
        if result["risk_score"] > 80:
            result["blocked"] = True
            result["security_actions"].append("high_risk_blocked")
            result["filtered_content"] = "[SECURITY BLOCK] Content blocked due to high risk score"
        elif result["risk_score"] > 50:
            result["security_actions"].append("additional_monitoring")
        
        # 5. 更新用户上下文
        context.risk_score = result["risk_score"]
        if result["blocked"]:
            context.blocked_requests += 1
        
        return result
    
    def create_security_headers(self, context: SecurityContext) -> Dict[str, str]:
        """
        创建安全响应头
        基于Sub2API的安全头设置
        """
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-OpenClaw-Security-Level": str(context.risk_score),
            "X-Request-ID": context.session_id
        }
        
        # 根据风险等级添加额外头
        if context.risk_score > 50:
            headers["X-OpenClaw-Threat-Detected"] = "true"
            headers["X-OpenClaw-Monitoring-Level"] = "enhanced"
        
        return headers
    
    def audit_security_event(self, event_type: str, context: SecurityContext, details: Dict = None):
        """
        审计安全事件
        """
        audit_log = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user_id": context.user_id,
            "session_id": context.session_id,
            "ip_address": context.ip_address,
            "risk_score": context.risk_score,
            "blocked_requests": context.blocked_requests,
            "details": details or {}
        }
        
        logger.warning(f"Security Audit: {audit_log}")
        
        # 这里可以集成到外部日志系统
        # 例如发送到SIEM系统或安全分析平台
    
    def get_security_metrics(self) -> Dict:
        """获取安全指标"""
        total_requests = sum(ctx.request_count for ctx in self.user_contexts.values())
        total_blocked = sum(ctx.blocked_requests for ctx in self.user_contexts.values())
        avg_risk_score = sum(ctx.risk_score for ctx in self.user_contexts.values()) / len(self.user_contexts) if self.user_contexts else 0
        
        return {
            "total_users": len(self.user_contexts),
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "block_rate": total_blocked / total_requests if total_requests > 0 else 0,
            "average_risk_score": avg_risk_score,
            "active_api_keys": len(self.api_keys),
            "blocked_ips": len(self.blocked_ips),
            "timestamp": datetime.now().isoformat()
        }

# 安全配置类
class SecurityConfig:
    """安全配置管理"""
    
    def __init__(self):
        self.config = {
            "rate_limiting": {
                "enabled": True,
                "requests_per_hour": 1000,
                "burst_limit": 100,
                "cleanup_interval": 3600
            },
            "threat_detection": {
                "enabled": True,
                "auto_block_threshold": 80,
                "monitoring_threshold": 50
            },
            "api_key_management": {
                "key_length": 32,
                "key_prefix": "osk_",
                "max_keys_per_user": 5,
                "key_expiry_days": 365
            },
            "audit_logging": {
                "enabled": True,
                "log_level": "INFO",
                "retention_days": 90
            }
        }
    
    def update_config(self, section: str, key: str, value):
        """更新配置"""
        if section in self.config and key in self.config[section]:
            self.config[section][key] = value
            logger.info(f"Updated security config: {section}.{key} = {value}")
    
    def get_config(self, section: str = None, key: str = None):
        """获取配置"""
        if section is None:
            return self.config
        elif key is None:
            return self.config.get(section, {})
        else:
            return self.config.get(section, {}).get(key)

# 全局安全过滤器实例
enhanced_security_filter = EnhancedSecurityFilter()
security_config = SecurityConfig()
