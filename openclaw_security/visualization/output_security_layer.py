"""
OpenClaw 输出层级安全层策略系统
基于GitHub Agentic Workflows安全架构的优化版本
直接将要输出的内容做成力导向图，在数据安全方面做出成绩
"""

import re
import json
import hashlib
from datetime import datetime
from pathlib import Path
import webbrowser
from typing import Dict, List, Any, Tuple, Optional

class OutputSecurityLevel:
    """输出安全等级"""
    SECURE = "secure"           # 安全输出
    CAUTION = "caution"         # 需要注意
    WARNING = "warning"         # 警告级别
    BLOCKED = "blocked"         # 阻止输出
    REDACTED = "redacted"       # 需要脱敏

class DataClassification:
    """数据分类等级"""
    PUBLIC = "public"           # 公开数据
    INTERNAL = "internal"       # 内部数据
    CONFIDENTIAL = "confidential"  # 机密数据
    RESTRICTED = "restricted"   # 限制数据

class OutputSecurityLayer:
    """输出层级安全层策略系统"""
    
    def __init__(self):
        self.content_sanitizers = []
        self.secret_patterns = []
        self.permission_isolation = True
        self.threat_detection_enabled = True
        self.auto_redaction = True
        
        # 初始化内容净化器
        self._init_sanitizers()
        
        # 初始化秘密检测模式
        self._init_secret_patterns()
        
        # 初始化权限隔离配置
        self._init_permission_isolation()
    
    def _init_sanitizers(self):
        """初始化内容净化器 - 基于GitHub安全策略"""
        self.content_sanitizers = [
            {
                "name": "mention_neutralization",
                "pattern": r'@(\w+)',
                "replacement": r'`\1`',
                "description": "@用户名中性化处理"
            },
            {
                "name": "bot_trigger_protection", 
                "pattern": r'(fixes|closes|resolves)\s+#(\d+)',
                "replacement": r'\1 `#\2`',
                "description": "机器人触发保护"
            },
            {
                "name": "xml_html_conversion",
                "pattern": r'<(/?)(\w+)([^>]*)>',
                "replacement": r'(\1\2\3/)',
                "description": "XML/HTML标签转换"
            },
            {
                "name": "uri_filtering",
                "pattern": r'http://[^\s]+',
                "replacement": '(redacted)',
                "description": "HTTP URL过滤"
            },
            {
                "name": "control_character_removal",
                "pattern": r'[\x00-\x1F\x7F]',
                "replacement": '',
                "description": "控制字符移除"
            },
            {
                "name": "special_character_handling",
                "pattern": r'[^\w\s\u4e00-\u9fff\-\.\,\!\?\:\;\(\)\[\]\{\}\/\@\#\$\%\^\&\*\+\=\|\\]',
                "replacement": '',
                "description": "特殊字符处理"
            }
        ]
    
    def _init_secret_patterns(self):
        """初始化秘密检测模式"""
        self.secret_patterns = [
            {
                "name": "api_key",
                "pattern": r'(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?',
                "classification": DataClassification.RESTRICTED,
                "description": "API密钥检测"
            },
            {
                "name": "password",
                "pattern": r'(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{6,})["\']?',
                "classification": DataClassification.RESTRICTED,
                "description": "密码检测"
            },
            {
                "name": "token",
                "pattern": r'(token|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9\-_\.]{20,})["\']?',
                "classification": DataClassification.RESTRICTED,
                "description": "Token检测"
            },
            {
                "name": "private_key",
                "pattern": r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                "classification": DataClassification.RESTRICTED,
                "description": "私钥检测"
            },
            {
                "name": "database_connection",
                "pattern": r'(mysql|postgresql|mongodb|redis)\s*://[^\s:@]+:[^\s:@]+@[^\s:]+:\d+',
                "classification": DataClassification.CONFIDENTIAL,
                "description": "数据库连接字符串"
            },
            {
                "name": "email_address",
                "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "classification": DataClassification.INTERNAL,
                "description": "邮箱地址"
            },
            {
                "name": "phone_number",
                "pattern": r'\b1[3-9]\d{9}\b|\b\d{3}[-\s]?\d{4}[-\s]?\d{4}\b',
                "classification": DataClassification.INTERNAL,
                "description": "手机号码"
            },
            {
                "name": "id_card",
                "pattern": r'\b\d{17}[\dXx]\b|\b\d{15}\b',
                "classification": DataClassification.CONFIDENTIAL,
                "description": "身份证号"
            },
            {
                "name": "bank_card",
                "pattern": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                "classification": DataClassification.RESTRICTED,
                "description": "银行卡号"
            }
        ]
    
    def _init_permission_isolation(self):
        """初始化权限隔离配置"""
        self.permission_isolation_config = {
            "read_only_permissions": [
                "contents:read",
                "metadata:read", 
                "pull-requests:read",
                "issues:read"
            ],
            "write_permissions": [
                "issues:write",
                "contents:write",
                "pull-requests:write"
            ],
            "safe_outputs": [
                "create_issue",
                "add_comment", 
                "create_pull_request",
                "add_labels"
            ]
        }
    
    def sanitize_content(self, content: str) -> Tuple[str, List[Dict]]:
        """内容净化 - 基于GitHub安全策略"""
        sanitized_content = content
        sanitization_log = []
        
        for sanitizer in self.content_sanitizers:
            matches = re.findall(sanitizer["pattern"], sanitized_content)
            if matches:
                sanitized_content = re.sub(
                    sanitizer["pattern"], 
                    sanitizer["replacement"], 
                    sanitized_content
                )
                sanitization_log.append({
                    "type": "sanitization",
                    "name": sanitizer["name"],
                    "description": sanitizer["description"],
                    "matches_count": len(matches),
                    "matches": matches[:3]  # 只记录前3个匹配
                })
        
        return sanitized_content, sanitization_log
    
    def detect_secrets(self, content: str) -> List[Dict]:
        """秘密检测"""
        detected_secrets = []
        
        for secret_pattern in self.secret_patterns:
            matches = re.finditer(secret_pattern["pattern"], content, re.IGNORECASE)
            for match in matches:
                # 提取匹配的值
                if secret_pattern["name"] == "private_key":
                    secret_value = match.group(0)  # 整个私钥
                elif len(match.groups()) > 0:
                    secret_value = match.group(1) if len(match.groups()) >= 1 else match.group(0)
                else:
                    secret_value = match.group(0)
                
                # 创建脱敏版本
                masked_value = self._mask_secret(secret_value)
                
                detected_secrets.append({
                    "type": "secret",
                    "name": secret_pattern["name"],
                    "classification": secret_pattern["classification"],
                    "description": secret_pattern["description"],
                    "original_value": secret_value,
                    "masked_value": masked_value,
                    "position": f"{match.start()}-{match.end()}",
                    "confidence": self._calculate_confidence(secret_pattern["name"], secret_value)
                })
        
        return detected_secrets
    
    def _mask_secret(self, secret: str) -> str:
        """创建脱敏版本"""
        if len(secret) <= 3:
            return "***"
        elif len(secret) <= 6:
            return secret[:2] + "*" * (len(secret) - 2)
        else:
            return secret[:3] + "*" * (len(secret) - 3)
    
    def _calculate_confidence(self, secret_type: str, value: str) -> float:
        """计算检测置信度"""
        base_confidence = {
            "api_key": 0.95,
            "password": 0.85,
            "token": 0.90,
            "private_key": 1.0,
            "database_connection": 0.88,
            "email_address": 0.70,
            "phone_number": 0.80,
            "id_card": 0.92,
            "bank_card": 0.95
        }
        
        confidence = base_confidence.get(secret_type, 0.5)
        
        # 根据值的特征调整置信度
        if secret_type == "email_address" and "@" in value and "." in value.split("@")[1]:
            confidence += 0.1
        elif secret_type == "phone_number" and len(value) >= 11:
            confidence += 0.1
        elif secret_type == "api_key" and len(value) >= 20:
            confidence += 0.05
        
        return min(confidence, 1.0)
    
    def assess_output_security(self, content: str) -> Dict:
        """评估输出安全性"""
        # 1. 内容净化
        sanitized_content, sanitization_log = self.sanitize_content(content)
        
        # 2. 秘密检测
        detected_secrets = self.detect_secrets(sanitized_content)
        
        # 3. 权限隔离检查
        permission_check = self._check_permission_isolation(detected_secrets)
        
        # 4. 威胁检测
        threat_analysis = self._perform_threat_detection(sanitized_content, detected_secrets)
        
        # 5. 确定安全等级
        security_level = self._determine_security_level(detected_secrets, threat_analysis)
        
        # 6. 生成安全建议
        recommendations = self._generate_recommendations(detected_secrets, security_level)
        
        return {
            "original_content": content,
            "sanitized_content": sanitized_content,
            "security_level": security_level,
            "detected_secrets": detected_secrets,
            "sanitization_log": sanitization_log,
            "permission_check": permission_check,
            "threat_analysis": threat_analysis,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        }
    
    def _check_permission_isolation(self, secrets: List[Dict]) -> Dict:
        """权限隔离检查"""
        restricted_secrets = [s for s in secrets if s["classification"] == DataClassification.RESTRICTED]
        confidential_secrets = [s for s in secrets if s["classification"] == DataClassification.CONFIDENTIAL]
        
        return {
            "requires_isolation": len(restricted_secrets) > 0,
            "restricted_count": len(restricted_secrets),
            "confidential_count": len(confidential_secrets),
            "safe_outputs_available": self.permission_isolation_config["safe_outputs"],
            "isolation_status": "required" if len(restricted_secrets) > 0 else "optional"
        }
    
    def _perform_threat_detection(self, content: str, secrets: List[Dict]) -> Dict:
        """威胁检测"""
        threats = []
        
        # 检测潜在的数据泄露威胁
        if len(secrets) > 0:
            restricted_secrets = [s for s in secrets if s["classification"] == DataClassification.RESTRICTED]
            if len(restricted_secrets) > 0:
                threats.append({
                    "type": "data_exfiltration",
                    "severity": "high",
                    "description": "检测到限制级数据，存在数据泄露风险",
                    "affected_secrets": len(restricted_secrets)
                })
        
        # 检测注入攻击
        injection_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*='
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append({
                    "type": "injection_attack",
                    "severity": "medium",
                    "description": "检测到潜在的注入攻击模式",
                    "pattern": pattern
                })
        
        # 检测异常内容长度
        if len(content) > 100000:  # 100KB
            threats.append({
                "type": "oversized_content",
                "severity": "low",
                "description": "内容长度异常，可能存在性能风险",
                "content_length": len(content)
            })
        
        return {
            "threats_detected": len(threats),
            "threats": threats,
            "overall_risk": "high" if any(t["severity"] == "high" for t in threats) else 
                           "medium" if any(t["severity"] == "medium" for t in threats) else "low"
        }
    
    def _determine_security_level(self, secrets: List[Dict], threat_analysis: Dict) -> str:
        """确定安全等级"""
        restricted_secrets = [s for s in secrets if s["classification"] == DataClassification.RESTRICTED]
        
        if len(restricted_secrets) > 0:
            return OutputSecurityLevel.BLOCKED
        elif threat_analysis["overall_risk"] == "high":
            return OutputSecurityLevel.WARNING
        elif len(secrets) > 0:
            return OutputSecurityLevel.CAUTION
        else:
            return OutputSecurityLevel.SECURE
    
    def _generate_recommendations(self, secrets: List[Dict], security_level: str) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        if security_level == OutputSecurityLevel.BLOCKED:
            recommendations.append("🚫 检测到限制级数据，建议阻止输出")
            recommendations.append("🔐 使用权限隔离机制处理敏感数据")
            recommendations.append("🛡️ 启用自动脱敏功能")
        elif security_level == OutputSecurityLevel.WARNING:
            recommendations.append("⚠️ 检测到安全威胁，建议谨慎处理")
            recommendations.append("🔍 进行详细的安全审查")
        elif security_level == OutputSecurityLevel.CAUTION:
            recommendations.append("🔍 检测到敏感信息，建议注意保护")
            recommendations.append("📝 考虑对敏感信息进行脱敏处理")
        else:
            recommendations.append("✅ 内容安全，可以正常输出")
        
        # 基于检测到的秘密类型添加具体建议
        secret_types = set(s["name"] for s in secrets)
        if "api_key" in secret_types:
            recommendations.append("🔑 API密钥应使用环境变量或密钥管理服务")
        if "password" in secret_types:
            recommendations.append("🔒 密码应使用强密码策略和定期更换")
        if "email_address" in secret_types:
            recommendations.append("📧 邮箱地址建议进行隐私保护")
        if "phone_number" in secret_types:
            recommendations.append("📱 手机号码建议进行脱敏处理")
        
        return recommendations

def create_output_security_force_graph(content: str, title: str = "输出安全层级分析") -> str:
    """创建输出安全层级力导向图"""
    security_layer = OutputSecurityLayer()
    assessment = security_layer.assess_output_security(content)
    
    # 安全等级颜色
    level_colors = {
        OutputSecurityLevel.SECURE: "#4CAF50",      # 绿色
        OutputSecurityLevel.CAUTION: "#FF9800",     # 橙色
        OutputSecurityLevel.WARNING: "#FF5722",     # 红橙色
        OutputSecurityLevel.BLOCKED: "#F44336",      # 红色
        OutputSecurityLevel.REDACTED: "#9C27B0"       # 紫色
    }
    
    # 数据分类颜色
    classification_colors = {
        DataClassification.PUBLIC: "#4CAF50",       # 绿色
        DataClassification.INTERNAL: "#FF9800",       # 橙色
        DataClassification.CONFIDENTIAL: "#FF5722",   # 红橙色
        DataClassification.RESTRICTED: "#F44336"      # 红色
    }
    
    # 创建节点和边
    nodes = []
    links = []
    
    # 1. 原始内容节点
    original_node = {
        "id": "original_content",
        "name": "原始内容",
        "type": "content",
        "content": content[:100] + "..." if len(content) > 100 else content,
        "level": "original",
        "color": "#2196F3",
        "icon": "📄",
        "description": "待输出的原始内容",
        "size": 40,
        "content_length": len(content)
    }
    nodes.append(original_node)
    
    # 2. 净化内容节点
    sanitized_node = {
        "id": "sanitized_content",
        "name": "净化内容",
        "type": "sanitized",
        "content": assessment["sanitized_content"][:100] + "..." if len(assessment["sanitized_content"]) > 100 else assessment["sanitized_content"],
        "level": "sanitized",
        "color": "#00BCD4",
        "icon": "🧹",
        "description": "经过安全净化的内容",
        "size": 35,
        "sanitization_count": len(assessment["sanitization_log"])
    }
    nodes.append(sanitized_node)
    
    # 3. 安全等级节点
    security_node = {
        "id": "security_level",
        "name": f"安全等级: {assessment['security_level'].upper()}",
        "type": "security",
        "level": assessment["security_level"],
        "color": level_colors.get(assessment["security_level"], "#9E9E9E"),
        "icon": "🛡️",
        "description": f"整体安全等级评估",
        "size": 30,
        "recommendations_count": len(assessment["recommendations"])
    }
    nodes.append(security_node)
    
    # 4. 威胁分析节点
    if assessment["threat_analysis"]["threats_detected"] > 0:
        threat_node = {
            "id": "threat_analysis",
            "name": f"威胁分析 ({assessment['threat_analysis']['threats_detected']})",
            "type": "threat",
            "level": assessment["threat_analysis"]["overall_risk"],
            "color": "#FF5252",
            "icon": "⚠️",
            "description": f"检测到 {assessment['threat_analysis']['threats_detected']} 个威胁",
            "size": 25 + assessment["threat_analysis"]["threats_detected"] * 5,
            "threats": assessment["threat_analysis"]["threats"]
        }
        nodes.append(threat_node)
    
    # 5. 权限隔离节点
    permission_node = {
        "id": "permission_isolation",
        "name": "权限隔离",
        "type": "permission",
        "level": "isolation",
        "color": "#7E57C2",
        "icon": "🔐",
        "description": f"权限隔离状态: {assessment['permission_check']['isolation_status']}",
        "size": 25,
        "isolation_required": assessment["permission_check"]["requires_isolation"]
    }
    nodes.append(permission_node)
    
    # 6. 秘密检测节点
    if len(assessment["detected_secrets"]) > 0:
        secret_node = {
            "id": "secret_detection",
            "name": f"秘密检测 ({len(assessment['detected_secrets'])})",
            "type": "secret",
            "level": "secrets",
            "color": "#D32F2F",
            "icon": "🔑",
            "description": f"检测到 {len(assessment['detected_secrets'])} 个敏感信息",
            "size": 25 + len(assessment["detected_secrets"]) * 3,
            "secrets": assessment["detected_secrets"]
        }
        nodes.append(secret_node)
        
        # 为每个检测到的秘密创建子节点
        for i, secret in enumerate(assessment["detected_secrets"]):
            secret_sub_node = {
                "id": f"secret_{i}",
                "name": secret["name"],
                "type": "secret_item",
                "level": secret["classification"],
                "color": classification_colors.get(secret["classification"], "#9E9E9E"),
                "icon": "🔒",
                "description": secret["description"],
                "size": 15 + secret["confidence"] * 10,
                "confidence": secret["confidence"],
                "masked_value": secret["masked_value"]
            }
            nodes.append(secret_sub_node)
            
            # 连接秘密检测节点到具体秘密节点
            links.append({
                "source": "secret_detection",
                "target": f"secret_{i}",
                "relationship": "contains",
                "strength": secret["confidence"],
                "value": secret["confidence"] * 10
            })
    
    # 7. 净化步骤节点
    for i, sanitizer in enumerate(assessment["sanitization_log"]):
        sanitizer_node = {
            "id": f"sanitizer_{i}",
            "name": sanitizer["name"],
            "type": "sanitizer",
            "level": "sanitization",
            "color": "#009688",
            "icon": "⚙️",
            "description": sanitizer["description"],
            "size": 15 + sanitizer["matches_count"] * 2,
            "matches_count": sanitizer["matches_count"]
        }
        nodes.append(sanitizer_node)
        
        # 连接原始内容到净化步骤
        links.append({
            "source": "original_content",
            "target": f"sanitizer_{i}",
            "relationship": "sanitized_by",
            "strength": 0.8,
            "value": 5
        })
    
    # 创建主要连接
    links.extend([
        {
            "source": "original_content",
            "target": "sanitized_content",
            "relationship": "sanitized_to",
            "strength": 0.9,
            "value": 10
        },
        {
            "source": "sanitized_content",
            "target": "security_level",
            "relationship": "assessed_by",
            "strength": 0.8,
            "value": 8
        },
        {
            "source": "security_level",
            "target": "permission_isolation",
            "relationship": "requires",
            "strength": 0.7,
            "value": 6
        }
    ])
    
    # 连接威胁分析节点
    if assessment["threat_analysis"]["threats_detected"] > 0:
        links.append({
            "source": "sanitized_content",
            "target": "threat_analysis",
            "relationship": "analyzed_for",
            "strength": 0.8,
            "value": 8
        })
    
    # 连接秘密检测节点
    if len(assessment["detected_secrets"]) > 0:
        links.append({
            "source": "sanitized_content",
            "target": "secret_detection",
            "relationship": "scanned_for",
            "strength": 0.9,
            "value": 10
        })
    
    # 生成HTML
    html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
            box-shadow: 0 0 50px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
            position: relative;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.2em;
            font-weight: 300;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .security-overview {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .overview-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }}
        
        .overview-card:hover {{
            transform: translateY(-5px);
            border-color: #667eea;
        }}
        
        .overview-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .overview-label {{
            color: #666;
            font-size: 0.9em;
            font-weight: 500;
        }}
        
        .security-secure {{ color: #4CAF50; }}
        .security-caution {{ color: #FF9800; }}
        .security-warning {{ color: #FF5722; }}
        .security-blocked {{ color: #F44336; }}
        
        .graph-container {{
            height: 600px;
            margin: 0 30px 30px 30px;
            border-radius: 15px;
            background: #fafafa;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.1);
            position: relative;
            overflow: hidden;
        }}
        
        .graph-container svg {{
            width: 100%;
            height: 100%;
        }}
        
        .node {{
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .node circle {{
            stroke: #fff;
            stroke-width: 3px;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2));
            transition: all 0.3s ease;
        }}
        
        .node:hover circle {{
            stroke-width: 5px;
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.3));
        }}
        
        .node text {{
            font-size: 12px;
            pointer-events: none;
            text-anchor: middle;
            fill: #333;
            font-weight: 500;
        }}
        
        .link {{
            fill: none;
            stroke-opacity: 0.6;
            transition: all 0.3s ease;
        }}
        
        .tooltip {{
            position: absolute;
            padding: 20px;
            background: rgba(0, 0, 0, 0.95);
            color: white;
            border-radius: 12px;
            font-size: 14px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s ease;
            max-width: 400px;
            z-index: 1000;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
        }}
        
        .controls {{
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
            justify-content: center;
        }}
        
        .btn {{
            padding: 12px 24px;
            border: none;
            border-radius: 25px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }}
        
        .recommendations {{
            padding: 30px;
            background: linear-gradient(135deg, #e7f3ff, #f0f8ff);
            border-left: 4px solid #667eea;
        }}
        
        .recommendations h3 {{
            margin: 0 0 20px 0;
            color: #667eea;
            font-size: 1.3em;
        }}
        
        .recommendations ul {{
            margin: 0;
            padding-left: 20px;
        }}
        
        .recommendations li {{
            margin: 12px 0;
            font-size: 1.05em;
            line-height: 1.5;
        }}
        
        .footer {{
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
        }}
        
        .footer p {{
            margin: 5px 0;
            opacity: 0.9;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .security-overview {{
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
                padding: 20px;
            }}
            
            .graph-container {{
                height: 400px;
                margin: 0 20px 20px 20px;
            }}
            
            .controls {{
                padding: 15px 20px;
            }}
            
            .btn {{
                padding: 10px 20px;
                font-size: 13px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ {title}</h1>
            <p>输出层级安全层策略系统 - 基于GitHub安全架构的专业级保护</p>
        </div>
        
        <div class="security-overview">
            <div class="overview-card">
                <div class="overview-value security-{assessment['security_level']}">{assessment['security_level'].upper()}</div>
                <div class="overview-label">安全等级</div>
            </div>
            <div class="overview-card">
                <div class="overview-value">{len(assessment['detected_secrets'])}</div>
                <div class="overview-label">检测到秘密</div>
            </div>
            <div class="overview-card">
                <div class="overview-value">{assessment['threat_analysis']['threats_detected']}</div>
                <div class="overview-label">威胁数量</div>
            </div>
            <div class="overview-card">
                <div class="overview-value">{len(assessment['sanitization_log'])}</div>
                <div class="overview-label">净化步骤</div>
            </div>
            <div class="overview-card">
                <div class="overview-value">{len(assessment['recommendations'])}</div>
                <div class="overview-label">安全建议</div>
            </div>
            <div class="overview-card">
                <div class="overview-value">{'✅' if assessment['permission_check']['requires_isolation'] else '⚠️'}</div>
                <div class="overview-label">权限隔离</div>
            </div>
        </div>
        
        <div class="graph-container" id="graph"></div>
        
        <div class="controls">
            <button class="btn" onclick="resetZoom()">🔄 重置视图</button>
            <button class="btn" onclick="toggleLabels()">🏷️ 切换标签</button>
            <button class="btn" onclick="toggleForce()">⏸️ 暂停动画</button>
            <button class="btn" onclick="showDetails()">📋 查看详情</button>
            <button class="btn" onclick="exportData()">📤 导出数据</button>
        </div>
        
        <div class="recommendations">
            <h3>💡 安全建议</h3>
            <ul>
                {''.join(f'<li>{rec}</li>' for rec in assessment['recommendations'])}
            </ul>
        </div>
        
        <div class="footer">
            <p><strong>🛡️ 输出层级安全层策略系统</strong></p>
            <p>基于GitHub Agentic Workflows安全架构，提供企业级输出保护</p>
            <p><small>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small></p>
        </div>
    </div>
    
    <div class="tooltip" id="tooltip"></div>
    
    <script>
        // 数据
        const data = {json.dumps({"nodes": nodes, "links": links}, indent=2)};
        
        // 设置SVG尺寸
        const container = document.getElementById('graph');
        const width = container.clientWidth;
        const height = 600;
        
        // 创建SVG
        const svg = d3.select("#graph")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
        
        // 创建缩放行为
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => {{
                containerGroup.attr("transform", event.transform);
            }});
        
        svg.call(zoom);
        
        // 创建容器
        const containerGroup = svg.append("g");
        
        // 创建力导向图
        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links)
                .id(d => d.id)
                .distance(120)
                .strength(d => d.strength))
            .force("charge", d3.forceManyBody().strength(-400))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => d.size + 5));
        
        // 创建边
        const link = containerGroup.append("g")
            .selectAll("line")
            .data(data.links)
            .enter().append("line")
            .attr("class", "link")
            .attr("stroke", "#999")
            .attr("stroke-width", d => Math.sqrt(d.value))
            .attr("stroke-opacity", d => d.strength);
        
        // 创建节点
        const node = containerGroup.append("g")
            .selectAll("g")
            .data(data.nodes)
            .enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // 添加圆形
        node.append("circle")
            .attr("r", d => d.size)
            .attr("fill", d => d.color)
            .on("mouseover", showTooltip)
            .on("mouseout", hideTooltip)
            .on("click", nodeClick);
        
        // 添加图标
        node.append("text")
            .attr("dy", ".35em")
            .style("font-size", d => d.size * 0.4 + "px")
            .style("pointer-events", "none")
            .text(d => d.icon);
        
        // 添加标签
        const labels = node.append("text")
            .attr("dy", d => d.size + 18)
            .style("font-size", "12px")
            .style("text-anchor", "middle")
            .style("fill", "#333")
            .style("font-weight", "500")
            .style("pointer-events", "none")
            .text(d => d.name);
        
        // 更新位置
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        // 拖拽函数
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        // 工具提示
        const tooltip = document.getElementById("tooltip");
        
        function showTooltip(event, d) {{
            let content = `<strong>${{d.name}}</strong><br>`;
            content += `类型: ${{d.type}}<br>`;
            content += `等级: ${{d.level}}<br>`;
            
            if (d.content_length) {{
                content += `内容长度: ${{d.content_length}}<br>`;
            }}
            
            if (d.confidence) {{
                content += `置信度: ${{(d.confidence * 100).toFixed(1)}}%<br>`;
            }}
            
            if (d.matches_count) {{
                content += `匹配次数: ${{d.matches_count}}<br>`;
            }}
            
            if (d.masked_value) {{
                content += `<br><strong>脱敏值:</strong> ${{d.masked_value}}`;
            }}
            
            if (d.description) {{
                content += `<br><br><strong>描述:</strong> ${{d.description}}`;
            }}
            
            if (d.content && d.content !== d.name) {{
                content += `<br><br><strong>内容:</strong> ${{d.content.substring(0, 100)}}${{d.content.length > 100 ? '...' : ''}}`;
            }}
            
            tooltip.innerHTML = content;
            tooltip.style.left = event.pageX + 15 + "px";
            tooltip.style.top = event.pageY - 10 + "px";
            tooltip.style.opacity = 1;
        }}
        
        function hideTooltip() {{
            tooltip.style.opacity = 0;
        }}
        
        // 节点点击
        function nodeClick(event, d) {{
            let details = `📋 节点详情\\n\\n`;
            details += `名称: ${{d.name}}\\n`;
            details += `类型: ${{d.type}}\\n`;
            details += `等级: ${{d.level}}\\n`;
            
            if (d.confidence) {{
                details += `置信度: ${{(d.confidence * 100).toFixed(1)}}%\\n`;
            }}
            
            if (d.description) {{
                details += `\\n描述: ${{d.description}}`;
            }}
            
            if (d.content) {{
                details += `\\n内容: ${{d.content}}`;
            }}
            
            alert(details);
        }}
        
        // 控制函数
        function resetZoom() {{
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity.translate(0, 0).scale(1)
            );
        }}
        
        let labelsVisible = true;
        function toggleLabels() {{
            labelsVisible = !labelsVisible;
            labels.style("display", labelsVisible ? "block" : "none");
        }}
        
        let forceRunning = true;
        function toggleForce() {{
            if (forceRunning) {{
                simulation.stop();
                document.querySelector('.btn:nth-child(3)').innerHTML = '▶️ 继续动画';
            }} else {{
                simulation.restart();
                document.querySelector('.btn:nth-child(3)').innerHTML = '⏸️ 暂停动画';
            }}
            forceRunning = !forceRunning;
        }}
        
        function showDetails() {{
            let details = `📋 安全分析详情\\n\\n`;
            details += `🔍 原始内容长度: ${{data.nodes.find(n => n.id === 'original_content').content_length}}\\n`;
            details += `🧹 净化步骤数: ${{data.nodes.find(n => n.id === 'sanitized_content').sanitization_count}}\\n`;
            details += `🛡️ 安全等级: ${{data.nodes.find(n => n.id === 'security_level').name}}\\n`;
            details += `🔑 检测秘密数: ${{data.nodes.find(n => n.id === 'secret_detection')?.secrets?.length || 0}}\\n`;
            details += `⚠️ 威胁数量: ${{data.nodes.find(n => n.id === 'threat_analysis')?.threats?.length || 0}}\\n`;
            details += `🔐 权限隔离: ${{data.nodes.find(n => n.id === 'permission_isolation').isolation_required ? '需要' : '不需要'}}\\n`;
            
            alert(details);
        }}
        
        function exportData() {{
            const exportData = {{
                timestamp: new Date().toISOString(),
                security_assessment: {json.dumps(assessment, indent=2)},
                graph_data: data
            }};
            
            const blob = new Blob([JSON.stringify(exportData, null, 2)], {{type: 'application/json'}});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_analysis_output.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }}
        
        // 响应式调整
        window.addEventListener("resize", () => {{
            const newWidth = container.clientWidth;
            svg.attr("width", newWidth);
            simulation.force("center", d3.forceCenter(newWidth / 2, height / 2));
            simulation.alpha(0.3).restart();
        }});
        
        // 添加初始动画效果
        setTimeout(() => {{
            simulation.alpha(0.3).restart();
        }}, 1000);
    </script>
</body>
</html>
"""
    
    return html_content

def create_output_security_demo():
    """创建输出安全层级演示"""
    print("🛡️ OpenClaw 输出层级安全层策略演示")
    print("=" * 70)
    print("基于GitHub Agentic Workflows安全架构的专业级输出保护")
    print()
    
    # 测试用例
    test_cases = [
        {
            "name": "API密钥泄露",
            "content": "请使用以下API密钥访问服务：api_key=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
            "description": "检测API密钥泄露风险"
        },
        {
            "name": "数据库连接信息",
            "content": "数据库连接字符串：mysql://user:password123@192.168.1.100:3306/mydatabase",
            "description": "检测数据库连接信息泄露"
        },
        {
            "name": "用户隐私信息",
            "content": "用户信息：张三，电话13812345678，邮箱zhangsan@example.com，身份证号110101199001011234",
            "description": "检测用户隐私信息泄露"
        },
        {
            "name": "XSS攻击尝试",
            "content": "用户输入：<script>alert('XSS攻击')</script>，请访问http://evil.com获取更多信息",
            "description": "检测XSS攻击和恶意URL"
        },
        {
            "name": "正常安全内容",
            "content": "今天天气很好，适合出门散步。建议做好防晒措施，多喝水保持健康。",
            "description": "正常内容示例"
        }
    ]
    
    # 创建输出目录
    output_dir = Path("output_security_demo")
    output_dir.mkdir(exist_ok=True)
    
    print(f"📁 输出目录: {output_dir.absolute()}")
    print()
    
    # 处理每个测试用例
    for i, test_case in enumerate(test_cases, 1):
        print(f"--- 输出安全分析 {i}: {test_case['name']} ---")
        print(f"内容: {test_case['content']}")
        print(f"描述: {test_case['description']}")
        
        # 生成输出安全力导向图
        html_content = create_output_security_force_graph(
            test_case['content'], 
            f"输出安全分析 - {test_case['name']}"
        )
        
        # 保存文件
        filename = output_dir / f"output_security_{i}_{test_case['name'].replace(' ', '_')}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ 已保存: {filename}")
        print(f"📏 文件大小: {len(html_content)/1024:.1f}KB")
        print()
    
    # 生成预览页面
    preview_html = create_output_security_preview_page(test_cases, output_dir)
    preview_file = output_dir / "index.html"
    
    with open(preview_file, 'w', encoding='utf-8') as f:
        f.write(preview_html)
    
    print(f"🌐 预览页面: {preview_file.absolute()}")
    
    # 自动打开浏览器
    try:
        webbrowser.open(f"file://{preview_file.absolute()}")
        print("🚀 已在浏览器中打开输出安全分析演示页面")
    except:
        print("⚠️  无法自动打开浏览器，请手动打开HTML文件")
    
    print(f"\n✅ 输出层级安全层策略演示完成！")
    print(f"📁 所有文件保存在: {output_dir.absolute()}")
    print()
    print("🛡️ 输出安全层级特点:")
    print("• 🔍 基于GitHub Agentic Workflows安全架构")
    print("• 🧹 多层次内容净化处理")
    print("• 🔑 智能秘密检测和脱敏")
    print("• 🔐 权限隔离机制")
    print("• ⚠️ 威胁检测和分析")
    print("• 🎨 专业级力导向图可视化")
    print("• 📊 实时安全评估")
    print("• 💡 企业级安全建议")
    
    return output_dir

def create_output_security_preview_page(test_cases, output_dir):
    """创建输出安全预览页面"""
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw 输出层级安全层策略系统</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            margin-bottom: 40px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .header p {{
            font-size: 1.2em;
            color: #666;
            margin-bottom: 20px;
        }}
        
        .features {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .feature {{
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }}
        
        .feature:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }}
        
        .feature-icon {{
            font-size: 3em;
            margin-bottom: 15px;
        }}
        
        .feature h3 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .demo-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }}
        
        .demo-card {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 6px 25px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }}
        
        .demo-card:hover {{
            border-color: #667eea;
            transform: translateY(-5px);
            box-shadow: 0 12px 35px rgba(102, 126, 234, 0.2);
        }}
        
        .demo-title {{
            font-size: 1.4em;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }}
        
        .demo-description {{
            color: #666;
            margin-bottom: 15px;
            line-height: 1.5;
        }}
        
        .demo-content {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
            word-break: break-all;
        }}
        
        .demo-link {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 15px 30px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        
        .demo-link:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }}
        
        .architecture {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            border-left: 5px solid #667eea;
            box-shadow: 0 6px 25px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }}
        
        .architecture h3 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        .architecture ul {{
            list-style: none;
            padding: 0;
        }}
        
        .architecture li {{
            margin: 15px 0;
            padding-left: 30px;
            position: relative;
            line-height: 1.6;
        }}
        
        .architecture li:before {{
            content: "🛡️";
            position: absolute;
            left: 0;
        }}
        
        .footer {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 6px 25px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header {{
                padding: 30px 20px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .demo-grid {{
                grid-template-columns: 1fr;
                gap: 20px;
            }}
            
            .features {{
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ 输出层级安全层策略系统</h1>
            <p>基于GitHub Agentic Workflows安全架构的专业级输出保护</p>
            <p><strong>直接将要输出的内容做成力导向图，在数据安全方面做出成绩</strong></p>
        </div>
        
        <div class="features">
            <div class="feature">
                <div class="feature-icon">🧹</div>
                <h3>内容净化</h3>
                <p>多层次内容净化处理，确保输出内容的安全性</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔑</div>
                <h3>秘密检测</h3>
                <p>智能检测API密钥、密码、Token等敏感信息</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔐</div>
                <h3>权限隔离</h3>
                <p>基于GitHub安全架构的权限隔离机制</p>
            </div>
            <div class="feature">
                <div class="feature-icon">⚠️</div>
                <h3>威胁检测</h3>
                <p>实时威胁检测和分析，提供安全预警</p>
            </div>
        </div>
        
        <div class="architecture">
            <h3>🏗️ 安全架构特点</h3>
            <ul>
                <li><strong>内容净化管道：</strong> @用户名中性化、机器人触发保护、XML/HTML标签转换、URL过滤、控制字符移除</li>
                <li><strong>秘密检测引擎：</strong> API密钥、密码、Token、私钥、数据库连接、邮箱、手机号、身份证、银行卡</li>
                <li><strong>权限隔离机制：</strong> 读写权限分离、安全输出作业、最小权限原则</li>
                <li><strong>威胁检测系统：</strong> 数据泄露检测、注入攻击检测、异常内容检测</li>
                <li><strong>力导向图可视化：</strong> 专业级D3.js可视化，直观展示安全状态</li>
            </ul>
        </div>
        
        <div class="demo-grid">
"""
    
    for i, test_case in enumerate(test_cases, 1):
        html += f"""
            <div class="demo-card">
                <div class="demo-title">🔍 安全分析 {i}: {test_case['name']}</div>
                <div class="demo-description">{test_case['description']}</div>
                <div class="demo-content">{test_case['content'][:80]}{'...' if len(test_case['content']) > 80 else ''}</div>
                <a href="output_security_{i}_{test_case['name'].replace(' ', '_')}.html" class="demo-link" target="_blank">
                    🛡️ 查看安全分析 →
                </a>
            </div>
"""
    
    html += f"""
        </div>
        
        <div class="footer">
            <h3>🌟 系统优势</h3>
            <p>基于GitHub Agentic Workflows安全架构，提供企业级输出安全保护</p>
            <p>通过专业级力导向图可视化，让安全状态一目了然</p>
            <p><small>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small></p>
        </div>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    print("🛡️ OpenClaw 输出层级安全层策略系统")
    print("=" * 70)
    print("基于GitHub Agentic Workflows安全架构的专业级输出保护")
    print("直接将要输出的内容做成力导向图，在数据安全方面做出成绩")
    print()
    
    try:
        output_dir = create_output_security_demo()
        
        print(f"\n🎯 输出层级安全层策略演示完成！")
        print(f"📁 演示文件保存在: {output_dir}")
        print(f"🌐 请在浏览器中查看输出安全分析效果")
        print()
        print("💡 核心优势:")
        print("• 🏗️ 基于GitHub Agentic Workflows安全架构")
        print("• 🧹 多层次内容净化管道")
        print("• 🔑 智能秘密检测和脱敏")
        print("• 🔐 权限隔离机制")
        print("• ⚠️ 威胁检测和分析")
        print("• 🎨 专业级力导向图可视化")
        print("• 📊 实时安全评估")
        print("• 💡 企业级安全建议")
        print()
        print("🚀 立即体验:")
        print(f"• 打开 {output_dir}/index.html 查看演示首页")
        print("• 点击各个演示链接查看不同类型的安全分析")
        print("• 体验完整的输出层级安全保护功能")
        
    except KeyboardInterrupt:
        print("\n⏹️  演示被中断")
    except Exception as e:
        print(f"❌ 演示失败: {e}")
        import traceback
        traceback.print_exc()
