"""
OpenClaw 安全过滤中间件
实现输出内容的检测、分级和防护处理
"""

import re
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from security_config import SecurityLevel, SecurityConfig

@dataclass
class FilterResult:
    """过滤结果数据类"""
    is_blocked: bool
    security_level: Optional[SecurityLevel]
    filtered_content: str
    detected_patterns: List[str]
    action_taken: str
    risk_score: float

class SecurityFilter:
    """安全过滤器主类"""
    
    def __init__(self, enable_audit: bool = True):
        self.enable_audit = enable_audit
        self.logger = self._setup_logger()
        
        # 预编译正则表达式以提高性能
        self.compiled_patterns = self._compile_patterns()
        
    def _setup_logger(self) -> logging.Logger:
        """设置日志记录器"""
        logger = logging.getLogger('OpenClawSecurity')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _compile_patterns(self) -> Dict[SecurityLevel, List[re.Pattern]]:
        """预编译所有检测模式"""
        compiled = {}
        for level, patterns in SecurityConfig.DETECTION_RULES.items():
            compiled[level] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        return compiled
    
    def _calculate_risk_score(self, detections: Dict[SecurityLevel, List[str]]) -> float:
        """计算风险评分"""
        level_weights = {
            SecurityLevel.L4_TOP_SECRET: 10.0,
            SecurityLevel.L3_CONFIDENTIAL: 5.0,
            SecurityLevel.L2_INTERNAL: 2.0,
            SecurityLevel.L1_PUBLIC: 0.1
        }
        
        total_score = 0.0
        for level, patterns in detections.items():
            weight = level_weights.get(level, 0.1)
            total_score += len(patterns) * weight
            
        return min(total_score, 100.0)  # 限制最高分值为100
    
    def _detect_sensitive_data(self, content: str) -> Dict[SecurityLevel, List[str]]:
        """检测敏感数据"""
        detections = {level: [] for level in SecurityLevel}
        
        # 正则表达式检测
        for level, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(content)
                if matches:
                    detections[level].extend([f"Regex: {pattern.pattern}"] * len(matches))
        
        # 关键词检测
        for level, keywords in SecurityConfig.SENSITIVE_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in content.lower():
                    detections[level].append(f"Keyword: {keyword}")
        
        return detections
    
    def _mask_sensitive_content(self, content: str, level: SecurityLevel) -> str:
        """脱敏处理"""
        if level == SecurityLevel.L3_CONFIDENTIAL:
            masked_content = content
            
            # 手机号脱敏 - 修复正则
            phone_pattern = re.compile(r'1[3-9]\d{9}')
            def mask_phone(match):
                phone = match.group(0)
                return phone[:3] + '****' + phone[-4:]
            masked_content = phone_pattern.sub(mask_phone, masked_content)
            
            # 身份证号脱敏 - 修复正则
            id_pattern = re.compile(r'[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]')
            def mask_id(match):
                id_card = match.group(0)
                return id_card[:6] + '********' + id_card[-4:]
            masked_content = id_pattern.sub(mask_id, masked_content)
            
            # 邮箱脱敏 - 修复正则
            email_pattern = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
            def mask_email(match):
                email = match.group(0)
                local, domain = email.split('@')
                return local[0] + '***@' + domain
            masked_content = email_pattern.sub(mask_email, masked_content)
            
            # 银行卡号脱敏 - 修复正则
            bank_pattern = re.compile(r'\d{16,19}')
            def mask_bank(match):
                bank = match.group(0)
                if len(bank) >= 8:
                    return bank[:4] + '****' + bank[-4:]
                return bank
            masked_content = bank_pattern.sub(mask_bank, masked_content)
            
            return masked_content
        
        return content
    
    def _add_watermark(self, content: str) -> str:
        """添加水印"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        content_hash = hashlib.md5(content.encode()).hexdigest()[:8]
        watermark = f"\n\n[OpenClaw-Internal-{timestamp}-{content_hash}]"
        return content + watermark
    
    def _log_audit(self, content: str, result: FilterResult, user_id: str = "anonymous"):
        """记录审计日志"""
        if not self.enable_audit:
            return
            
        audit_data = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "content_length": len(content),
            "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
            "is_blocked": result.is_blocked,
            "security_level": result.security_level.value if result.security_level else None,
            "action_taken": result.action_taken,
            "risk_score": result.risk_score,
            "detected_patterns": result.detected_patterns
        }
        
        self.logger.info(f"AUDIT: {audit_data}")
    
    def filter_content(self, content: str, user_id: str = "anonymous") -> FilterResult:
        """
        主要过滤方法
        
        Args:
            content: 待过滤的内容
            user_id: 用户ID（用于审计）
            
        Returns:
            FilterResult: 过滤结果
        """
        # 检测敏感数据
        detections = self._detect_sensitive_data(content)
        
        # 确定最高安全等级
        highest_level = None
        all_patterns = []
        
        for level in [SecurityLevel.L4_TOP_SECRET, SecurityLevel.L3_CONFIDENTIAL, SecurityLevel.L2_INTERNAL]:
            if detections[level]:
                highest_level = level
                all_patterns.extend(detections[level])
                break  # 找到最高等级就停止
        
        # 计算风险评分
        risk_score = self._calculate_risk_score(detections)
        
        # 根据安全等级执行相应操作
        if highest_level == SecurityLevel.L4_TOP_SECRET:
            # 完全阻断
            result = FilterResult(
                is_blocked=True,
                security_level=highest_level,
                filtered_content="[BLOCKED] 内容包含极度敏感信息，已被系统拦截",
                detected_patterns=all_patterns,
                action_taken="blocked",
                risk_score=risk_score
            )
        
        elif highest_level == SecurityLevel.L3_CONFIDENTIAL:
            # 脱敏处理
            masked_content = self._mask_sensitive_content(content, highest_level)
            result = FilterResult(
                is_blocked=False,
                security_level=highest_level,
                filtered_content=masked_content,
                detected_patterns=all_patterns,
                action_taken="masked",
                risk_score=risk_score
            )
        
        elif highest_level == SecurityLevel.L2_INTERNAL:
            # 受控输出（添加水印）
            watermarked_content = self._add_watermark(content)
            result = FilterResult(
                is_blocked=False,
                security_level=highest_level,
                filtered_content=watermarked_content,
                detected_patterns=all_patterns,
                action_taken="watermarked",
                risk_score=risk_score
            )
        
        else:
            # 公开信息，直接放行
            result = FilterResult(
                is_blocked=False,
                security_level=SecurityLevel.L1_PUBLIC,
                filtered_content=content,
                detected_patterns=[],
                action_taken="allowed",
                risk_score=risk_score
            )
        
        # 记录审计日志
        self._log_audit(content, result, user_id)
        
        return result

# 便捷函数
def filter_openclaw_output(content: str, user_id: str = "anonymous") -> str:
    """
    便捷的过滤函数，直接返回过滤后的内容
    
    Args:
        content: OpenClaw输出内容
        user_id: 用户ID
        
    Returns:
        str: 过滤后的内容
    """
    filter_instance = SecurityFilter()
    result = filter_instance.filter_content(content, user_id)
    
    if result.is_blocked:
        raise SecurityException(f"内容被拦截: {result.filtered_content}")
    
    return result.filtered_content

class SecurityException(Exception):
    """安全异常类"""
    pass
