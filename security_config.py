"""
OpenClaw 数据安全分级配置
定义数据安全等级和相关策略
"""

from enum import Enum
from typing import Dict, List, Pattern
import re

class SecurityLevel(Enum):
    """数据安全等级枚举"""
    L1_PUBLIC = "public"           # 公开信息
    L2_INTERNAL = "internal"       # 内部公开
    L3_CONFIDENTIAL = "confidential"  # 高度敏感
    L4_TOP_SECRET = "top_secret"   # 极度敏感

class SecurityConfig:
    """安全配置管理类"""
    
    # 等级定义
    LEVEL_DEFINITIONS = {
        SecurityLevel.L4_TOP_SECRET: {
            "name": "极度敏感 (Top Secret)",
            "description": "核心凭据：数据库密码、API密钥、私钥、核心算法源码、系统Root权限信息",
            "impact": "造成毁灭性打击，可能导致系统被控或资产清空",
            "action": "block"  # 完全阻断
        },
        SecurityLevel.L3_CONFIDENTIAL: {
            "name": "高度敏感 (Confidential)",
            "description": "个人隐私(PII)：身份证号、手机号、家庭住址、详细薪资、健康记录",
            "impact": "法律合规风险（如GDPR/PIPL），损害用户信誉",
            "action": "mask"  # 脱敏处理
        },
        SecurityLevel.L2_INTERNAL: {
            "name": "内部公开 (Internal)",
            "description": "业务逻辑：内部技术架构图、项目进度、非公开产品规划、内部会议纪要",
            "impact": "削弱竞争优势，可能被竞品利用",
            "action": "controlled"  # 受控输出
        },
        SecurityLevel.L1_PUBLIC: {
            "name": "公开信息 (Public)",
            "description": "通用知识：已发布的博客、开源代码、技术文档、产品说明书",
            "impact": "无负面影响",
            "action": "allow"  # 自由输出
        }
    }
    
    # 敏感数据检测规则
    DETECTION_RULES = {
        SecurityLevel.L4_TOP_SECRET: [
            # API密钥模式
            r'(?i)(api[_-]?key|apikey|secret[_-]?key|secretkey)["\']?\s*[:：=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
            # 私钥模式
            r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            # 数据库连接字符串
            r'(?i)(mysql|postgresql|mongodb)://[^\s]+:[^\s]+@[^\s]+',
            # 密码字段 - 支持中英文冒号
            r'(?i)(password|passwd|pwd|密码|密码|口令)["\']?\s*[:：=]\s*["\']?([^\s"\']{6,})["\']?',
        ],
        SecurityLevel.L3_CONFIDENTIAL: [
            # 身份证号
            r'[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]',
            # 手机号
            r'1[3-9]\d{9}',
            # 邮箱地址
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
            # 银行卡号
            r'\d{16,19}',
        ],
        SecurityLevel.L2_INTERNAL: [
            # 内部项目代号
            r'(?i)(project[_-]?|proj[_-]?)(alpha|beta|gamma|delta|epsilon)[_-]?\d*',
            # 内部服务器地址
            r'(?i)(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+',
        ]
    }
    
    # 敏感词库
    SENSITIVE_KEYWORDS = {
        SecurityLevel.L4_TOP_SECRET: [
            'root', 'admin', 'superuser', 'database', 'credentials',
            'private_key', 'access_token', 'refresh_token', 'session_secret'
        ],
        SecurityLevel.L3_CONFIDENTIAL: [
            '身份证', '手机号', '银行卡', '薪资', '工资', '健康记录', '病历',
            'id_card', 'phone_number', 'bank_account', 'salary', 'medical_record'
        ],
        SecurityLevel.L2_INTERNAL: [
            '内部文档', '项目计划', '技术架构', '会议纪要', 'roadmap',
            'internal_doc', 'project_plan', 'tech_architecture', 'meeting_minutes'
        ]
    }
    
    @classmethod
    def get_level_info(cls, level: SecurityLevel) -> Dict:
        """获取等级信息"""
        return cls.LEVEL_DEFINITIONS.get(level, {})
    
    @classmethod
    def get_detection_rules(cls, level: SecurityLevel) -> List[str]:
        """获取检测规则"""
        return cls.DETECTION_RULES.get(level, [])
    
    @classmethod
    def get_sensitive_keywords(cls, level: SecurityLevel) -> List[str]:
        """获取敏感词库"""
        return cls.SENSITIVE_KEYWORDS.get(level, [])
