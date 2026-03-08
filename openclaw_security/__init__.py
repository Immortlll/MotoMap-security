"""
OpenClaw 安全过滤器
数据安全分级防护系统
"""

__version__ = "1.0.0"
__author__ = "OpenClaw Security Team"
__description__ = "数据安全分级防护系统，为OpenClaw输出端提供安全阀门"

# 导入核心功能
from .core.filter import SecurityFilter, filter_openclaw_output, SecurityException
from .core.config import SecurityLevel, SecurityConfig

# 导入客户端
from .client.sdk import OpenClawSecurityClient, quick_filter, secure_output

__all__ = [
    # 核心功能
    'SecurityFilter',
    'filter_openclaw_output', 
    'SecurityException',
    'SecurityLevel',
    'SecurityConfig',
    
    # 客户端
    'OpenClawSecurityClient',
    'quick_filter',
    'secure_output',
]
