"""
OpenClaw 安全过滤器
数据安全分级防护系统 - 增强版本 + 威胁可视化 + D3.js交互图
"""

__version__ = "2.2.0"
__author__ = "OpenClaw Security Team"
__description__ = "数据安全分级防护系统，融合Sub2API安全特性，提供威胁力导向图可视化和D3.js交互图表，为OpenClaw输出端提供增强安全阀门"

# 导入核心功能
from .core.filter import SecurityFilter, filter_openclaw_output, SecurityException
from .core.config import SecurityLevel, SecurityConfig

# 导入增强功能
from .core.security_enhancements import (
    EnhancedSecurityFilter, 
    security_config,
    ThreatLevel,
    SecurityContext
)

# 导入可视化功能
from .visualization.threat_graph import (
    ThreatGraphVisualizer,
    ThreatNode,
    ThreatEdge,
    ThreatType,
    create_threat_visualization
)

# 导入D3.js可视化功能
from .visualization.d3_force_graph import (
    D3ForceGraphGenerator,
    create_d3_force_graph,
    save_d3_graph
)

# 导入客户端
from .client.sdk import OpenClawSecurityClient, quick_filter, secure_output
from .client.enhanced_sdk import (
    EnhancedOpenClawClient, 
    quick_enhanced_filter, 
    quick_security_scan,
    enhanced_secure_output,
    EnhancedSecurityMiddleware
)
from .client.visualization_client import (
    ThreatVisualizationClient,
    quick_visualize,
    quick_analyze,
    threat_aware_output,
    ThreatAwareMiddleware
)
from .client.d3_client import (
    D3VisualizationClient,
    quick_d3_graph,
    quick_d3_demo,
    d3_aware_output,
    D3AwareMiddleware
)

# 导入API创建函数
from .api.flask_server import create_flask_app
from .api.fastapi_server import create_fastapi_app
from .api.enhanced_server import create_enhanced_server
from .api.visualization_server import create_visualization_server
from .api.d3_server import create_d3_server

__all__ = [
    # 核心功能
    'SecurityFilter',
    'filter_openclaw_output', 
    'SecurityException',
    'SecurityLevel',
    'SecurityConfig',
    
    # 增强功能
    'EnhancedSecurityFilter',
    'security_config',
    'ThreatLevel',
    'SecurityContext',
    
    # 标准可视化功能
    'ThreatGraphVisualizer',
    'ThreatNode',
    'ThreatEdge',
    'ThreatType',
    'create_threat_visualization',
    
    # D3.js可视化功能
    'D3ForceGraphGenerator',
    'create_d3_force_graph',
    'save_d3_graph',
    
    # 标准客户端
    'OpenClawSecurityClient',
    'quick_filter',
    'secure_output',
    
    # 增强客户端
    'EnhancedOpenClawClient',
    'quick_enhanced_filter',
    'quick_security_scan',
    'enhanced_secure_output',
    'EnhancedSecurityMiddleware',
    
    # 可视化客户端
    'ThreatVisualizationClient',
    'quick_visualize',
    'quick_analyze',
    'threat_aware_output',
    'ThreatAwareMiddleware',
    
    # D3.js客户端
    'D3VisualizationClient',
    'quick_d3_graph',
    'quick_d3_demo',
    'd3_aware_output',
    'D3AwareMiddleware',
    
    # API服务器
    'create_flask_app',
    'create_fastapi_app',
    'create_enhanced_server',
    'create_visualization_server',
    'create_d3_server',
]
