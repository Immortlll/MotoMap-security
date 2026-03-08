"""
OpenClaw 增强安全客户端SDK
融合Sub2API的安全特性和我们的数据分级系统
"""

import requests
import json
import time
from typing import List, Dict, Optional, Union
from dataclasses import dataclass
import logging
from datetime import datetime

@dataclass
class EnhancedFilterResult:
    """增强过滤结果"""
    success: bool
    filtered_content: str
    is_blocked: bool
    security_actions: List[str]
    risk_score: float
    threats_detected: List[Dict]
    enhanced_mode: bool
    timestamp: str
    original_length: Optional[int] = None
    filtered_length: Optional[int] = None
    api_key_info: Optional[Dict] = None

@dataclass
class SecurityScanResult:
    """安全扫描结果"""
    success: bool
    security_status: str
    risk_score: float
    threats_detected: List[Dict]
    recommendations: List[str]
    timestamp: str

@dataclass
class APIKeyInfo:
    """API密钥信息"""
    api_key: str
    permissions: List[str]
    created_at: str
    key_prefix: str

class EnhancedOpenClawClient:
    """增强的OpenClaw安全客户端"""
    
    def __init__(self, base_url: str = "http://localhost:5000", api_key: str = None, timeout: int = 30):
        """
        初始化增强客户端
        
        Args:
            base_url: API服务器地址
            api_key: API密钥（可选，也可以通过set_api_key设置）
            timeout: 请求超时时间（秒）
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.api_key = api_key
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        # 设置默认请求头
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'OpenClaw-Enhanced-SDK/2.0'
        })
    
    def set_api_key(self, api_key: str):
        """设置API密钥"""
        self.api_key = api_key
        self.session.headers['X-API-Key'] = api_key
    
    def generate_api_key(self, user_id: str, permissions: List[str] = None) -> APIKeyInfo:
        """
        生成新的API密钥
        
        Args:
            user_id: 用户ID
            permissions: 权限列表
            
        Returns:
            APIKeyInfo: API密钥信息
        """
        try:
            data = {
                "user_id": user_id,
                "permissions": permissions or ["read", "filter"]
            }
            
            response = self.session.post(
                f"{self.base_url}/api/keys",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return APIKeyInfo(
                    api_key=result['api_key'],
                    permissions=result['permissions'],
                    created_at=result['created_at'],
                    key_prefix=result['api_key'][:20] + '...'
                )
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API key generation failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def list_api_keys(self) -> List[Dict]:
        """列出用户的API密钥"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/keys",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result['keys']
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API key list failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def enhanced_filter(self, 
                     content: str, 
                     enhanced_mode: bool = True,
                     return_details: bool = False) -> EnhancedFilterResult:
        """
        增强内容过滤
        
        Args:
            content: 待过滤的内容
            enhanced_mode: 是否使用增强安全模式
            return_details: 是否返回详细信息
            
        Returns:
            EnhancedFilterResult: 增强过滤结果
        """
        try:
            data = {
                "content": content,
                "enhanced_mode": enhanced_mode,
                "return_details": return_details
            }
            
            response = self.session.post(
                f"{self.base_url}/filter",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                return EnhancedFilterResult(
                    success=result_data['success'],
                    filtered_content=result_data['filtered_content'],
                    is_blocked=result_data['is_blocked'],
                    security_actions=result_data['security_actions'],
                    risk_score=result_data['risk_score'],
                    threats_detected=result_data.get('threats_detected', []),
                    enhanced_mode=result_data['enhanced_mode'],
                    timestamp=result_data['timestamp'],
                    original_length=result_data.get('original_length'),
                    filtered_length=result_data.get('filtered_length'),
                    api_key_info=result_data.get('api_key_info')
                )
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Enhanced filter failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def security_scan(self, content: str) -> SecurityScanResult:
        """
        执行安全扫描
        
        Args:
            content: 待扫描的内容
            
        Returns:
            SecurityScanResult: 安全扫描结果
        """
        try:
            data = {"content": content}
            
            response = self.session.post(
                f"{self.base_url}/security/scan",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                return SecurityScanResult(
                    success=result_data['success'],
                    security_status=result_data['security_status'],
                    risk_score=result_data['risk_score'],
                    threats_detected=result_data['threats_detected'],
                    recommendations=result_data['recommendations'],
                    timestamp=result_data['timestamp']
                )
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Security scan failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def get_security_metrics(self) -> Dict:
        """获取安全指标"""
        try:
            response = self.session.get(
                f"{self.base_url}/security/metrics",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result['metrics']
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Security metrics failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def get_security_config(self) -> Dict:
        """获取安全配置"""
        try:
            response = self.session.get(
                f"{self.base_url}/security/config",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result['config']
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Security config failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def update_security_config(self, section: str, key: str, value) -> bool:
        """更新安全配置"""
        try:
            data = {
                "section": section,
                "key": key,
                "value": value
            }
            
            response = self.session.post(
                f"{self.base_url}/security/config",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return True
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Security config update failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def health_check(self) -> Dict:
        """健康检查"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Health check failed: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Health check failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def close(self):
        """关闭客户端连接"""
        self.session.close()

# 便捷函数
def quick_enhanced_filter(content: str, 
                        api_url: str = "http://localhost:5000",
                        api_key: str = None) -> EnhancedFilterResult:
    """
    快速增强过滤函数
    
    Args:
        content: 待过滤的内容
        api_url: API服务器地址
        api_key: API密钥
        
    Returns:
        EnhancedFilterResult: 增强过滤结果
    """
    client = EnhancedOpenClawClient(api_url, api_key)
    try:
        result = client.enhanced_filter(content)
        if result.is_blocked:
            raise Exception(f"内容被安全系统拦截: {result.filtered_content}")
        return result
    finally:
        client.close()

def quick_security_scan(content: str,
                    api_url: str = "http://localhost:5000",
                    api_key: str = None) -> SecurityScanResult:
    """
    快速安全扫描函数
    
    Args:
        content: 待扫描的内容
        api_url: API服务器地址
        api_key: API密钥
        
    Returns:
        SecurityScanResult: 安全扫描结果
    """
    client = EnhancedOpenClawClient(api_url, api_key)
    try:
        return client.security_scan(content)
    finally:
        client.close()

# 装饰器
def enhanced_secure_output(api_url: str = "http://localhost:5000", 
                        api_key: str = None,
                        enhanced_mode: bool = True):
    """
    增强安全输出装饰器
    
    Usage:
        @enhanced_secure_output(api_url="http://localhost:5000", api_key="your_key")
        def my_function():
            return "用户手机号13812345678"
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 执行原函数
            result = func(*args, **kwargs)
            
            # 如果结果是字符串，进行增强安全过滤
            if isinstance(result, str):
                client = EnhancedOpenClawClient(api_url, api_key)
                try:
                    filter_result = client.enhanced_filter(result, enhanced_mode=enhanced_mode)
                    if filter_result.is_blocked:
                        raise Exception(f"输出被增强安全过滤器拦截: {filter_result.filtered_content}")
                    return filter_result.filtered_content
                finally:
                    client.close()
            
            return result
        return wrapper
    return decorator

# 增强中间件
class EnhancedSecurityMiddleware:
    """增强安全中间件"""
    
    def __init__(self, api_url: str = "http://localhost:5000", api_key: str = None):
        self.api_url = api_url
        self.client = EnhancedOpenClawClient(api_url, api_key)
    
    def process_response(self, response_content: str, enhanced_mode: bool = True) -> str:
        """处理响应内容"""
        try:
            result = self.client.enhanced_filter(response_content, enhanced_mode=enhanced_mode)
            if result.is_blocked:
                raise Exception(f"响应内容被增强安全系统拦截: {result.filtered_content}")
            return result.filtered_content
        except Exception as e:
            self.logger.error(f"Enhanced security middleware error: {e}")
            raise
    
    def security_scan(self, content: str) -> SecurityScanResult:
        """安全扫描内容"""
        return self.client.security_scan(content)
    
    def close(self):
        """关闭中间件"""
        self.client.close()
