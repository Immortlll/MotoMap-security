"""
OpenClaw 安全过滤器客户端 SDK
提供便捷的接入方式
"""

import requests
import json
from typing import List, Dict, Optional, Union
from dataclasses import dataclass
import logging

@dataclass
class FilterResult:
    """过滤结果数据类"""
    success: bool
    filtered_content: str
    is_blocked: bool
    action_taken: str
    security_level: Optional[str]
    risk_score: float
    detected_patterns: Optional[List[str]] = None
    original_length: Optional[int] = None
    filtered_length: Optional[int] = None
    timestamp: Optional[str] = None

@dataclass
class SecurityCheckResult:
    """安全检查结果数据类"""
    success: bool
    is_safe: bool
    security_level: str
    risk_score: float
    detected_patterns: Dict[str, List[str]]
    recommendations: List[str]
    timestamp: str

class OpenClawSecurityClient:
    """OpenClaw 安全过滤器客户端"""
    
    def __init__(self, base_url: str = "http://localhost:5000", timeout: int = 30):
        """
        初始化客户端
        
        Args:
            base_url: API服务器地址
            timeout: 请求超时时间（秒）
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
    
    def health_check(self) -> bool:
        """健康检查"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
    
    def filter_content(self, 
                     content: str, 
                     user_id: str = "anonymous",
                     return_details: bool = False) -> FilterResult:
        """
        过滤单个内容
        
        Args:
            content: 待过滤的内容
            user_id: 用户ID
            return_details: 是否返回详细信息
            
        Returns:
            FilterResult: 过滤结果
        """
        try:
            data = {
                "content": content,
                "user_id": user_id,
                "return_details": return_details
            }
            
            response = self.session.post(
                f"{self.base_url}/filter",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                return FilterResult(**result_data)
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def batch_filter(self, 
                    contents: List[str], 
                    user_id: str = "anonymous",
                    return_details: bool = False) -> Dict:
        """
        批量过滤内容
        
        Args:
            contents: 待过滤的内容列表
            user_id: 用户ID
            return_details: 是否返回详细信息
            
        Returns:
            Dict: 批量过滤结果
        """
        try:
            data = {
                "contents": contents,
                "user_id": user_id,
                "return_details": return_details
            }
            
            response = self.session.post(
                f"{self.base_url}/batch_filter",
                json=data,
                timeout=self.timeout * 2  # 批量请求需要更长时间
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Batch request failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def check_security(self, 
                      content: str, 
                      user_id: str = "anonymous") -> SecurityCheckResult:
        """
        安全检查（不修改内容）
        
        Args:
            content: 待检查的内容
            user_id: 用户ID
            
        Returns:
            SecurityCheckResult: 安全检查结果
        """
        try:
            data = {
                "content": content,
                "user_id": user_id
            }
            
            response = self.session.post(
                f"{self.base_url}/check_security",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                return SecurityCheckResult(**result_data)
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Security check failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        try:
            response = self.session.get(f"{self.base_url}/stats", timeout=self.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Stats request failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def close(self):
        """关闭客户端连接"""
        self.session.close()

class OpenClawSecurityAsync:
    """异步客户端（适用于高并发场景）"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        """初始化异步客户端"""
        self.base_url = base_url.rstrip('/')
        self.logger = logging.getLogger(__name__)
    
    async def filter_content(self, content: str, user_id: str = "anonymous") -> FilterResult:
        """异步过滤内容"""
        try:
            import aiohttp
            
            data = {
                "content": content,
                "user_id": user_id,
                "return_details": False
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.base_url}/filter", json=data) as response:
                    if response.status == 200:
                        result_data = await response.json()
                        return FilterResult(**result_data)
                    else:
                        error_data = await response.json()
                        raise Exception(f"API Error {response.status}: {error_data.get('error', 'Unknown error')}")
                        
        except Exception as e:
            self.logger.error(f"Async filter failed: {e}")
            raise

# 便捷函数
def quick_filter(content: str, 
                api_url: str = "http://localhost:5000",
                user_id: str = "anonymous") -> str:
    """
    快速过滤函数，直接返回过滤后的内容
    
    Args:
        content: 待过滤的内容
        api_url: API服务器地址
        user_id: 用户ID
        
    Returns:
        str: 过滤后的内容
    """
    client = OpenClawSecurityClient(api_url)
    try:
        result = client.filter_content(content, user_id)
        if result.is_blocked:
            raise Exception(f"内容被拦截: {result.filtered_content}")
        return result.filtered_content
    finally:
        client.close()

def quick_security_check(content: str,
                        api_url: str = "http://localhost:5000",
                        user_id: str = "anonymous") -> bool:
    """
    快速安全检查，返回是否安全
    
    Args:
        content: 待检查的内容
        api_url: API服务器地址
        user_id: 用户ID
        
    Returns:
        bool: 是否安全
    """
    client = OpenClawSecurityClient(api_url)
    try:
        result = client.check_security(content, user_id)
        return result.is_safe
    finally:
        client.close()

# 装饰器
def secure_output(api_url: str = "http://localhost:5000", user_id: str = "anonymous"):
    """
    安全输出装饰器
    
    Usage:
        @secure_output(api_url="http://localhost:5000")
        def my_function():
            return "用户手机号13812345678"
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 执行原函数
            result = func(*args, **kwargs)
            
            # 如果结果是字符串，进行安全过滤
            if isinstance(result, str):
                client = OpenClawSecurityClient(api_url)
                try:
                    filter_result = client.filter_content(result, user_id)
                    if filter_result.is_blocked:
                        raise Exception(f"输出被安全过滤器拦截: {filter_result.filtered_content}")
                    return filter_result.filtered_content
                finally:
                    client.close()
            
            return result
        return wrapper
    return decorator

# 中间件示例（适用于Web框架）
class SecurityMiddleware:
    """安全过滤中间件"""
    
    def __init__(self, api_url: str = "http://localhost:5000"):
        self.api_url = api_url
        self.client = OpenClawSecurityClient(api_url)
    
    def process_response(self, response_content: str, user_id: str = "anonymous") -> str:
        """处理响应内容"""
        try:
            result = self.client.filter_content(response_content, user_id)
            if result.is_blocked:
                raise Exception(f"响应内容被拦截: {result.filtered_content}")
            return result.filtered_content
        except Exception as e:
            self.logger.error(f"Security middleware error: {e}")
            raise
    
    def close(self):
        """关闭中间件"""
        self.client.close()
