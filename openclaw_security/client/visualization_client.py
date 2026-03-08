"""
OpenClaw 威胁可视化客户端
提供便捷的威胁可视化接口
"""

import requests
import base64
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import logging
from datetime import datetime

@dataclass
class ThreatVisualizationResult:
    """威胁可视化结果"""
    success: bool
    content: str
    image: str  # base64编码的图片
    format: str
    nodes: int
    edges: int
    threat_analysis: Dict
    timestamp: str
    threat_details: Optional[List[Dict]] = None

@dataclass
class ThreatAnalysisResult:
    """威胁分析结果"""
    success: bool
    content: str
    threat_analysis: Dict
    threat_details: List[Dict]
    timestamp: str

class ThreatVisualizationClient:
    """威胁可视化客户端"""
    
    def __init__(self, base_url: str = "http://localhost:5001", timeout: int = 30):
        """
        初始化可视化客户端
        
        Args:
            base_url: 可视化服务器地址
            timeout: 请求超时时间（秒）
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        # 设置默认请求头
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'OpenClaw-Visualization-Client/2.1'
        })
    
    def visualize_threats(self, 
                         content: str, 
                         user_id: str = "anonymous",
                         include_details: bool = False) -> ThreatVisualizationResult:
        """
        生成威胁可视化图
        
        Args:
            content: 待分析的内容
            user_id: 用户ID
            include_details: 是否包含详细信息
            
        Returns:
            ThreatVisualizationResult: 可视化结果
        """
        try:
            data = {
                "content": content,
                "user_id": user_id,
                "options": {
                    "include_details": include_details
                }
            }
            
            response = self.session.post(
                f"{self.base_url}/visualize",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                
                return ThreatVisualizationResult(
                    success=result_data['success'],
                    content=result_data['content'],
                    image=result_data['visualization']['image'],
                    format=result_data['visualization']['format'],
                    nodes=result_data['visualization']['nodes'],
                    edges=result_data['visualization']['edges'],
                    threat_analysis=result_data['threat_analysis'],
                    timestamp=result_data['timestamp'],
                    threat_details=result_data.get('threat_details')
                )
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Visualization request failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def batch_visualize(self, 
                       contents: List[str], 
                       user_id: str = "anonymous") -> Dict:
        """
        批量威胁可视化
        
        Args:
            contents: 待分析的内容列表
            user_id: 用户ID
            
        Returns:
            Dict: 批量可视化结果
        """
        try:
            data = {
                "contents": contents,
                "user_id": user_id
            }
            
            response = self.session.post(
                f"{self.base_url}/visualize/batch",
                json=data,
                timeout=self.timeout * 2  # 批量请求需要更长时间
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Batch visualization request failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def analyze_threats(self, content: str, user_id: str = "anonymous") -> ThreatAnalysisResult:
        """
        仅分析威胁，不生成图片
        
        Args:
            content: 待分析的内容
            user_id: 用户ID
            
        Returns:
            ThreatAnalysisResult: 威胁分析结果
        """
        try:
            data = {
                "content": content,
                "user_id": user_id
            }
            
            response = self.session.post(
                f"{self.base_url}/analyze",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                
                return ThreatAnalysisResult(
                    success=result_data['success'],
                    content=result_data['content'],
                    threat_analysis=result_data['threat_analysis'],
                    threat_details=result_data['threat_details'],
                    timestamp=result_data['timestamp']
                )
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Analysis request failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def export_image(self, 
                     content: str, 
                     format_type: str = "png",
                     size: str = "medium") -> Dict:
        """
        导出威胁图片
        
        Args:
            content: 待分析的内容
            format_type: 图片格式 (png, jpg)
            size: 图片大小 (small, medium, large)
            
        Returns:
            Dict: 导出结果
        """
        try:
            data = {
                "content": content,
                "format": format_type,
                "size": size
            }
            
            response = self.session.post(
                f"{self.base_url}/export/image",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Export request failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def get_demo(self) -> Dict:
        """获取演示示例"""
        try:
            response = self.session.get(f"{self.base_url}/demo", timeout=self.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Demo request failed: {e}")
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
    
    def save_image(self, image_base64: str, filename: str) -> str:
        """
        保存base64图片到文件
        
        Args:
            image_base64: base64编码的图片数据
            filename: 保存的文件名
            
        Returns:
            str: 保存的文件路径
        """
        try:
            # 解码base64
            image_data = base64.b64decode(image_base64)
            
            # 保存到文件
            with open(filename, 'wb') as f:
                f.write(image_data)
            
            self.logger.info(f"Image saved to: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"Failed to save image: {e}")
            raise Exception(f"Save image error: {e}")
    
    def close(self):
        """关闭客户端连接"""
        self.session.close()

# 便捷函数
def quick_visualize(content: str, 
                    api_url: str = "http://localhost:5001",
                    save_file: bool = False,
                    filename: str = None) -> ThreatVisualizationResult:
    """
    快速威胁可视化
    
    Args:
        content: 待分析的内容
        api_url: API服务器地址
        save_file: 是否保存图片到文件
        filename: 保存的文件名
        
    Returns:
        ThreatVisualizationResult: 可视化结果
    """
    client = ThreatVisualizationClient(api_url)
    try:
        result = client.visualize_threats(content, include_details=True)
        
        # 保存图片到文件
        if save_file:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"threat_analysis_{timestamp}.png"
            
            client.save_image(result.image, filename)
            result.saved_file = filename
        
        return result
    finally:
        client.close()

def quick_analyze(content: str, api_url: str = "http://localhost:5001") -> ThreatAnalysisResult:
    """
    快速威胁分析
    
    Args:
        content: 待分析的内容
        api_url: API服务器地址
        
    Returns:
        ThreatAnalysisResult: 威胁分析结果
    """
    client = ThreatVisualizationClient(api_url)
    try:
        return client.analyze_threats(content)
    finally:
        client.close()

# 装饰器
def threat_aware_output(api_url: str = "http://localhost:5001", 
                       save_image: bool = False):
    """
    威胁感知输出装饰器
    不拦截输出，但生成威胁分析图
    
    Usage:
        @threat_aware_output(api_url="http://localhost:5001", save_image=True)
        def my_function():
            return "SELECT * FROM users; DROP TABLE users;"
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 执行原函数
            result = func(*args, **kwargs)
            
            # 如果结果是字符串，进行威胁可视化
            if isinstance(result, str):
                client = ThreatVisualizationClient(api_url)
                try:
                    viz_result = client.visualize_threats(result, include_details=True)
                    
                    # 保存图片
                    if save_image:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"threat_analysis_{timestamp}.png"
                        client.save_image(viz_result.image, filename)
                        viz_result.saved_file = filename
                    
                    # 返回增强结果
                    return {
                        'original_content': result,
                        'threat_visualization': viz_result,
                        'warning': 'Content contains potential threats - see visualization'
                    }
                finally:
                    client.close()
            
            return result
        return wrapper
    return decorator

# 威胁感知中间件
class ThreatAwareMiddleware:
    """威胁感知中间件"""
    
    def __init__(self, api_url: str = "http://localhost:5001"):
        self.api_url = api_url
        self.client = ThreatVisualizationClient(api_url)
    
    def process_response(self, response_content: str, save_image: bool = False) -> Dict:
        """处理响应内容，生成威胁可视化"""
        try:
            viz_result = self.client.visualize_threats(response_content, include_details=True)
            
            # 保存图片
            if save_image:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"threat_analysis_{timestamp}.png"
                self.client.save_image(viz_result.image, filename)
                viz_result.saved_file = filename
            
            return {
                'original_content': response_content,
                'threat_visualization': viz_result,
                'processed_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Threat aware middleware error: {e}")
            return {
                'original_content': response_content,
                'error': str(e),
                'processed_at': datetime.now().isoformat()
            }
    
    def close(self):
        """关闭中间件"""
        self.client.close()
