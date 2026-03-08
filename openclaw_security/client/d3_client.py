"""
OpenClaw D3.js 可视化客户端
提供交互式D3.js力导向图客户端接口
"""

import requests
import webbrowser
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging
from datetime import datetime
from pathlib import Path

@dataclass
class D3GraphResult:
    """D3.js图表结果"""
    success: bool
    content: str
    html_content: str
    title: str
    timestamp: str
    saved_file: Optional[str] = None
    file_url: Optional[str] = None

@dataclass
class D3DemoResult:
    """D3.js演示结果"""
    demo_id: int
    name: str
    content: str
    description: str
    filename: Optional[str] = None
    url: Optional[str] = None
    html_content: Optional[str] = None
    error: Optional[str] = None

class D3VisualizationClient:
    """D3.js可视化客户端"""
    
    def __init__(self, base_url: str = "http://localhost:5002", timeout: int = 30):
        """
        初始化D3.js客户端
        
        Args:
            base_url: D3.js服务器地址
            timeout: 请求超时时间（秒）
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        # 设置默认请求头
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'OpenClaw-D3-Client/2.2'
        })
    
    def generate_graph(self, 
                      content: str, 
                      title: str = "威胁力导向图",
                      save_to_file: bool = False) -> D3GraphResult:
        """
        生成D3.js力导向图
        
        Args:
            content: 待分析的内容
            title: 图表标题
            save_to_file: 是否保存到文件
            
        Returns:
            D3GraphResult: 图表生成结果
        """
        try:
            data = {
                "content": content,
                "title": title,
                "save_to_file": save_to_file
            }
            
            response = self.session.post(
                f"{self.base_url}/generate",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                
                return D3GraphResult(
                    success=result_data['success'],
                    content=result_data['content'],
                    html_content=result_data['html_content'],
                    title=result_data['title'],
                    timestamp=result_data['timestamp'],
                    saved_file=result_data.get('saved_file'),
                    file_url=result_data.get('file_url')
                )
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"D3 graph generation failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def generate_and_save_graph(self, 
                               content: str, 
                               filename: str = None,
                               title: str = "威胁力导向图") -> D3GraphResult:
        """
        生成并保存D3.js力导向图
        
        Args:
            content: 待分析的内容
            filename: 保存的文件名
            title: 图表标题
            
        Returns:
            D3GraphResult: 图表生成结果
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"threat_graph_{timestamp}.html"
            
            data = {
                "content": content,
                "filename": filename,
                "title": title
            }
            
            response = self.session.post(
                f"{self.base_url}/generate_and_save",
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                
                return D3GraphResult(
                    success=result_data['success'],
                    content=result_data['content'],
                    html_content="",  # 不返回HTML内容，文件已保存
                    title=result_data['title'],
                    timestamp=result_data['timestamp'],
                    saved_file=result_data['filepath'],
                    file_url=result_data['file_url']
                )
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"D3 graph save failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def list_graphs(self) -> Dict:
        """列出所有生成的图表文件"""
        try:
            response = self.session.get(f"{self.base_url}/graphs", timeout=self.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"List graphs failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def open_graph(self, filename: str, in_browser: bool = True) -> bool:
        """
        打开图表文件
        
        Args:
            filename: 图表文件名
            in_browser: 是否在浏览器中打开
            
        Returns:
            bool: 是否成功打开
        """
        try:
            if in_browser:
                url = f"{self.base_url}/graphs/{filename}"
                webbrowser.open(url)
                self.logger.info(f"Opened graph in browser: {url}")
                return True
            else:
                response = self.session.get(f"{self.base_url}/graphs/{filename}", timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
                else:
                    return False
                    
        except Exception as e:
            self.logger.error(f"Open graph failed: {e}")
            return False
    
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
            self.logger.error(f"Get demo failed: {e}")
            raise Exception(f"Network error: {e}")
    
    def get_template(self) -> Dict:
        """获取模板信息"""
        try:
            response = self.session.get(f"{self.base_url}/template", timeout=self.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.content else {}
                raise Exception(f"API Error {response.status_code}: {error_data.get('error', 'Unknown error')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Get template failed: {e}")
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
    
    def save_html_locally(self, html_content: str, filename: str) -> str:
        """
        保存HTML内容到本地文件
        
        Args:
            html_content: HTML内容
            filename: 保存的文件名
            
        Returns:
            str: 保存的文件路径
        """
        try:
            filepath = Path(filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML saved locally: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Save HTML failed: {e}")
            raise Exception(f"Save HTML error: {e}")
    
    def open_local_html(self, filename: str) -> bool:
        """
        打开本地HTML文件
        
        Args:
            filename: 本地HTML文件路径
            
        Returns:
            bool: 是否成功打开
        """
        try:
            filepath = Path(filename)
            if filepath.exists():
                webbrowser.open(f"file://{filepath.absolute()}")
                self.logger.info(f"Opened local HTML: {filepath}")
                return True
            else:
                self.logger.error(f"File not found: {filepath}")
                return False
        except Exception as e:
            self.logger.error(f"Open local HTML failed: {e}")
            return False
    
    def close(self):
        """关闭客户端连接"""
        self.session.close()

# 便捷函数
def quick_d3_graph(content: str, 
                  title: str = "威胁力导向图",
                  api_url: str = "http://localhost:5002",
                  save_to_file: bool = False,
                  open_in_browser: bool = True) -> D3GraphResult:
    """
    快速生成D3.js力导向图
    
    Args:
        content: 待分析的内容
        title: 图表标题
        api_url: API服务器地址
        save_to_file: 是否保存到文件
        open_in_browser: 是否在浏览器中打开
        
    Returns:
        D3GraphResult: 图表生成结果
    """
    client = D3VisualizationClient(api_url)
    try:
        result = client.generate_graph(content, title, save_to_file)
        
        # 保存到本地
        if not save_to_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"d3_graph_{timestamp}.html"
            client.save_html_locally(result.html_content, filename)
            result.saved_file = filename
        
        # 在浏览器中打开
        if open_in_browser:
            if result.file_url:
                client.open_graph(Path(result.file_url).name)
            elif result.saved_file:
                client.open_local_html(result.saved_file)
        
        return result
    finally:
        client.close()

def quick_d3_demo(api_url: str = "http://localhost:5002", 
                  open_in_browser: bool = True) -> Dict:
    """
    快速获取D3.js演示
    
    Args:
        api_url: API服务器地址
        open_in_browser: 是否在浏览器中打开演示
        
    Returns:
        Dict: 演示结果
    """
    client = D3VisualizationClient(api_url)
    try:
        demo_result = client.get_demo()
        
        if open_in_browser and demo_result.get('success'):
            # 打开第一个演示
            first_demo = demo_result['results'][0]
            if 'url' in first_demo:
                client.open_graph(Path(first_demo['url']).name)
        
        return demo_result
    finally:
        client.close()

# 装饰器
def d3_aware_output(api_url: str = "http://localhost:5002", 
                    save_to_file: bool = True,
                    open_in_browser: bool = True):
    """
    D3.js感知输出装饰器
    
    Usage:
        @d3_aware_output(api_url="http://localhost:5002")
        def my_function():
            return "SELECT * FROM users; DROP TABLE users;"
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 执行原函数
            result = func(*args, **kwargs)
            
            # 如果结果是字符串，生成D3.js图表
            if isinstance(result, str):
                client = D3VisualizationClient(api_url)
                try:
                    d3_result = client.generate_graph(
                        result, 
                        title=f"威胁分析: {func.__name__}",
                        save_to_file=save_to_file
                    )
                    
                    # 在浏览器中打开
                    if open_in_browser and d3_result.file_url:
                        client.open_graph(Path(d3_result.file_url).name)
                    
                    # 返回增强结果
                    return {
                        'original_content': result,
                        'd3_visualization': d3_result,
                        'warning': 'Content contains potential threats - see D3.js visualization'
                    }
                finally:
                    client.close()
            
            return result
        return wrapper
    return decorator

# D3.js感知中间件
class D3AwareMiddleware:
    """D3.js感知中间件"""
    
    def __init__(self, api_url: str = "http://localhost:5002"):
        self.api_url = api_url
        self.client = D3VisualizationClient(api_url)
    
    def process_response(self, 
                        response_content: str, 
                        title: str = "威胁分析",
                        save_to_file: bool = True,
                        open_in_browser: bool = False) -> Dict:
        """处理响应内容，生成D3.js图表"""
        try:
            d3_result = self.client.generate_graph(
                response_content, 
                title=title,
                save_to_file=save_to_file
            )
            
            # 在浏览器中打开
            if open_in_browser and d3_result.file_url:
                self.client.open_graph(Path(d3_result.file_url).name)
            
            return {
                'original_content': response_content,
                'd3_visualization': d3_result,
                'processed_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"D3 aware middleware error: {e}")
            return {
                'original_content': response_content,
                'error': str(e),
                'processed_at': datetime.now().isoformat()
            }
    
    def close(self):
        """关闭中间件"""
        self.client.close()
