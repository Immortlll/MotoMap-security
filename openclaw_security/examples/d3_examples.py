"""
OpenClaw D3.js 可视化示例
展示交互式力导向图的使用方法
"""

import time
import os
from ..client.d3_client import (
    D3VisualizationClient, 
    quick_d3_graph, 
    quick_d3_demo,
    d3_aware_output,
    D3AwareMiddleware
)

# ============================================================================
# 1. 基本D3.js图表生成示例
# ============================================================================

def basic_d3_example():
    """基本D3.js图表生成示例"""
    print("=== 基本D3.js图表生成示例 ===")
    
    client = D3VisualizationClient("http://localhost:5002")
    
    try:
        # 健康检查
        print("1. 健康检查...")
        health = client.health_check()
        print(f"服务状态: {health['status']}")
        print(f"功能特性: {health['features']}")
        
        # 测试各种威胁类型
        test_cases = [
            ("SQL注入", "SELECT * FROM users WHERE id = 1; DROP TABLE users;"),
            ("XSS攻击", "<script>alert('XSS攻击')</script>"),
            ("路径遍历", "../../../etc/passwd"),
            ("命令注入", "ls -la; rm -rf /"),
            ("敏感信息", "API密钥：sk-1234567890abcdef，密码：admin123"),
            ("正常内容", "这是一个安全的文本内容，不包含任何威胁。")
        ]
        
        for test_name, content in test_cases:
            print(f"\n--- {test_name} ---")
            print(f"测试内容: {content}")
            
            # 生成D3.js图表
            result = client.generate_graph(
                content, 
                title=f"{test_name}威胁分析",
                save_to_file=True
            )
            
            print(f"图表标题: {result.title}")
            print(f"生成时间: {result.timestamp}")
            
            if result.saved_file:
                print(f"已保存: {result.saved_file}")
                print(f"访问URL: {result.file_url}")
            
            # 在浏览器中打开
            if result.file_url:
                client.open_graph(os.path.basename(result.file_url))
                print("✅ 已在浏览器中打开图表")
            
            print("等待3秒后继续...")
            time.sleep(3)
    
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.close()

# ============================================================================
# 2. 快速D3.js图表示例
# ============================================================================

def quick_d3_example():
    """快速D3.js图表示例"""
    print("\n=== 快速D3.js图表示例 ===")
    
    try:
        # 快速生成并打开图表
        content = "用户输入：SELECT * FROM users WHERE name = 'admin'; DROP TABLE users;"
        
        result = quick_d3_graph(
            content, 
            title="SQL注入威胁分析",
            api_url="http://localhost:5002",
            save_to_file=True,
            open_in_browser=True
        )
        
        print(f"原始内容: {result.content}")
        print(f"图表标题: {result.title}")
        print(f"生成时间: {result.timestamp}")
        
        if result.saved_file:
            print(f"本地文件: {result.saved_file}")
        
        print("✅ D3.js图表已生成并在浏览器中打开")
        
    except Exception as e:
        print(f"❌ 错误: {e}")

# ============================================================================
# 3. D3.js感知装饰器示例
# ============================================================================

@d3_aware_output(api_url="http://localhost:5002", save_to_file=True, open_in_browser=True)
def get_user_input():
    """模拟用户输入函数"""
    return "SELECT * FROM users WHERE id = 1; DROP TABLE users;"

@d3_aware_output(api_url="http://localhost:5002", save_to_file=True, open_in_browser=True)
def get_script_content():
    """模拟脚本内容函数"""
    return "<script>alert('XSS攻击'); location.href='http://evil.com';</script>"

@d3_aware_output(api_url="http://localhost:5002", save_to_file=True, open_in_browser=True)
def get_safe_content():
    """模拟安全内容函数"""
    return "这是一个安全的文本内容，不包含任何威胁。"

def d3_aware_decorator_example():
    """D3.js感知装饰器示例"""
    print("\n=== D3.js感知装饰器示例 ===")
    
    try:
        # 测试各种内容
        print("1. 用户输入处理...")
        user_result = get_user_input()
        print(f"处理结果: {user_result['warning']}")
        print(f"图表标题: {user_result['d3_visualization'].title}")
        
        print("\n2. 脚本内容处理...")
        script_result = get_script_content()
        print(f"处理结果: {script_result['warning']}")
        print(f"图表标题: {script_result['d3_visualization'].title}")
        
        print("\n3. 安全内容处理...")
        safe_result = get_safe_content()
        print(f"处理结果: {safe_result.get('warning', '无威胁')}")
        print(f"图表标题: {safe_result['d3_visualization'].title}")
        
        print("等待3秒后继续...")
        time.sleep(3)
        
    except Exception as e:
        print(f"❌ 装饰器错误: {e}")

# ============================================================================
# 4. D3.js感知中间件示例
# ============================================================================

def d3_aware_middleware_example():
    """D3.js感知中间件示例"""
    print("\n=== D3.js感知中间件示例 ===")
    
    middleware = D3AwareMiddleware("http://localhost:5002")
    
    try:
        # 模拟Web框架响应处理
        responses = [
            "这是公开的响应内容",
            "用户查询：SELECT * FROM products WHERE id = 1",
            "脚本内容：<script>alert('test')</script>",
            "系统信息：API密钥sk-1234567890abcdef"
        ]
        
        for i, response in enumerate(responses):
            print(f"\n响应{i+1}: {response}")
            
            # 处理响应
            processed = middleware.process_response(
                response, 
                title=f"响应{i+1}威胁分析",
                save_to_file=True,
                open_in_browser=False
            )
            
            d3_result = processed['d3_visualization']
            print(f"图表标题: {d3_result.title}")
            print(f"生成时间: {d3_result.timestamp}")
            
            if d3_result.saved_file:
                print(f"已保存: {d3_result.saved_file}")
            
            # 选择性地打开图表
            if i == 2:  # 只打开脚本内容的图表
                if d3_result.file_url:
                    middleware.client.open_graph(os.path.basename(d3_result.file_url))
                    print("✅ 已在浏览器中打开图表")
                    print("等待3秒后继续...")
                    time.sleep(3)
    
    finally:
        middleware.close()

# ============================================================================
# 5. D3.js演示示例
# ============================================================================

def d3_demo_example():
    """D3.js演示示例"""
    print("\n=== D3.js演示示例 ===")
    
    client = D3VisualizationClient("http://localhost:5002")
    
    try:
        # 获取演示数据
        demo_result = client.get_demo()
        
        print(f"演示标题: {demo_result['title']}")
        print(f"演示描述: {demo_result['description']}")
        print(f"演示数量: {len(demo_result['results'])}")
        
        # 显示每个演示
        for i, demo in enumerate(demo_result['results']):
            print(f"\n--- 演示{i+1}: {demo['name']} ---")
            print(f"内容: {demo['content']}")
            print(f"描述: {demo['description']}")
            
            if 'error' not in demo:
                print(f"文件名: {demo['filename']}")
                print(f"访问URL: {demo['url']}")
                
                # 打开前3个演示
                if i < 3:
                    client.open_graph(os.path.basename(demo['url']))
                    print("✅ 已在浏览器中打开演示")
                    print("等待3秒后继续...")
                    time.sleep(3)
            else:
                print(f"错误: {demo['error']}")
    
    except Exception as e:
        print(f"❌ 演示错误: {e}")
    finally:
        client.close()

# ============================================================================
# 6. 图表管理示例
# ============================================================================

def graph_management_example():
    """图表管理示例"""
    print("\n=== 图表管理示例 ===")
    
    client = D3VisualizationClient("http://localhost:5002")
    
    try:
        # 生成多个图表
        contents = [
            "SQL注入测试：SELECT * FROM users;",
            "XSS测试：<script>alert('xss')</script>",
            "路径遍历：../../../etc/passwd",
            "正常内容：这是安全的文本。"
        ]
        
        generated_files = []
        
        for i, content in enumerate(contents):
            result = client.generate_and_save_graph(
                content,
                filename=f"test_{i+1}_graph.html",
                title=f"测试{i+1}威胁分析"
            )
            generated_files.append(result.saved_file)
            print(f"生成图表{i+1}: {result.saved_file}")
        
        # 列出所有图表
        print("\n--- 图表列表 ---")
        graphs = client.list_graphs()
        
        print(f"总图表数: {graphs['total_count']}")
        print("最近生成的图表:")
        
        for graph in graphs['graphs'][:5]:  # 显示前5个
            print(f"  - {graph['filename']}")
            print(f"    大小: {graph['size']}字节")
            print(f"    创建时间: {graph['created']}")
            print(f"    访问URL: {graph['url']}")
        
        # 打开最新的图表
        if graphs['graphs']:
            latest = graphs['graphs'][0]
            print(f"\n打开最新图表: {latest['filename']}")
            client.open_graph(latest['filename'])
            print("✅ 已在浏览器中打开")
            print("等待3秒后继续...")
            time.sleep(3)
    
    except Exception as e:
        print(f"❌ 图表管理错误: {e}")
    finally:
        client.close()

# ============================================================================
# 7. 模板信息示例
# ============================================================================

def template_info_example():
    """模板信息示例"""
    print("\n=== 模板信息示例 ===")
    
    client = D3VisualizationClient("http://localhost:5002")
    
    try:
        # 获取模板信息
        template = client.get_template()
        
        print(f"模板标题: {template['title']}")
        print(f"模板描述: {template['description']}")
        
        print("\n功能特性:")
        for feature in template['features']:
            print(f"  ✅ {feature}")
        
        print("\nAPI端点:")
        for endpoint, description in template['usage'].items():
            print(f"  {endpoint}: {description}")
        
        print(f"\n示例请求:")
        example = template['example_request']
        print(f"  方法: {example['method']}")
        print(f"  URL: {example['url']}")
        print(f"  请求体: {example['body']}")
        
    except Exception as e:
        print(f"❌ 模板信息错误: {e}")
    finally:
        client.close()

# ============================================================================
# 8. 性能测试示例
# ============================================================================

def performance_test_example():
    """性能测试示例"""
    print("\n=== 性能测试示例 ===")
    
    client = D3VisualizationClient("http://localhost:5002")
    
    try:
        # 测试内容
        test_content = "用户输入：SELECT * FROM users WHERE id = 1; <script>alert('test')</script>"
        test_count = 10
        
        print(f"性能测试：{test_count}次D3.js图表生成...")
        
        # 单次测试
        start_time = time.time()
        for i in range(test_count):
            result = client.generate_graph(f"{test_content} #{i}")
        single_time = time.time() - start_time
        
        # 性能统计
        avg_time = single_time / test_count
        
        print(f"\n性能结果:")
        print(f"总耗时: {single_time:.3f}秒")
        print(f"平均耗时: {avg_time*1000:.1f}毫秒/次")
        print(f"处理速度: {test_count/single_time:.1f}次/秒")
        
        # 内存使用估算
        print(f"\n内存估算:")
        print(f"单个HTML大小: ~{len(result.html_content)/1024:.1f}KB")
        print(f"总HTML大小: ~{len(result.html_content)*test_count/1024:.1f}KB")
        
    except Exception as e:
        print(f"❌ 性能测试错误: {e}")
    finally:
        client.close()

# ============================================================================
# 9. 完整工作流示例
# ============================================================================

def complete_d3_workflow_example():
    """完整D3.js工作流示例"""
    print("\n=== 完整D3.js工作流示例 ===")
    
    client = D3VisualizationClient("http://localhost:5002")
    
    try:
        # 模拟用户输入场景
        user_inputs = [
            "登录表单：username=admin&password=123' OR '1'='1",
            "搜索查询：<img src=x onerror=alert('XSS')>",
            "文件上传：filename=../../../etc/passwd",
            "API调用：curl -X POST -d 'cmd=ls;rm -rf /' http://api.com",
            "配置文件：db_user=root&db_pass=secret123&api_key=sk-abcdef"
        ]
        
        print("D3.js威胁可视化工作流:")
        
        for i, user_input in enumerate(user_inputs):
            print(f"\n--- 用户输入{i+1} ---")
            print(f"输入内容: {user_input}")
            
            # 1. 生成D3.js图表
            result = client.generate_and_save_graph(
                user_input,
                filename=f"workflow_{i+1}_input.html",
                title=f"用户输入{i+1}威胁分析"
            )
            
            print(f"图表标题: {result.title}")
            print(f"生成时间: {result.timestamp}")
            print(f"保存文件: {result.saved_file}")
            
            # 2. 在浏览器中打开
            if result.file_url:
                client.open_graph(os.path.basename(result.file_url))
                print("✅ 已在浏览器中打开交互式图表")
            
            # 3. 等待用户查看
            print("请查看浏览器中的交互式图表...")
            print("等待5秒后继续...")
            time.sleep(5)
    
    except Exception as e:
        print(f"❌ 工作流错误: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    print("🎨 OpenClaw D3.js 可视化系统示例")
    print("=" * 60)
    
    # 注意：在运行示例前，请确保D3.js服务器已启动
    # python -m openclaw_security.api.d3_server
    
    try:
        # 运行所有示例
        basic_d3_example()
        quick_d3_example()
        d3_aware_decorator_example()
        d3_aware_middleware_example()
        d3_demo_example()
        graph_management_example()
        template_info_example()
        performance_test_example()
        complete_d3_workflow_example()
        
        print("\n✅ 所有D3.js可视化示例运行完成！")
        
    except KeyboardInterrupt:
        print("\n⏹️  示例运行被中断")
    except Exception as e:
        print(f"\n❌ 示例运行出错: {e}")
        print("请确保D3.js可视化服务器正在运行：python -m openclaw_security.api.d3_server")
