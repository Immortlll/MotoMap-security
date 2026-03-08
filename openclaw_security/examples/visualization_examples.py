"""
OpenClaw 威胁可视化示例
展示威胁力导向图的使用方法
"""

import time
import os
from ..client.visualization_client import (
    ThreatVisualizationClient, 
    quick_visualize, 
    quick_analyze,
    threat_aware_output,
    ThreatAwareMiddleware
)

# ============================================================================
# 1. 基本威胁可视化示例
# ============================================================================

def basic_visualization_example():
    """基本威胁可视化示例"""
    print("=== 基本威胁可视化示例 ===")
    
    client = ThreatVisualizationClient("http://localhost:5001")
    
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
            
            # 生成威胁可视化
            result = client.visualize_threats(content, include_details=True)
            
            print(f"威胁数量: {result.nodes}个节点, {result.edges}条边")
            print(f"风险等级: {result.threat_analysis['risk_level']}")
            print(f"风险评分: {result.threat_analysis['risk_score']}")
            
            if result.threat_details:
                print("检测到的威胁:")
                for threat in result.threat_details:
                    print(f"  - {threat['type']} ({threat['level']}): {threat['content']}")
            
            print(f"建议: {', '.join(result.threat_analysis['recommendations'][:2])}")
            
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.close()

# ============================================================================
# 2. 快速可视化示例
# ============================================================================

def quick_visualization_example():
    """快速威胁可视化示例"""
    print("\n=== 快速威胁可视化示例 ===")
    
    try:
        # 快速可视化并保存图片
        content = "用户输入：SELECT * FROM users WHERE name = 'admin'; DROP TABLE users;"
        
        result = quick_visualize(
            content, 
            api_url="http://localhost:5001",
            save_file=True,
            filename="sql_injection_threat.png"
        )
        
        print(f"原始内容: {result.original_content}")
        print(f"威胁节点: {result.nodes}个")
        print(f"风险等级: {result.threat_analysis['risk_level']}")
        
        if hasattr(result, 'saved_file'):
            print(f"图片已保存: {result.saved_file}")
        
        # 快速威胁分析
        analysis = quick_analyze(content, api_url="http://localhost:5001")
        print(f"\n威胁分析结果:")
        print(f"总威胁数: {analysis.threat_analysis['total_threats']}")
        print(f"威胁分布: {analysis.threat_analysis['threat_breakdown']}")
        
    except Exception as e:
        print(f"❌ 错误: {e}")

# ============================================================================
# 3. 威胁感知装饰器示例
# ============================================================================

@threat_aware_output(api_url="http://localhost:5001", save_image=True)
def get_user_input():
    """模拟用户输入函数"""
    return "SELECT * FROM users WHERE id = 1; DROP TABLE users;"

@threat_aware_output(api_url="http://localhost:5001", save_image=True)
def get_script_content():
    """模拟脚本内容函数"""
    return "<script>alert('XSS攻击'); location.href='http://evil.com';</script>"

@threat_aware_output(api_url="http://localhost:5001", save_image=True)
def get_safe_content():
    """模拟安全内容函数"""
    return "这是一个安全的文本内容，不包含任何威胁。"

def threat_aware_decorator_example():
    """威胁感知装饰器示例"""
    print("\n=== 威胁感知装饰器示例 ===")
    
    try:
        # 测试各种内容
        print("1. 用户输入处理...")
        user_result = get_user_input()
        print(f"处理结果: {user_result['warning']}")
        print(f"威胁节点: {user_result['threat_visualization'].nodes}")
        
        print("\n2. 脚本内容处理...")
        script_result = get_script_content()
        print(f"处理结果: {script_result['warning']}")
        print(f"威胁节点: {script_result['threat_visualization'].nodes}")
        
        print("\n3. 安全内容处理...")
        safe_result = get_safe_content()
        print(f"处理结果: {safe_result.get('warning', '无威胁')}")
        print(f"威胁节点: {safe_result['threat_visualization'].nodes}")
        
    except Exception as e:
        print(f"❌ 装饰器错误: {e}")

# ============================================================================
# 4. 威胁感知中间件示例
# ============================================================================

def threat_aware_middleware_example():
    """威胁感知中间件示例"""
    print("\n=== 威胁感知中间件示例 ===")
    
    middleware = ThreatAwareMiddleware("http://localhost:5001")
    
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
            processed = middleware.process_response(response, save_image=True)
            
            viz_result = processed['threat_visualization']
            print(f"威胁节点: {viz_result.nodes}")
            print(f"风险等级: {viz_result.threat_analysis['risk_level']}")
            
            if viz_result.threat_analysis['total_threats'] > 0:
                print(f"建议: {', '.join(viz_result.threat_analysis['recommendations'][:2])}")
            
            if hasattr(viz_result, 'saved_file'):
                print(f"图片已保存: {viz_result.saved_file}")
    
    finally:
        middleware.close()

# ============================================================================
# 5. 批量可视化示例
# ============================================================================

def batch_visualization_example():
    """批量威胁可视化示例"""
    print("\n=== 批量威胁可视化示例 ===")
    
    client = ThreatVisualizationClient("http://localhost:5001")
    
    try:
        # 准备批量内容
        contents = [
            "用户登录：admin' OR '1'='1",
            "搜索内容：<script>document.cookie</script>",
            "文件路径：../../../windows/system32/config/sam",
            "命令执行：system('rm -rf /')",
            "配置信息：database_password=secret123"
        ]
        
        print(f"批量处理{len(contents)}个内容...")
        
        # 批量可视化
        start_time = time.time()
        batch_result = client.batch_visualize(contents, user_id="batch_user")
        end_time = time.time()
        
        print(f"处理耗时: {end_time - start_time:.3f}秒")
        print(f"总威胁数: {batch_result['summary']['total_threats']}")
        print(f"处理成功: {batch_result['summary']['processed_count']}")
        
        # 显示详细结果
        for i, result in enumerate(batch_result['results']):
            if 'error' not in result:
                print(f"内容{i+1}: {result['threat_analysis']['total_threats']}个威胁, "
                      f"风险等级: {result['threat_analysis']['risk_level']}")
            else:
                print(f"内容{i+1}: 处理失败 - {result['error']}")
    
    except Exception as e:
        print(f"❌ 批量处理错误: {e}")
    finally:
        client.close()

# ============================================================================
# 6. 图片导出示例
# ============================================================================

def image_export_example():
    """图片导出示例"""
    print("\n=== 图片导出示例 ===")
    
    client = ThreatVisualizationClient("http://localhost:5001")
    
    try:
        content = "复合威胁：SELECT * FROM users; <script>alert('XSS')</script> ../../../etc/passwd"
        
        # 导出不同尺寸的图片
        sizes = ['small', 'medium', 'large']
        
        for size in sizes:
            print(f"\n导出{size}尺寸图片...")
            
            export_result = client.export_image(
                content, 
                format_type="png", 
                size=size
            )
            
            print(f"图片格式: {export_result['format']}")
            print(f"图片尺寸: {export_result['size']}")
            print(f"文件名: {export_result['filename']}")
            
            # 保存图片
            filename = f"threat_{size}_{export_result['filename']}"
            client.save_image(export_result['image'], filename)
            print(f"图片已保存: {filename}")
    
    except Exception as e:
        print(f"❌ 导出错误: {e}")
    finally:
        client.close()

# ============================================================================
# 7. 演示示例
# ============================================================================

def demo_examples():
    """演示示例"""
    print("\n=== 演示示例 ===")
    
    client = ThreatVisualizationClient("http://localhost:5001")
    
    try:
        # 获取演示数据
        demo_result = client.get_demo()
        
        print(f"演示标题: {demo_result['title']}")
        print(f"演示描述: {demo_result['description']}")
        print(f"演示数量: {len(demo_result['results'])}")
        
        # 显示每个演示
        for i, demo in enumerate(demo_result['results']):
            print(f"\n--- 演示{i+1}: {demo['content']} ---")
            
            if 'error' in demo:
                print(f"错误: {demo['error']}")
                continue
            
            viz = demo['visualization']
            analysis = demo['threat_analysis']
            
            print(f"威胁节点: {viz['nodes']}")
            print(f"风险等级: {analysis['risk_level']}")
            print(f"威胁分布: {analysis['threat_breakdown']}")
            
            # 保存演示图片
            if viz['image']:
                filename = f"demo_{i+1}_threat.png"
                client.save_image(viz['image'], filename)
                print(f"演示图片已保存: {filename}")
    
    except Exception as e:
        print(f"❌ 演示错误: {e}")
    finally:
        client.close()

# ============================================================================
# 8. 性能测试示例
# ============================================================================

def performance_test_example():
    """性能测试示例"""
    print("\n=== 性能测试示例 ===")
    
    client = ThreatVisualizationClient("http://localhost:5001")
    
    try:
        # 测试内容
        test_content = "用户输入：SELECT * FROM users WHERE id = 1; <script>alert('test')</script>"
        test_count = 50
        
        print(f"性能测试：{test_count}次可视化...")
        
        # 单次测试
        start_time = time.time()
        for i in range(test_count):
            result = client.visualize_threats(f"{test_content} #{i}")
        single_time = time.time() - start_time
        
        # 批量测试
        batch_contents = [f"{test_content} #{i}" for i in range(test_count)]
        start_time = time.time()
        batch_result = client.batch_visualize(batch_contents)
        batch_time = time.time() - start_time
        
        # 性能对比
        avg_single = single_time / test_count
        avg_batch = batch_time / test_count
        
        print(f"\n性能对比结果:")
        print(f"单次处理: {single_time:.3f}秒, 平均{avg_single*1000:.3f}毫秒/次")
        print(f"批量处理: {batch_time:.3f}秒, 平均{avg_batch*1000:.3f}毫秒/次")
        print(f"性能提升: {single_time/batch_time:.1f}x")
        
        # 内存使用估算
        print(f"\n内存估算:")
        print(f"单次图片大小: ~{len(result.image) * 3 / 4 / 1024:.1f}KB")
        print(f"批量总大小: ~{len(batch_result['results']) * len(result.image) * 3 / 4 / 1024:.1f}KB")
    
    except Exception as e:
        print(f"❌ 性能测试错误: {e}")
    finally:
        client.close()

# ============================================================================
# 9. 完整工作流示例
# ============================================================================

def complete_workflow_example():
    """完整工作流示例"""
    print("\n=== 完整威胁可视化工作流示例 ===")
    
    client = ThreatVisualizationClient("http://localhost:5001")
    
    try:
        # 模拟用户输入场景
        user_inputs = [
            "登录表单：username=admin&password=123' OR '1'='1",
            "搜索查询：<img src=x onerror=alert('XSS')>",
            "文件上传：filename=../../../etc/passwd",
            "API调用：curl -X POST -d 'cmd=ls;rm -rf /' http://api.com",
            "配置文件：db_user=root&db_pass=secret123&api_key=sk-abcdef"
        ]
        
        print("威胁可视化工作流:")
        
        for i, user_input in enumerate(user_inputs):
            print(f"\n--- 用户输入{i+1} ---")
            print(f"输入内容: {user_input}")
            
            # 1. 威胁分析
            analysis = client.analyze_threats(user_input)
            print(f"威胁分析: {analysis.threat_analysis['total_threats']}个威胁")
            print(f"风险等级: {analysis.threat_analysis['risk_level']}")
            
            # 2. 详细威胁信息
            if analysis.threat_details:
                print("威胁详情:")
                for threat in analysis.threat_details:
                    print(f"  - {threat['type']}: {threat['description']}")
            
            # 3. 生成可视化图
            viz_result = client.visualize_threats(user_input, include_details=True)
            print(f"可视化: {viz_result.nodes}个节点, {viz_result.edges}条边")
            
            # 4. 保存图片
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"workflow_{i+1}_{timestamp}.png"
            client.save_image(viz_result.image, filename)
            print(f"图片已保存: {filename}")
            
            # 5. 处理建议
            recommendations = viz_result.threat_analysis['recommendations']
            print(f"处理建议: {', '.join(recommendations[:2])}")
            
            # 6. 风险评估总结
            risk_score = viz_result.threat_analysis['risk_score']
            if risk_score > 50:
                print("🚨 高风险：建议立即处理")
            elif risk_score > 20:
                print("⚠️  中风险：建议关注")
            else:
                print("✅ 低风险：可正常处理")
    
    except Exception as e:
        print(f"❌ 工作流错误: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    print("🎨 OpenClaw 威胁可视化系统示例")
    print("=" * 60)
    
    # 注意：在运行示例前，请确保可视化服务器已启动
    # python -m openclaw_security.api.visualization_server
    
    try:
        # 运行所有示例
        basic_visualization_example()
        quick_visualization_example()
        threat_aware_decorator_example()
        threat_aware_middleware_example()
        batch_visualization_example()
        image_export_example()
        demo_examples()
        performance_test_example()
        complete_workflow_example()
        
        print("\n✅ 所有威胁可视化示例运行完成！")
        
    except KeyboardInterrupt:
        print("\n⏹️  示例运行被中断")
    except Exception as e:
        print(f"\n❌ 示例运行出错: {e}")
        print("请确保威胁可视化服务器正在运行：python -m openclaw_security.api.visualization_server")
