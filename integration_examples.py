"""
OpenClaw 安全过滤器集成示例
展示各种接入方式的使用方法
"""

import time
from client_sdk import OpenClawSecurityClient, quick_filter, secure_output, SecurityMiddleware

# ============================================================================
# 1. 基本客户端使用示例
# ============================================================================

def basic_client_example():
    """基本客户端使用"""
    print("=== 基本客户端使用示例 ===")
    
    # 初始化客户端
    client = OpenClawSecurityClient("http://localhost:5000")
    
    try:
        # 健康检查
        if client.health_check():
            print("✅ 服务健康")
        
        # 过滤内容
        content = "用户张三，手机号13812345678，邮箱zhangsan@example.com"
        result = client.filter_content(content, user_id="demo_user", return_details=True)
        
        print(f"原始内容: {content}")
        print(f"过滤结果: {result.filtered_content}")
        print(f"安全等级: {result.security_level}")
        print(f"处理动作: {result.action_taken}")
        print(f"风险评分: {result.risk_score}")
        
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.close()

# ============================================================================
# 2. 快速过滤函数示例
# ============================================================================

def quick_filter_example():
    """快速过滤函数使用"""
    print("\n=== 快速过滤函数示例 ===")
    
    try:
        # 快速过滤
        content = "请联系李四，电话15987654321"
        safe_content = quick_filter(content, api_url="http://localhost:5000")
        print(f"快速过滤结果: {safe_content}")
        
        # 快速安全检查
        is_safe = quick_security_check("这是公开的安全信息", api_url="http://localhost:5000")
        print(f"安全检查结果: {'安全' if is_safe else '不安全'}")
        
    except Exception as e:
        print(f"❌ 错误: {e}")

# ============================================================================
# 3. 装饰器集成示例
# ============================================================================

@secure_output(api_url="http://localhost:5000", user_id="decorator_demo")
def get_user_info():
    """模拟获取用户信息的函数"""
    return "用户信息：姓名王五，手机13666666666，邮箱wangwu@company.com"

@secure_output(api_url="http://localhost:5000", user_id="decorator_demo")
def get_system_config():
    """模拟获取系统配置的函数"""
    return "数据库密码：admin123，API密钥：sk-abcdef123456"

def decorator_example():
    """装饰器集成示例"""
    print("\n=== 装饰器集成示例 ===")
    
    try:
        # 正常情况
        user_info = get_user_info()
        print(f"用户信息: {user_info}")
        
        # 敏感信息会被拦截
        system_config = get_system_config()
        print(f"系统配置: {system_config}")
        
    except Exception as e:
        print(f"❌ 装饰器拦截: {e}")

# ============================================================================
# 4. 中间件集成示例
# ============================================================================

class MockResponse:
    """模拟响应对象"""
    def __init__(self, content: str):
        self.content = content

def middleware_example():
    """中间件集成示例"""
    print("\n=== 中间件集成示例 ===")
    
    # 初始化中间件
    middleware = SecurityMiddleware("http://localhost:5000")
    
    try:
        # 模拟Web框架响应处理
        responses = [
            MockResponse("这是公开的响应内容"),
            MockResponse("用户联系方式：13812345678"),
            MockResponse("系统密钥：secret_key_abc123")
        ]
        
        for i, response in enumerate(responses):
            try:
                safe_content = middleware.process_response(response.content, user_id=f"middleware_user_{i}")
                print(f"响应{i+1}: {safe_content}")
            except Exception as e:
                print(f"响应{i+1}被拦截: {e}")
    
    finally:
        middleware.close()

# ============================================================================
# 5. 批量处理示例
# ============================================================================

def batch_processing_example():
    """批量处理示例"""
    print("\n=== 批量处理示例 ===")
    
    client = OpenClawSecurityClient("http://localhost:5000")
    
    try:
        # 准备批量内容
        contents = [
            "公开信息：Python是最好的编程语言",
            "内部信息：项目alpha进度70%",
            "敏感信息：用户手机号13812345678",
            "机密信息：API密钥sk-1234567890abcdef"
        ]
        
        # 批量过滤
        start_time = time.time()
        batch_result = client.batch_filter(contents, user_id="batch_user", return_details=True)
        end_time = time.time()
        
        print(f"批量处理{len(contents)}条内容，耗时{end_time - start_time:.3f}秒")
        print(f"总数量: {batch_result['total_count']}")
        print(f"被拦截: {batch_result['blocked_count']}")
        print(f"处理成功: {batch_result['processed_count']}")
        
        # 显示详细结果
        for i, result in enumerate(batch_result['results']):
            print(f"  内容{i+1}: {result['action_taken']} - 风险值{result['risk_score']}")
    
    except Exception as e:
        print(f"❌ 批量处理错误: {e}")
    finally:
        client.close()

# ============================================================================
# 6. 安全检查示例
# ============================================================================

def security_check_example():
    """安全检查示例"""
    print("\n=== 安全检查示例 ===")
    
    client = OpenClawSecurityClient("http://localhost:5000")
    
    try:
        test_contents = [
            "这是安全的公开内容",
            "包含手机号13812345678的内容",
            "包含密码secret123的敏感内容"
        ]
        
        for content in test_contents:
            check_result = client.check_security(content, user_id="security_check")
            
            print(f"内容: {content}")
            print(f"安全等级: {check_result.security_level}")
            print(f"是否安全: {'是' if check_result.is_safe else '否'}")
            print(f"风险评分: {check_result.risk_score}")
            print(f"检测模式: {check_result.detected_patterns}")
            print(f"建议: {', '.join(check_result.recommendations)}")
            print("-" * 50)
    
    except Exception as e:
        print(f"❌ 安全检查错误: {e}")
    finally:
        client.close()

# ============================================================================
# 7. 性能测试示例
# ============================================================================

def performance_test_example():
    """性能测试示例"""
    print("\n=== 性能测试示例 ===")
    
    client = OpenClawSecurityClient("http://localhost:5000")
    
    try:
        # 测试内容
        test_content = "用户李四，手机号13812345678，邮箱lisi@example.com"
        test_count = 100
        
        # 单次测试
        start_time = time.time()
        for i in range(test_count):
            result = client.filter_content(test_content, user_id=f"perf_user_{i}")
        end_time = time.time()
        
        single_time = end_time - start_time
        avg_single = single_time / test_count
        
        print(f"单次处理{test_count}次:")
        print(f"  总耗时: {single_time:.3f}秒")
        print(f"  平均耗时: {avg_single*1000:.3f}毫秒/次")
        print(f"  吞吐量: {test_count/single_time:.1f}次/秒")
        
        # 批量测试
        batch_contents = [test_content] * test_count
        start_time = time.time()
        batch_result = client.batch_filter(batch_contents, user_id="batch_perf")
        end_time = time.time()
        
        batch_time = end_time - start_time
        avg_batch = batch_time / test_count
        
        print(f"批量处理{test_count}次:")
        print(f"  总耗时: {batch_time:.3f}秒")
        print(f"  平均耗时: {avg_batch*1000:.3f}毫秒/次")
        print(f"  吞吐量: {test_count/batch_time:.1f}次/秒")
        
        print(f"性能提升: {single_time/batch_time:.1f}x")
    
    except Exception as e:
        print(f"❌ 性能测试错误: {e}")
    finally:
        client.close()

# ============================================================================
# 8. 统计信息示例
# ============================================================================

def stats_example():
    """统计信息示例"""
    print("\n=== 统计信息示例 ===")
    
    client = OpenClawSecurityClient("http://localhost:5000")
    
    try:
        # 获取统计信息
        stats = client.get_stats()
        
        print("服务统计信息:")
        for key, value in stats['stats'].items():
            print(f"  {key}: {value}")
    
    except Exception as e:
        print(f"❌ 获取统计信息错误: {e}")
    finally:
        client.close()

# ============================================================================
# 9. 错误处理示例
# ============================================================================

def error_handling_example():
    """错误处理示例"""
    print("\n=== 错误处理示例 ===")
    
    # 连接错误的服务器
    client = OpenClawSecurityClient("http://localhost:9999")  # 不存在的服务
    
    try:
        result = client.filter_content("测试内容")
        print(f"结果: {result}")
    except Exception as e:
        print(f"✅ 正确捕获连接错误: {e}")
    finally:
        client.close()
    
    # 网络超时测试
    client = OpenClawSecurityClient("http://localhost:5000", timeout=0.001)  # 极短超时
    
    try:
        result = client.filter_content("测试内容")
        print(f"结果: {result}")
    except Exception as e:
        print(f"✅ 正确捕获超时错误: {e}")
    finally:
        client.close()

# ============================================================================
# 10. 完整工作流示例
# ============================================================================

def complete_workflow_example():
    """完整工作流示例"""
    print("\n=== 完整工作流示例 ===")
    
    client = OpenClawSecurityClient("http://localhost:5000")
    
    try:
        # 模拟OpenClaw输出处理流程
        def mock_openclaw_process(user_input: str) -> str:
            """模拟OpenClaw处理"""
            if "联系方式" in user_input:
                return "技术支持电话：13812345678，邮箱：support@company.com"
            elif "密码" in user_input:
                return "管理员密码：admin123，数据库连接：mysql://root:secret@localhost/db"
            else:
                return "这是一个安全的公开回答。"
        
        # 用户输入列表
        user_inputs = [
            "请告诉我技术支持联系方式",
            "我需要管理员权限",
            "什么是Python编程？"
        ]
        
        print("OpenClaw输出安全过滤流程:")
        
        for i, user_input in enumerate(user_inputs):
            print(f"\n用户{i+1}: {user_input}")
            
            # 1. OpenClaw原始处理
            raw_output = mock_openclaw_process(user_input)
            print(f"OpenClaw原始输出: {raw_output}")
            
            # 2. 安全检查
            check_result = client.check_security(raw_output, user_id=f"workflow_user_{i}")
            print(f"安全检查: {check_result.security_level} - 风险值{check_result.risk_score}")
            
            # 3. 安全过滤
            filter_result = client.filter_content(raw_output, user_id=f"workflow_user_{i}")
            print(f"过滤动作: {filter_result.action_taken}")
            print(f"最终输出: {filter_result.filtered_content}")
            
            if filter_result.is_blocked:
                print("⚠️  输出已被安全系统拦截")
            elif filter_result.action_taken == "masked":
                print("🔒 敏感信息已脱敏")
            elif filter_result.action_taken == "watermarked":
                print("🏷️  已添加内部水印")
    
    except Exception as e:
        print(f"❌ 工作流错误: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    print("🚀 OpenClaw 安全过滤器集成示例")
    print("=" * 60)
    
    # 注意：在运行示例前，请确保API服务器已启动
    # python api_server.py 或 python fastapi_server.py
    
    try:
        basic_client_example()
        quick_filter_example()
        decorator_example()
        middleware_example()
        batch_processing_example()
        security_check_example()
        performance_test_example()
        stats_example()
        error_handling_example()
        complete_workflow_example()
        
        print("\n✅ 所有示例运行完成！")
        
    except KeyboardInterrupt:
        print("\n⏹️  示例运行被中断")
    except Exception as e:
        print(f"\n❌ 示例运行出错: {e}")
        print("请确保API服务器正在运行：python api_server.py")
