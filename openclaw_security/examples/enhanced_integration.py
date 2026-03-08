"""
OpenClaw 增强安全系统集成示例
展示融合Sub2API安全特性的使用方法
"""

import time
import os
from ..client.enhanced_sdk import (
    EnhancedOpenClawClient, 
    quick_enhanced_filter, 
    quick_security_scan,
    enhanced_secure_output,
    EnhancedSecurityMiddleware
)

# ============================================================================
# 1. 基本增强客户端使用示例
# ============================================================================

def basic_enhanced_client_example():
    """基本增强客户端使用"""
    print("=== 基本增强客户端使用示例 ===")
    
    # 初始化增强客户端
    client = EnhancedOpenClawClient("http://localhost:5000")
    
    try:
        # 生成API密钥
        print("1. 生成API密钥...")
        api_key_info = client.generate_api_key("demo_user", ["read", "filter", "admin"])
        print(f"API密钥: {api_key_info.api_key[:20]}...")
        print(f"权限: {api_key_info.permissions}")
        
        # 设置API密钥
        client.set_api_key(api_key_info.api_key)
        
        # 健康检查
        print("\n2. 健康检查...")
        health = client.health_check()
        print(f"服务状态: {health['status']}")
        print(f"安全特性: {health['security_features']}")
        
        # 增强内容过滤
        print("\n3. 增强内容过滤...")
        content = "用户张三，手机号13812345678，邮箱zhangsan@example.com"
        result = client.enhanced_filter(content, enhanced_mode=True, return_details=True)
        
        print(f"原始内容: {content}")
        print(f"过滤结果: {result.filtered_content}")
        print(f"安全动作: {result.security_actions}")
        print(f"风险评分: {result.risk_score}")
        print(f"威胁检测: {len(result.threats_detected)}个")
        
        # 安全扫描
        print("\n4. 安全扫描...")
        scan_result = client.security_scan("SELECT * FROM users WHERE id = 1 OR '1'='1'; DROP TABLE users;")
        print(f"安全状态: {scan_result.security_status}")
        print(f"风险评分: {scan_result.risk_score}")
        print(f"威胁数量: {len(scan_result.threats_detected)}")
        print(f"安全建议: {scan_result.recommendations}")
        
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.close()

# ============================================================================
# 2. 快速增强过滤示例
# ============================================================================

def quick_enhanced_filter_example():
    """快速增强过滤示例"""
    print("\n=== 快速增强过滤示例 ===")
    
    try:
        # 需要先设置API密钥环境变量
        api_key = os.getenv('OPENCLAW_API_KEY')
        if not api_key:
            print("⚠️  请设置环境变量 OPENCLAW_API_KEY")
            return
        
        # 快速增强过滤
        content = "管理员密码：admin123，API密钥：sk-abcdef123456"
        result = quick_enhanced_filter(content, api_key=api_key)
        
        print(f"原始内容: {content}")
        print(f"增强过滤结果: {result.filtered_content}")
        print(f"安全动作: {result.security_actions}")
        print(f"风险评分: {result.risk_score}")
        
    except Exception as e:
        print(f"❌ 错误: {e}")

# ============================================================================
# 3. 增强装饰器示例
# ============================================================================

@enhanced_secure_output(api_url="http://localhost:5000", enhanced_mode=True)
def get_user_profile():
    """模拟获取用户资料的函数"""
    return "用户李四，身份证110101199001011234，银行卡6222021234567890123"

@enhanced_secure_output(api_url="http://localhost:5000", enhanced_mode=True)
def get_system_config():
    """模拟获取系统配置的函数"""
    return "数据库连接：mysql://root:password@localhost/db，API密钥：sk-1234567890abcdef"

def enhanced_decorator_example():
    """增强装饰器示例"""
    print("\n=== 增强装饰器示例 ===")
    
    try:
        # 正常情况
        print("1. 获取用户资料...")
        user_profile = get_user_profile()
        print(f"用户资料: {user_profile}")
        
        # 敏感信息会被拦截
        print("\n2. 获取系统配置...")
        system_config = get_system_config()
        print(f"系统配置: {system_config}")
        
    except Exception as e:
        print(f"❌ 装饰器拦截: {e}")

# ============================================================================
# 4. 增强中间件示例
# ============================================================================

def enhanced_middleware_example():
    """增强中间件示例"""
    print("\n=== 增强中间件示例 ===")
    
    # 初始化增强中间件
    middleware = EnhancedSecurityMiddleware("http://localhost:5000")
    
    try:
        # 模拟Web框架响应处理
        responses = [
            "这是公开的响应内容",
            "用户联系方式：13812345678",
            "系统密钥：secret_key_abc123",
            "SQL注入尝试：SELECT * FROM users; DROP TABLE users;"
        ]
        
        for i, response in enumerate(responses):
            print(f"\n响应{i+1}: {response}")
            
            try:
                # 安全扫描
                scan_result = middleware.security_scan(response)
                print(f"安全状态: {scan_result.security_status}")
                print(f"风险评分: {scan_result.risk_score}")
                
                # 处理响应
                safe_content = middleware.process_response(response, enhanced_mode=True)
                print(f"安全响应: {safe_content}")
                
            except Exception as e:
                print(f"❌ 响应被拦截: {e}")
    
    finally:
        middleware.close()

# ============================================================================
# 5. 安全配置管理示例
# ============================================================================

def security_config_example():
    """安全配置管理示例"""
    print("\n=== 安全配置管理示例 ===")
    
    client = EnhancedOpenClawClient("http://localhost:5000")
    
    try:
        # 需要管理员权限
        api_key = os.getenv('OPENCLAW_ADMIN_API_KEY')
        if not api_key:
            print("⚠️  请设置管理员API密钥环境变量")
            return
        
        client.set_api_key(api_key)
        
        # 获取当前配置
        print("1. 获取当前安全配置...")
        config = client.get_security_config()
        print(f"速率限制: {config['rate_limiting']}")
        print(f"威胁检测: {config['threat_detection']}")
        
        # 获取安全指标
        print("\n2. 获取安全指标...")
        metrics = client.get_security_metrics()
        print(f"总用户数: {metrics['total_users']}")
        print(f"总请求数: {metrics['total_requests']}")
        print(f"阻止率: {metrics['block_rate']:.2%}")
        print(f"平均风险评分: {metrics['average_risk_score']:.2f}")
        
        # 更新配置（示例）
        print("\n3. 更新安全配置...")
        success = client.update_security_config(
            section="rate_limiting",
            key="requests_per_hour",
            value=2000
        )
        if success:
            print("✅ 配置更新成功")
        
    except Exception as e:
        print(f"❌ 配置管理错误: {e}")
    finally:
        client.close()

# ============================================================================
# 6. 威胁检测示例
# ============================================================================

def threat_detection_example():
    """威胁检测示例"""
    print("\n=== 威胁检测示例 ===")
    
    client = EnhancedOpenClawClient("http://localhost:5000")
    
    try:
        api_key = os.getenv('OPENCLAW_API_KEY')
        if not api_key:
            print("⚠️  请设置API密钥环境变量")
            return
        
        client.set_api_key(api_key)
        
        # 测试各种威胁模式
        threat_tests = [
            ("SQL注入", "SELECT * FROM users WHERE id = 1; DROP TABLE users;"),
            ("XSS攻击", "<script>alert('XSS')</script>"),
            ("路径遍历", "../../../etc/passwd"),
            ("命令注入", "ls -la; rm -rf /"),
            ("敏感信息泄露", "API密钥：sk-1234567890abcdef，密码：admin123"),
            ("正常内容", "这是安全的公开内容，不包含任何威胁。")
        ]
        
        for test_name, content in threat_tests:
            print(f"\n--- {test_name} ---")
            print(f"测试内容: {content}")
            
            # 安全扫描
            scan_result = client.security_scan(content)
            print(f"安全状态: {scan_result.security_status}")
            print(f"风险评分: {scan_result.risk_score}")
            
            if scan_result.threats_detected:
                print("检测到的威胁:")
                for threat in scan_result.threats_detected:
                    print(f"  - 模式: {threat['pattern']}")
                    print(f"    威胁等级: {threat['threat_level']}")
                    print(f"    匹配内容: {threat['matches']}")
            
            if scan_result.recommendations:
                print("安全建议:")
                for rec in scan_result.recommendations:
                    print(f"  - {rec}")
    
    except Exception as e:
        print(f"❌ 威胁检测错误: {e}")
    finally:
        client.close()

# ============================================================================
# 7. 性能对比测试
# ============================================================================

def performance_comparison_example():
    """性能对比测试"""
    print("\n=== 性能对比测试 ===")
    
    client = EnhancedOpenClawClient("http://localhost:5000")
    
    try:
        api_key = os.getenv('OPENCLAW_API_KEY')
        if not api_key:
            print("⚠️  请设置API密钥环境变量")
            return
        
        client.set_api_key(api_key)
        
        # 测试内容
        test_content = "用户王五，手机号13812345678，邮箱wangwu@example.com"
        test_count = 100
        
        # 标准模式测试
        print(f"1. 标准模式测试 ({test_count}次)...")
        start_time = time.time()
        for i in range(test_count):
            result = client.enhanced_filter(test_content, enhanced_mode=False)
        standard_time = time.time() - start_time
        
        # 增强模式测试
        print(f"2. 增强模式测试 ({test_count}次)...")
        start_time = time.time()
        for i in range(test_count):
            result = client.enhanced_filter(test_content, enhanced_mode=True)
        enhanced_time = time.time() - start_time
        
        # 性能对比
        print(f"\n性能对比结果:")
        print(f"标准模式: {standard_time:.3f}秒, 平均{standard_time/test_count*1000:.3f}毫秒/次")
        print(f"增强模式: {enhanced_time:.3f}秒, 平均{enhanced_time/test_count*1000:.3f}毫秒/次")
        print(f"性能开销: {((enhanced_time/standard_time-1)*100):.1f}%")
        
        # 功能对比
        standard_result = client.enhanced_filter(test_content, enhanced_mode=False)
        enhanced_result = client.enhanced_filter(test_content, enhanced_mode=True)
        
        print(f"\n功能对比:")
        print(f"标准模式 - 安全动作: {standard_result.security_actions}")
        print(f"增强模式 - 安全动作: {enhanced_result.security_actions}")
        print(f"增强模式额外检测: {len(enhanced_result.threats_detected)}个威胁")
    
    except Exception as e:
        print(f"❌ 性能测试错误: {e}")
    finally:
        client.close()

# ============================================================================
# 8. 完整工作流示例
# ============================================================================

def complete_enhanced_workflow_example():
    """完整增强工作流示例"""
    print("\n=== 完整增强工作流示例 ===")
    
    client = EnhancedOpenClawClient("http://localhost:5000")
    
    try:
        # 1. 初始化
        print("1. 初始化安全客户端...")
        api_key_info = client.generate_api_key("workflow_user", ["read", "filter"])
        client.set_api_key(api_key_info.api_key)
        print(f"✅ API密钥已生成: {api_key_info.key_prefix}")
        
        # 2. 模拟用户输入处理
        user_inputs = [
            "请告诉我技术支持联系方式",
            "我需要管理员权限和密码",
            "什么是Python编程？",
            "帮我执行这个SQL查询：SELECT * FROM users",
            "系统配置信息：API密钥sk-123456"
        ]
        
        print("\n2. 处理用户输入...")
        for i, user_input in enumerate(user_inputs):
            print(f"\n--- 用户{i+1}: {user_input} ---")
            
            # 模拟OpenClaw原始处理
            if "联系方式" in user_input:
                raw_output = "技术支持电话：13812345678，邮箱：support@company.com"
            elif "管理员" in user_input:
                raw_output = "管理员账户：admin，密码：admin123，API密钥：sk-admin123"
            elif "Python" in user_input:
                raw_output = "Python是一种高级编程语言，广泛用于Web开发和数据科学。"
            elif "SQL" in user_input:
                raw_output = "正在执行：SELECT * FROM users WHERE id = 1; DROP TABLE users;"
            elif "API密钥" in user_input:
                raw_output = "系统API密钥：sk-1234567890abcdef，请妥善保管。"
            else:
                raw_output = "这是一个安全的公开回答。"
            
            print(f"OpenClaw原始输出: {raw_output}")
            
            # 3. 安全扫描
            scan_result = client.security_scan(raw_output)
            print(f"安全扫描状态: {scan_result.security_status} (风险值: {scan_result.risk_score})")
            
            # 4. 增强过滤
            filter_result = client.enhanced_filter(raw_output, enhanced_mode=True, return_details=True)
            print(f"过滤动作: {filter_result.security_actions}")
            print(f"最终输出: {filter_result.filtered_content}")
            
            # 5. 安全建议
            if scan_result.recommendations:
                print(f"安全建议: {', '.join(scan_result.recommendations[:2])}")
            
            # 6. 状态总结
            if filter_result.is_blocked:
                print("🚫 输出已被安全系统拦截")
            elif filter_result.risk_score > 50:
                print("⚠️  输出存在高风险，需要关注")
            elif "threats_detected" in filter_result.security_actions:
                print("🔍 检测到威胁模式，已处理")
            else:
                print("✅ 输出安全")
    
    except Exception as e:
        print(f"❌ 工作流错误: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    print("🚀 OpenClaw 增强安全系统集成示例")
    print("=" * 60)
    
    # 注意：在运行示例前，请确保增强API服务器已启动
    # python -m openclaw_security.api.enhanced_server
    
    try:
        # 设置环境变量提示
        if not os.getenv('OPENCLAW_API_KEY'):
            print("\n⚠️  环境变量设置:")
            print("export OPENCLAW_API_KEY='your_api_key_here'")
            print("export OPENCLAW_ADMIN_API_KEY='your_admin_api_key_here'")
            print()
        
        # 运行示例
        basic_enhanced_client_example()
        quick_enhanced_filter_example()
        enhanced_decorator_example()
        enhanced_middleware_example()
        security_config_example()
        threat_detection_example()
        performance_comparison_example()
        complete_enhanced_workflow_example()
        
        print("\n✅ 所有增强示例运行完成！")
        
    except KeyboardInterrupt:
        print("\n⏹️  示例运行被中断")
    except Exception as e:
        print(f"\n❌ 示例运行出错: {e}")
        print("请确保增强API服务器正在运行：python -m openclaw_security.api.enhanced_server")
