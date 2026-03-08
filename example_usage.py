"""
OpenClaw 安全过滤器使用示例
演示如何集成和使用安全过滤中间件
"""

from security_filter import SecurityFilter, filter_openclaw_output, SecurityException
from security_config import SecurityLevel

def demo_basic_usage():
    """基本使用示例"""
    print("=== 基本使用示例 ===")
    
    # 示例内容
    test_contents = [
        # 公开信息
        "这是一个公开的技术文档，包含Python编程基础知识。",
        
        # 内部信息
        "项目alpha的开发进度：已完成70%，预计下月发布。内部服务器地址：192.168.1.100",
        
        # 高度敏感信息
        "用户张三的联系方式：13812345678，邮箱：zhangsan@example.com，身份证号：110101199001011234",
        
        # 极度敏感信息
        "数据库连接：mysql://user:password123@localhost:3306/dbname，API密钥：sk-1234567890abcdef",
    ]
    
    filter_instance = SecurityFilter()
    
    for i, content in enumerate(test_contents, 1):
        print(f"\n--- 测试 {i} ---")
        print(f"原始内容: {content}")
        
        try:
            result = filter_instance.filter_content(content, user_id=f"demo_user_{i}")
            print(f"安全等级: {result.security_level.value if result.security_level else 'None'}")
            print(f"风险评分: {result.risk_score}")
            print(f"处理动作: {result.action_taken}")
            print(f"是否被拦截: {result.is_blocked}")
            print(f"过滤后内容: {result.filtered_content}")
            if result.detected_patterns:
                print(f"检测到模式: {result.detected_patterns}")
        except Exception as e:
            print(f"处理异常: {e}")

def demo_openclaw_integration():
    """OpenClaw集成示例"""
    print("\n=== OpenClaw集成示例 ===")
    
    def mock_openclaw_process(user_input: str) -> str:
        """模拟OpenClaw处理函数"""
        # 这里是OpenClaw的实际处理逻辑
        if "密码" in user_input:
            return "系统管理员密码是：admin123，数据库连接字符串为：mysql://root:secret@localhost/db"
        elif "联系方式" in user_input:
            return "请联系张三，电话：13812345678，邮箱：zhangsan@company.com"
        else:
            return "这是一个公开的回答，不包含敏感信息。"
    
    # 用户输入
    user_inputs = [
        "请告诉我系统密码",
        "我需要联系技术支持",
        "什么是Python？"
    ]
    
    for user_input in user_inputs:
        print(f"\n用户输入: {user_input}")
        
        try:
            # OpenClaw处理
            raw_output = mock_openclaw_process(user_input)
            print(f"OpenClaw原始输出: {raw_output}")
            
            # 安全过滤
            safe_output = filter_openclaw_output(raw_output, user_id="user_001")
            print(f"安全过滤后输出: {safe_output}")
            
        except SecurityException as e:
            print(f"安全拦截: {e}")

def demo_custom_rules():
    """自定义规则示例"""
    print("\n=== 自定义规则示例 ===")
    
    # 创建自定义过滤器
    custom_filter = SecurityFilter()
    
    # 添加自定义检测规则（临时）
    custom_pattern = r'(?i)secret[_-]?code["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{8,})["\']?'
    
    test_content = "系统配置：secret_code='ABC12345XYZ'，其他信息正常"
    print(f"测试内容: {test_content}")
    
    result = custom_filter.filter_content(test_content, user_id="custom_test")
    print(f"检测结果: {result.action_taken}")
    print(f"风险评分: {result.risk_score}")

def demo_batch_processing():
    """批量处理示例"""
    print("\n=== 批量处理示例 ===")
    
    batch_contents = [
        "公开信息1：Python是最好的编程语言",
        "内部信息2：项目beta将在Q3发布",
        "敏感信息3：用户手机号：13987654321",
        "机密信息4：私钥：-----BEGIN RSA PRIVATE KEY-----"
    ]
    
    filter_instance = SecurityFilter()
    
    results = []
    blocked_count = 0
    masked_count = 0
    watermarked_count = 0
    
    for content in batch_contents:
        result = filter_instance.filter_content(content, user_id="batch_user")
        results.append(result)
        
        if result.is_blocked:
            blocked_count += 1
        elif result.action_taken == "masked":
            masked_count += 1
        elif result.action_taken == "watermarked":
            watermarked_count += 1
    
    print(f"批量处理结果：")
    print(f"总处理数: {len(results)}")
    print(f"被拦截: {blocked_count}")
    print(f"已脱敏: {masked_count}")
    print(f"已水印: {watermarked_count}")
    print(f"直接放行: {len(results) - blocked_count - masked_count - watermarked_count}")

def demo_performance_test():
    """性能测试示例"""
    print("\n=== 性能测试示例 ===")
    
    import time
    
    # 生成测试内容
    test_content = "这是一个包含敏感信息的测试内容：用户手机号13812345678，邮箱test@example.com，" * 100
    
    filter_instance = SecurityFilter()
    
    # 测试多次过滤的性能
    test_times = 100
    start_time = time.time()
    
    for i in range(test_times):
        result = filter_instance.filter_content(test_content, user_id=f"perf_test_{i}")
    
    end_time = time.time()
    avg_time = (end_time - start_time) / test_times
    
    print(f"性能测试结果：")
    print(f"测试次数: {test_times}")
    print(f"总耗时: {end_time - start_time:.4f}秒")
    print(f"平均耗时: {avg_time*1000:.4f}毫秒/次")
    print(f"每秒处理能力: {1/avg_time:.2f}次")

if __name__ == "__main__":
    # 运行所有示例
    demo_basic_usage()
    demo_openclaw_integration()
    demo_custom_rules()
    demo_batch_processing()
    demo_performance_test()
