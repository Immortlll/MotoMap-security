"""
快速验证安全过滤器功能
"""

from security_filter import SecurityFilter, SecurityException, filter_openclaw_output
from security_config import SecurityLevel

def quick_test():
    """快速功能测试"""
    print("=== OpenClaw 安全过滤器快速检查 ===\n")
    
    filter_instance = SecurityFilter(enable_audit=False)
    
    test_cases = [
        ("公开信息", "这是一个公开的技术文档，包含Python编程基础知识"),
        ("内部信息", "项目alpha的开发进度：已完成70%，内部服务器192.168.1.100"),
        ("敏感信息", "用户张三，手机号13812345678，邮箱zhangsan@example.com"),
        ("机密信息", "数据库连接：mysql://user:password123@localhost/db，API密钥：sk-1234567890abcdef"),
        ("混合信息", "公开内容，用户手机号13987654321，系统密码secret123")
    ]
    
    print("1. 基本功能测试:")
    for name, content in test_cases:
        result = filter_instance.filter_content(content, user_id="quick_test")
        level = result.security_level.value if result.security_level else "None"
        print(f"  {name}: {level} - {result.action_taken} - 风险值:{result.risk_score:.1f}")
    
    print("\n2. 脱敏效果测试:")
    sensitive_content = "用户李四，手机号15987654321，邮箱lisi@company.com，身份证110101199002022345"
    result = filter_instance.filter_content(sensitive_content, user_id="mask_test")
    print(f"  原始: {sensitive_content}")
    print(f"  脱敏: {result.filtered_content}")
    
    print("\n3. 拦截功能测试:")
    secret_content = "私钥：-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"
    result = filter_instance.filter_content(secret_content, user_id="block_test")
    print(f"  原始: {secret_content[:30]}...")
    print(f"  结果: {result.filtered_content}")
    print(f"  拦截: {result.is_blocked}")
    
    print("\n4. 便捷函数测试:")
    try:
        content = "用户手机号13812345678"
        safe_content = filter_openclaw_output(content, user_id="func_test")
        print(f"  输入: {content}")
        print(f"  输出: {safe_content}")
    except SecurityException as e:
        print(f"  异常: {e}")
    
    print("\n5. 配置验证:")
    print(f"  L4规则数: {len(filter_instance.compiled_patterns.get(SecurityLevel.L4_TOP_SECRET, []))}")
    print(f"  L3规则数: {len(filter_instance.compiled_patterns.get(SecurityLevel.L3_CONFIDENTIAL, []))}")
    print(f"  L2规则数: {len(filter_instance.compiled_patterns.get(SecurityLevel.L2_INTERNAL, []))}")
    
    print("\n=== 快速检查完成 ===")

if __name__ == "__main__":
    quick_test()
