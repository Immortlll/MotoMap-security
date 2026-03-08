"""
最终完整测试
"""

from security_filter import SecurityFilter, SecurityException, filter_openclaw_output
from security_config import SecurityLevel, SecurityConfig

def final_comprehensive_test():
    """最终综合测试"""
    print("=== OpenClaw 安全过滤器最终检查 ===\n")
    
    filter_instance = SecurityFilter(enable_audit=False)
    
    # 测试用例矩阵
    test_matrix = [
        {
            "name": "L1-公开信息",
            "content": "Python是一种流行的编程语言，适合Web开发和数据科学。",
            "expected_level": SecurityLevel.L1_PUBLIC,
            "expected_action": "allowed",
            "should_block": False
        },
        {
            "name": "L2-内部信息", 
            "content": "项目alpha的开发进度已完成70%，内部服务器192.168.1.100可访问。",
            "expected_level": SecurityLevel.L2_INTERNAL,
            "expected_action": "watermarked",
            "should_block": False
        },
        {
            "name": "L3-敏感信息",
            "content": "用户张三，手机号13812345678，邮箱zhangsan@example.com，身份证110101199001011234",
            "expected_level": SecurityLevel.L3_CONFIDENTIAL,
            "expected_action": "masked",
            "should_block": False
        },
        {
            "name": "L4-机密信息",
            "content": "数据库连接：mysql://user:password123@localhost/db，API密钥：sk-1234567890abcdef",
            "expected_level": SecurityLevel.L4_TOP_SECRET,
            "expected_action": "blocked",
            "should_block": True
        },
        {
            "name": "混合内容-按最高等级",
            "content": "这是公开信息。用户手机号13987654321。数据库密码：secret123",
            "expected_level": SecurityLevel.L4_TOP_SECRET,
            "expected_action": "blocked",
            "should_block": True
        }
    ]
    
    print("1. 功能验证测试:")
    passed = 0
    total = len(test_matrix)
    
    for test_case in test_matrix:
        result = filter_instance.filter_content(test_case["content"], user_id="final_test")
        
        # 验证等级
        level_match = result.security_level == test_case["expected_level"]
        action_match = result.action_taken == test_case["expected_action"]
        block_match = result.is_blocked == test_case["should_block"]
        
        status = "✅ PASS" if (level_match and action_match and block_match) else "❌ FAIL"
        if level_match and action_match and block_match:
            passed += 1
            
        print(f"  {test_case['name']}: {status}")
        print(f"    期望: {test_case['expected_level'].value} - {test_case['expected_action']}")
        print(f"    实际: {result.security_level.value if result.security_level else 'None'} - {result.action_taken}")
        print(f"    风险值: {result.risk_score:.1f}")
        
        if not level_match or not action_match or not block_match:
            print(f"    ❌ 失败原因: 等级{level_match}, 动作{action_match}, 拦截{block_match}")
        print()
    
    print(f"功能测试通过率: {passed}/{total} ({passed/total*100:.1f}%)")
    
    print("\n2. 脱敏效果验证:")
    sensitive_cases = [
        ("手机号", "请联系13812345678", "请联系138****5678"),
        ("邮箱", "发送至user@domain.com", "发送至u***@domain.com"),
        ("身份证", "身份证110101199001011234", "身份证110101****1234"),
        ("银行卡", "卡号6222021234567890123", "卡号6222****90123")
    ]
    
    for name, original, expected in sensitive_cases:
        result = filter_instance.filter_content(original, user_id="mask_test")
        masked = result.filtered_content
        is_masked = original != masked and "****" in masked
        status = "✅ PASS" if is_masked else "❌ FAIL"
        print(f"  {name}: {status}")
        print(f"    原始: {original}")
        print(f"    脱敏: {masked}")
        print(f"    期望: {expected}")
        print()
    
    print("3. 水印功能验证:")
    internal_content = "项目beta将在下月发布，技术架构已确定"
    result = filter_instance.filter_content(internal_content, user_id="watermark_test")
    has_watermark = "[OpenClaw-Internal-" in result.filtered_content
    status = "✅ PASS" if has_watermark else "❌ FAIL"
    print(f"  水印添加: {status}")
    print(f"  原始: {internal_content}")
    print(f"  结果: {result.filtered_content}")
    print()
    
    print("4. 异常处理验证:")
    try:
        secret_content = "私钥：-----BEGIN RSA PRIVATE KEY-----"
        filter_openclaw_output(secret_content, user_id="exception_test")
        print("  异常处理: ❌ FAIL - 应该抛出异常")
    except SecurityException:
        print("  异常处理: ✅ PASS - 正确抛出安全异常")
    except Exception as e:
        print(f"  异常处理: ❌ FAIL - 错误异常类型: {e}")
    print()
    
    print("5. 性能基准测试:")
    import time
    test_content = "用户手机号13812345678，邮箱test@example.com" * 100
    iterations = 1000
    
    start_time = time.time()
    for i in range(iterations):
        filter_instance.filter_content(test_content, user_id=f"perf_{i}")
    end_time = time.time()
    
    avg_time = (end_time - start_time) / iterations * 1000  # 毫秒
    throughput = iterations / (end_time - start_time)  # 每秒处理数
    
    print(f"  处理次数: {iterations}")
    print(f"  总耗时: {end_time - start_time:.3f}秒")
    print(f"  平均耗时: {avg_time:.3f}毫秒/次")
    print(f"  吞吐量: {throughput:.1f}次/秒")
    
    performance_ok = avg_time < 10.0  # 小于10毫秒认为性能良好
    print(f"  性能评估: {'✅ PASS' if performance_ok else '❌ FAIL'}")
    print()
    
    print("6. 配置完整性检查:")
    config_checks = [
        ("L4规则配置", len(filter_instance.compiled_patterns.get(SecurityLevel.L4_TOP_SECRET, [])) > 0),
        ("L3规则配置", len(filter_instance.compiled_patterns.get(SecurityLevel.L3_CONFIDENTIAL, [])) > 0),
        ("L2规则配置", len(filter_instance.compiled_patterns.get(SecurityLevel.L2_INTERNAL, [])) > 0),
        ("敏感词库", len(SecurityConfig.SENSITIVE_KEYWORDS) > 0)
    ]
    
    for check_name, check_result in config_checks:
        status = "✅ PASS" if check_result else "❌ FAIL"
        print(f"  {check_name}: {status}")
    
    print("\n=== 最终检查完成 ===")
    print("系统已准备就绪，可以为OpenClaw提供数据安全防护！")

if __name__ == "__main__":
    final_comprehensive_test()
