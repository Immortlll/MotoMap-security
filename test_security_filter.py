"""
安全过滤器测试用例
验证各级别数据的检测和处理功能
"""

import unittest
from security_filter import SecurityFilter, SecurityException
from security_config import SecurityLevel

class TestSecurityFilter(unittest.TestCase):
    
    def setUp(self):
        self.filter = SecurityFilter(enable_audit=False)  # 测试时关闭审计
    
    def test_public_content(self):
        """测试公开内容"""
        content = "Python是一种流行的编程语言，适合初学者学习。"
        result = self.filter.filter_content(content)
        
        self.assertFalse(result.is_blocked)
        self.assertEqual(result.security_level, SecurityLevel.L1_PUBLIC)
        self.assertEqual(result.action_taken, "allowed")
        self.assertEqual(result.filtered_content, content)
        self.assertEqual(result.risk_score, 0.0)
    
    def test_internal_content(self):
        """测试内部内容"""
        content = "项目alpha的开发进度已完成70%，内部服务器192.168.1.100可访问。"
        result = self.filter.filter_content(content)
        
        self.assertFalse(result.is_blocked)
        self.assertEqual(result.security_level, SecurityLevel.L2_INTERNAL)
        self.assertEqual(result.action_taken, "watermarked")
        self.assertIn("[OpenClaw-Internal-", result.filtered_content)
        self.assertGreater(result.risk_score, 0)
    
    def test_confidential_content(self):
        """测试高度敏感内容"""
        content = "用户张三，手机号13812345678，邮箱zhangsan@example.com，身份证110101199001011234"
        result = self.filter.filter_content(content)
        
        self.assertFalse(result.is_blocked)
        self.assertEqual(result.security_level, SecurityLevel.L3_CONFIDENTIAL)
        self.assertEqual(result.action_taken, "masked")
        self.assertIn("13****5678", result.filtered_content)
        self.assertIn("z***@example.com", result.filtered_content)
    
    def test_top_secret_content(self):
        """测试极度敏感内容"""
        content = "数据库连接：mysql://user:password123@localhost/db，API密钥：sk-1234567890abcdef"
        result = self.filter.filter_content(content)
        
        self.assertTrue(result.is_blocked)
        self.assertEqual(result.security_level, SecurityLevel.L4_TOP_SECRET)
        self.assertEqual(result.action_taken, "blocked")
        self.assertIn("[BLOCKED]", result.filtered_content)
    
    def test_private_key_detection(self):
        """测试私钥检测"""
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        result = self.filter.filter_content(content)
        
        self.assertTrue(result.is_blocked)
        self.assertEqual(result.security_level, SecurityLevel.L4_TOP_SECRET)
    
    def test_mixed_content(self):
        """测试混合内容（应按最高等级处理）"""
        content = "这是公开信息。用户手机号13812345678。数据库密码：secret123"
        result = self.filter.filter_content(content)
        
        # 应该被L4规则阻断
        self.assertTrue(result.is_blocked)
        self.assertEqual(result.security_level, SecurityLevel.L4_TOP_SECRET)
    
    def test_email_masking(self):
        """测试邮箱脱敏"""
        content = "请联系john.doe@company.com获取支持"
        result = self.filter.filter_content(content)
        
        self.assertEqual(result.action_taken, "masked")
        self.assertIn("j***@company.com", result.filtered_content)
    
    def test_phone_masking(self):
        """测试手机号脱敏"""
        content = "紧急联系电话：15987654321"
        result = self.filter.filter_content(content)
        
        self.assertEqual(result.action_taken, "masked")
        self.assertIn("15****4321", result.filtered_content)
    
    def test_id_card_masking(self):
        """测试身份证脱敏"""
        content = "身份证号码：110101199001011234"
        result = self.filter.filter_content(content)
        
        self.assertEqual(result.action_taken, "masked")
        self.assertIn("11****1234", result.filtered_content)
    
    def test_risk_score_calculation(self):
        """测试风险评分计算"""
        # 低风险内容
        content1 = "项目alpha将在下月发布"
        result1 = self.filter.filter_content(content1)
        
        # 高风险内容
        content2 = "密码：secret123，手机号13812345678，私钥：-----BEGIN PRIVATE KEY-----"
        result2 = self.filter.filter_content(content2)
        
        self.assertGreater(result2.risk_score, result1.risk_score)
        self.assertGreaterEqual(result2.risk_score, 10.0)  # L4内容应该有高分
    
    def test_empty_content(self):
        """测试空内容"""
        content = ""
        result = self.filter.filter_content(content)
        
        self.assertFalse(result.is_blocked)
        self.assertEqual(result.filtered_content, content)
    
    def test_unicode_content(self):
        """测试Unicode内容"""
        content = "用户姓名：张三，邮箱：zhangsan@例子.com"
        result = self.filter.filter_content(content)
        
        self.assertFalse(result.is_blocked)
        self.assertIsInstance(result.filtered_content, str)
    
    def test_large_content(self):
        """测试大内容"""
        content = "公开信息。" * 10000 + "手机号13812345678"
        result = self.filter.filter_content(content)
        
        self.assertFalse(result.is_blocked)
        self.assertEqual(result.action_taken, "masked")
        self.assertGreater(len(result.filtered_content), 0)

class TestSecurityException(unittest.TestCase):
    
    def test_security_exception(self):
        """测试安全异常"""
        from security_filter import filter_openclaw_output
        
        content = "数据库密码：admin123"
        
        with self.assertRaises(SecurityException) as context:
            filter_openclaw_output(content)
        
        self.assertIn("被拦截", str(context.exception))

class TestPatternMatching(unittest.TestCase):
    
    def setUp(self):
        self.filter = SecurityFilter(enable_audit=False)
    
    def test_api_key_patterns(self):
        """测试API密钥模式匹配"""
        patterns = [
            "api_key=sk-1234567890abcdef",
            "API-KEY: 'abcd1234567890'",
            "secret_key : xyz987654321",
        ]
        
        for pattern in patterns:
            result = self.filter.filter_content(pattern)
            self.assertTrue(result.is_blocked, f"Pattern should be blocked: {pattern}")
    
    def test_database_patterns(self):
        """测试数据库连接模式匹配"""
        patterns = [
            "mysql://user:pass@localhost/db",
            "postgresql://admin:secret@db.example.com:5432/mydb",
            "mongodb://user:password@mongodb.example.com:27017/testdb",
        ]
        
        for pattern in patterns:
            result = self.filter.filter_content(pattern)
            self.assertTrue(result.is_blocked, f"Database pattern should be blocked: {pattern}")
    
    def test_server_ip_patterns(self):
        """测试内网IP模式匹配"""
        patterns = [
            "连接到192.168.1.100服务器",
            "访问10.0.0.50的API",
            "内网地址172.16.0.1",
        ]
        
        for pattern in patterns:
            result = self.filter.filter_content(pattern)
            self.assertEqual(result.action_taken, "watermarked", 
                           f"Internal IP should be watermarked: {pattern}")

if __name__ == '__main__':
    # 运行所有测试
    unittest.main(verbosity=2)
