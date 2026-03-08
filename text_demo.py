#!/usr/bin/env python3
"""
文本版威胁可视化演示
不依赖图形库，用ASCII字符展示威胁力导向图
"""

import re
from datetime import datetime
from pathlib import Path

def detect_threats(content):
    """检测内容中的威胁"""
    threats = []
    
    # SQL注入模式
    sql_patterns = [
        r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*',
        r'(?i)(UNION|JOIN)\s+.*',
        r'(?i)(OR|AND)\s+\d+\s*=\s*\d+',
        r'(?i)(OR|AND)\s+["\']?\w+["\']?\s*=\s*["\']?\w+["\']?'
    ]
    
    for pattern in sql_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            threats.append({
                'type': 'SQL注入',
                'level': 'HIGH',
                'icon': '🗃️',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}"
            })
    
    # XSS模式
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:\s*\w+',
        r'on\w+\s*=\s*["\'][^"\']*["\']',
        r'<iframe[^>]*>.*?</iframe>'
    ]
    
    for pattern in xss_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            threats.append({
                'type': 'XSS攻击',
                'level': 'MEDIUM',
                'icon': '🌐',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}"
            })
    
    # 路径遍历模式
    path_patterns = [
        r'\.\./|\.\.\\',
        r'/etc/passwd',
        r'/proc/version',
        r'windows/system32'
    ]
    
    for pattern in path_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            threats.append({
                'type': '路径遍历',
                'level': 'MEDIUM',
                'icon': '📁',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}"
            })
    
    # 命令注入模式
    cmd_patterns = [
        r'[;&|`$(){}\[\]]',
        r'eval\s*\(',
        r'system\s*\(',
        r'exec\s*\('
    ]
    
    for pattern in cmd_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            threats.append({
                'type': '命令注入',
                'level': 'HIGH',
                'icon': '⚡',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}"
            })
    
    # 敏感数据模式
    sensitive_patterns = [
        r'(?i)(api[_-]?key|secret[_-]?key|password|token|private[_-]?key)\s*[:=]\s*[^\s]{8,}',
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ]
    
    for pattern in sensitive_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            threats.append({
                'type': '敏感数据',
                'level': 'CRITICAL',
                'icon': '🔑',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}"
            })
    
    return threats

def create_ascii_graph(content, threats):
    """创建ASCII字符版威胁图"""
    if not threats:
        return """
╔══════════════════════════════════════╗
║           🎨 威胁分析结果              ║
╚══════════════════════════════════════╝

✅ 未检测到威胁

📊 分析统计:
   • 威胁数量: 0
   • 风险等级: 安全
   • 处理建议: 内容安全，可正常使用

🔍 原始内容:
   {content}

⏰ 分析时间: {time}
""".format(content=content[:50] + '...' if len(content) > 50 else content,
             time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # 计算风险等级
    risk_score = 0
    level_weights = {'LOW': 1, 'MEDIUM': 5, 'HIGH': 10, 'CRITICAL': 20}
    
    for threat in threats:
        risk_score += level_weights.get(threat['level'], 5)
    
    if risk_score >= 50:
        risk_level = "CRITICAL"
        risk_emoji = "🚨"
    elif risk_score >= 20:
        risk_level = "HIGH"
        risk_emoji = "⚠️"
    elif risk_score >= 10:
        risk_level = "MEDIUM"
        risk_emoji = "⚡"
    else:
        risk_level = "LOW"
        risk_emoji = "🔍"
    
    # 统计威胁类型
    threat_types = {}
    for threat in threats:
        threat_types[threat['type']] = threat_types.get(threat['type'], 0) + 1
    
    # 创建ASCII图
    graph = """
╔══════════════════════════════════════╗
║           🎨 威胁分析结果              ║
╚══════════════════════════════════════╝

📊 分析统计:
   • 威胁数量: {threat_count}
   • 风险等级: {risk_level} {risk_emoji}
   • 风险评分: {risk_score}

🔍 威胁分布:
{threat_distribution}

🎯 威胁详情:
{threat_details}

💡 处理建议:
{recommendations}

🔍 原始内容:
{content}

⏰ 分析时间: {time}
""".format(
        threat_count=len(threats),
        risk_level=risk_level,
        risk_emoji=risk_emoji,
        risk_score=risk_score,
        threat_distribution='\n'.join(f"   • {t}: {c}个" for t, c in threat_types.items()),
        threat_details='\n'.join(f"   {i+1}. {threat['icon']} {threat['type']} ({threat['level']}): {threat['content'][:40]}{'...' if len(threat['content']) > 40 else ''}" 
                              for i, threat in enumerate(threats)),
        recommendations=get_recommendations(threats, risk_level),
        content=content[:50] + '...' if len(content) > 50 else content,
        time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    
    return graph

def get_recommendations(threats, risk_level):
    """获取处理建议"""
    recommendations = []
    
    if risk_level == "CRITICAL":
        recommendations.append("   🚨 检测到关键威胁，建议立即处理")
        recommendations.append("   🔒 考虑阻止或严格过滤此内容")
        recommendations.append("   📞 联系安全管理员进行评估")
    elif risk_level == "HIGH":
        recommendations.append("   ⚠️ 检测到高风险威胁，需要关注")
        recommendations.append("   🔍 建议进行人工审核")
        recommendations.append("   📊 增强监控和日志记录")
    elif risk_level == "MEDIUM":
        recommendations.append("   ⚡ 检测到中等风险威胁")
        recommendations.append("   📝 建议记录日志并定期检查")
        recommendations.append("   🔧 考虑添加额外的安全验证")
    else:
        recommendations.append("   🔍 检测到低风险威胁")
        recommendations.append("   ✅ 保持常规监控即可")
    
    # 基于威胁类型的建议
    threat_types = set(threat['type'] for threat in threats)
    
    if "SQL注入" in threat_types:
        recommendations.append("   🗃️ 检测到SQL注入，建议验证数据库查询")
    if "XSS攻击" in threat_types:
        recommendations.append("   🌐 检测到XSS攻击，建议过滤用户输入")
    if "敏感数据" in threat_types:
        recommendations.append("   🔑 检测到敏感数据，建议加密存储")
    if "命令注入" in threat_types:
        recommendations.append("   ⚡ 检测到命令注入，建议避免执行用户命令")
    if "路径遍历" in threat_types:
        recommendations.append("   📁 检测到路径遍历，建议限制文件访问")
    
    return '\n'.join(recommendations)

def create_force_diagram(threats):
    """创建简单的力导向图ASCII表示"""
    if not threats:
        return """
🎨 力导向图:
    [内容] ✅ 安全
"""
    
    diagram = """
🎨 力导向图:
"""
    
    # 中心节点（内容）
    diagram += "    [内容]\n"
    
    # 威胁节点
    for i, threat in enumerate(threats):
        if i == 0:
            diagram += "      |\n"
        else:
            diagram += "      |\n"
        
        # 根据威胁等级选择连接线
        if threat['level'] == 'CRITICAL':
            line = "══════"
        elif threat['level'] == 'HIGH':
            line = "═════"
        elif threat['level'] == 'MEDIUM':
            line = "════"
        else:
            line = "═══"
        
        diagram += f"      {line}\n"
        diagram += f"    [{threat['icon']} {threat['type']}]\n"
        diagram += f"      ({threat['level']})\n"
    
    return diagram

def run_text_demo():
    """运行文本版演示"""
    print("🎨 OpenClaw 威胁可视化演示 (文本版)")
    print("=" * 60)
    
    # 测试用例
    test_cases = [
        {
            "name": "SQL注入攻击",
            "content": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
            "description": "检测SQL注入威胁"
        },
        {
            "name": "XSS攻击",
            "content": "<script>alert('XSS攻击')</script>",
            "description": "检测跨站脚本威胁"
        },
        {
            "name": "复合威胁",
            "content": "用户输入：admin' OR '1'='1'; <script>document.cookie</script>",
            "description": "检测多种威胁类型"
        },
        {
            "name": "敏感信息",
            "content": "API密钥：sk-1234567890abcdef，密码：admin123",
            "description": "检测敏感数据泄露"
        },
        {
            "name": "正常内容",
            "content": "这是一个安全的文本内容，不包含任何威胁。",
            "description": "安全内容测试"
        }
    ]
    
    # 创建输出目录
    output_dir = Path("threat_text_demo")
    output_dir.mkdir(exist_ok=True)
    
    print(f"📁 输出目录: {output_dir.absolute()}")
    print()
    
    # 处理每个测试用例
    all_results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"{'='*20} 测试 {i}: {test_case['name']} {'='*20}")
        print(f"📝 描述: {test_case['description']}")
        print(f"🔍 内容: {test_case['content']}")
        print()
        
        # 检测威胁
        threats = detect_threats(test_case['content'])
        
        # 生成ASCII分析图
        analysis_graph = create_ascii_graph(test_case['content'], threats)
        print(analysis_graph)
        
        # 生成力导向图
        force_diagram = create_force_diagram(threats)
        print(force_diagram)
        
        # 保存结果
        result = {
            'name': test_case['name'],
            'content': test_case['content'],
            'threats': threats,
            'analysis': analysis_graph,
            'diagram': force_diagram
        }
        all_results.append(result)
        
        # 保存到文件
        filename = output_dir / f"test_{i}_{test_case['name'].replace(' ', '_')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"{'='*50}\n")
            f.write(f"测试 {i}: {test_case['name']}\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"内容: {test_case['content']}\n\n")
            f.write(analysis_graph)
            f.write("\n")
            f.write(force_diagram)
        
        print(f"📄 结果已保存: {filename}")
        print()
    
    # 生成汇总报告
    summary = create_summary_report(all_results)
    summary_file = output_dir / "summary_report.txt"
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary)
    
    print(f"📊 汇总报告: {summary_file}")
    print()
    print("✅ 文本版演示完成！")
    print(f"📁 所有文件保存在: {output_dir.absolute()}")
    print()
    print("💡 演示特点:")
    print("• 🔍 检测多种威胁类型")
    print("• 📊 提供风险评估和统计")
    print("• 🎨 ASCII字符版力导向图")
    print("• 💡 详细的处理建议")
    print("• 📄 完整的分析报告")
    
    return output_dir

def create_summary_report(results):
    """创建汇总报告"""
    total_threats = sum(len(r['threats']) for r in results)
    
    threat_types = {}
    risk_levels = {}
    
    for result in results:
        for threat in result['threats']:
            threat_types[threat['type']] = threat_types.get(threat['type'], 0) + 1
            risk_levels[threat['level']] = risk_levels.get(threat['level'], 0) + 1
    
    report = f"""
╔══════════════════════════════════════╗
║        🎨 威胁可视化演示汇总报告        ║
╚══════════════════════════════════════╝

📊 总体统计:
   • 测试用例数: {len(results)}
   • 检测威胁总数: {total_threats}
   • 平均每例威胁数: {total_threats/len(results):.1f}

🎯 威胁类型分布:
"""
    
    for threat_type, count in sorted(threat_types.items()):
        report += f"   • {threat_type}: {count}个\n"
    
    report += "\n⚠️ 风险等级分布:\n"
    for level, count in sorted(risk_levels.items()):
        report += f"   • {level}: {count}个\n"
    
    report += f"""
📈 检测效果:
   • SQL注入检测: {'✅' if 'SQL注入' in threat_types else '❌'}
   • XSS攻击检测: {'✅' if 'XSS攻击' in threat_types else '❌'}
   • 敏感数据检测: {'✅' if '敏感数据' in threat_types else '❌'}
   • 命令注入检测: {'✅' if '命令注入' in threat_types else '❌'}
   • 路径遍历检测: {'✅' if '路径遍历' in threat_types else '❌'}

💡 系统特点:
   • 🔍 智能威胁识别
   • 📊 风险等级评估
   • 🎨 可视化展示
   • 💡 详细处理建议
   • 📄 完整分析报告

⏰ 生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    
    return report

if __name__ == "__main__":
    try:
        output_dir = run_text_demo()
        print(f"\n🎯 演示完成！请查看 {output_dir} 目录中的文件")
        print("📄 打开 summary_report.txt 查看汇总分析")
        print("📄 打开各个 test_*.txt 文件查看详细分析")
    except Exception as e:
        print(f"❌ 演示失败: {e}")
        import traceback
        traceback.print_exc()
