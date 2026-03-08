#!/usr/bin/env python3
"""
OpenClaw 威胁可视化演示脚本
快速展示威胁力导向图效果
"""

import sys
import os
import time
import webbrowser
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

def demo_standalone_visualization():
    """独立演示威胁可视化（不依赖服务器）"""
    print("🎨 OpenClaw 威胁可视化演示")
    print("=" * 50)
    
    try:
        from openclaw_security.visualization.threat_graph import create_threat_visualization
        
        # 测试用例
        test_cases = [
            {
                "name": "SQL注入攻击",
                "content": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
                "description": "检测到SQL注入威胁，包含删除表操作"
            },
            {
                "name": "XSS攻击",
                "content": "<script>alert('XSS攻击')</script><img src=x onerror=alert('XSS')>",
                "description": "检测到跨站脚本攻击威胁"
            },
            {
                "name": "复合威胁",
                "content": "用户输入：admin' OR '1'='1'; <script>document.cookie</script> ../../../etc/passwd",
                "description": "检测到多种类型威胁"
            },
            {
                "name": "敏感信息泄露",
                "content": "API密钥：sk-1234567890abcdef，密码：admin123，邮箱：user@domain.com",
                "description": "检测到敏感数据泄露威胁"
            },
            {
                "name": "正常内容",
                "content": "这是一个安全的文本内容，不包含任何威胁模式。",
                "description": "安全内容，无威胁检测"
            }
        ]
        
        # 创建输出目录
        output_dir = Path("threat_visualization_demo")
        output_dir.mkdir(exist_ok=True)
        
        print(f"📁 输出目录: {output_dir.absolute()}")
        print()
        
        # 处理每个测试用例
        for i, test_case in enumerate(test_cases, 1):
            print(f"--- 测试用例 {i}: {test_case['name']} ---")
            print(f"内容: {test_case['content']}")
            print(f"描述: {test_case['description']}")
            
            # 生成威胁可视化
            start_time = time.time()
            result = create_threat_visualization(test_case['content'])
            end_time = time.time()
            
            # 显示分析结果
            analysis = result['summary']
            print(f"⏱️  处理时间: {(end_time - start_time)*1000:.1f}ms")
            print(f"🔍 威胁数量: {analysis['total_threats']}")
            print(f"📊 风险等级: {analysis['risk_level']}")
            print(f"⚠️  风险评分: {analysis['risk_score']}")
            
            if analysis['threat_breakdown']['by_level']:
                print("📈 威胁分布:")
                for level, count in analysis['threat_breakdown']['by_level'].items():
                    print(f"  - {level.upper()}: {count}")
            
            if analysis['threat_breakdown']['by_type']:
                print("🎯 威胁类型:")
                for threat_type, count in analysis['threat_breakdown']['by_type'].items():
                    print(f"  - {threat_type}: {count}")
            
            # 显示建议
            print("💡 安全建议:")
            for rec in analysis['recommendations']:
                print(f"  - {rec}")
            
            # 保存图片
            import base64
            image_data = base64.b64decode(result['image'])
            filename = output_dir / f"test_{i}_{test_case['name'].replace(' ', '_')}.png"
            
            with open(filename, 'wb') as f:
                f.write(image_data)
            
            print(f"🖼️  图片已保存: {filename}")
            print(f"📏 图片大小: {len(image_data)/1024:.1f}KB")
            print()
        
        # 生成HTML预览页面
        html_content = create_html_preview(test_cases, output_dir)
        html_file = output_dir / "preview.html"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"🌐 HTML预览页面: {html_file.absolute()}")
        
        # 自动打开浏览器
        try:
            webbrowser.open(f"file://{html_file.absolute()}")
            print("🚀 已在浏览器中打开预览页面")
        except:
            print("⚠️  无法自动打开浏览器，请手动打开HTML文件")
        
        print("\n✅ 演示完成！")
        print(f"📁 所有文件保存在: {output_dir.absolute()}")
        
        return output_dir
        
    except ImportError as e:
        print(f"❌ 导入错误: {e}")
        print("请确保已安装所需依赖:")
        print("pip install matplotlib networkx numpy")
        return None
    except Exception as e:
        print(f"❌ 演示错误: {e}")
        return None

def create_html_preview(test_cases, output_dir):
    """创建HTML预览页面"""
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw 威胁可视化演示</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .test-case {{
            margin-bottom: 30px;
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        .test-title {{
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        .content {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            margin: 10px 0;
            word-break: break-all;
        }}
        .image-container {{
            text-align: center;
            margin: 20px 0;
        }}
        .threat-image {{
            max-width: 100%;
            height: auto;
            border: 2px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }}
        .stat-item {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .risk-high {{ color: #dc3545; }}
        .risk-medium {{ color: #fd7e14; }}
        .risk-low {{ color: #28a745; }}
        .risk-critical {{ color: #6f42c1; }}
        .recommendations {{
            background: #e7f3ff;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎨 OpenClaw 威胁可视化演示</h1>
        <p>数据安全分级防护系统 - 威胁力导向图展示</p>
    </div>
"""
    
    for i, test_case in enumerate(test_cases, 1):
        # 读取分析结果
        try:
            from openclaw_security.visualization.threat_graph import create_threat_visualization
            result = create_threat_visualization(test_case['content'])
            analysis = result['summary']
            
            # 确定风险等级样式
            risk_class = f"risk-{analysis['risk_level'].lower()}"
            
            html += f"""
    <div class="test-case">
        <h2 class="test-title">🔍 测试用例 {i}: {test_case['name']}</h2>
        <p><strong>描述:</strong> {test_case['description']}</p>
        
        <div class="content">
            <strong>测试内容:</strong><br>
            {test_case['content']}
        </div>
        
        <div class="stats">
            <div class="stat-item">
                <div class="stat-value">{analysis['total_threats']}</div>
                <div>威胁数量</div>
            </div>
            <div class="stat-item">
                <div class="stat-value {risk_class}">{analysis['risk_level']}</div>
                <div>风险等级</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{analysis['risk_score']}</div>
                <div>风险评分</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{result['graph_data']['nodes']}</div>
                <div>图节点</div>
            </div>
        </div>
        
        <div class="image-container">
            <img src="test_{i}_{test_case['name'].replace(' ', '_')}.png" 
                 alt="威胁可视化图" class="threat-image">
        </div>
        
        <div class="recommendations">
            <strong>💡 安全建议:</strong><br>
            {'<br>'.join(f"• {rec}" for rec in analysis['recommendations'])}
        </div>
    </div>
"""
        except Exception as e:
            html += f"""
    <div class="test-case">
        <h2 class="test-title">❌ 测试用例 {i}: {test_case['name']}</h2>
        <p>处理错误: {e}</p>
    </div>
"""
    
    html += """
    <div style="text-align: center; margin-top: 40px; padding: 20px; background: white; border-radius: 10px;">
        <h3>🎯 演示说明</h3>
        <p>以上展示了OpenClaw威胁可视化系统的效果：</p>
        <ul style="text-align: left; max-width: 600px; margin: 0 auto;">
            <li>🔍 自动检测多种威胁类型</li>
            <li>📊 生成力导向图可视化</li>
            <li>⚠️ 提供风险评估和建议</li>
            <li>🎨 不同威胁等级用颜色区分</li>
            <li>🔗 威胁之间的关系用边连接</li>
        </ul>
        <p style="margin-top: 20px; color: #666;">
            <small>生成时间: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</small>
        </p>
    </div>
</body>
</html>
"""
    return html

def demo_server_mode():
    """演示服务器模式"""
    print("🌐 服务器模式演示")
    print("=" * 30)
    
    try:
        from openclaw_security.client.visualization_client import ThreatVisualizationClient
        
        # 检查服务器是否运行
        client = ThreatVisualizationClient("http://localhost:5001")
        
        try:
            health = client.health_check()
            print("✅ 可视化服务器运行正常")
            print(f"服务状态: {health['status']}")
            print(f"功能特性: {health['features']}")
            
            # 获取演示数据
            print("\n🎨 获取演示示例...")
            demo_result = client.get_demo()
            
            print(f"演示标题: {demo_result['title']}")
            print(f"演示数量: {len(demo_result['results'])}")
            
            # 显示每个演示
            for i, demo in enumerate(demo_result['results'], 1):
                print(f"\n--- 演示 {i} ---")
                print(f"内容: {demo['content']}")
                
                if 'error' not in demo:
                    analysis = demo['threat_analysis']
                    print(f"威胁数量: {analysis['total_threats']}")
                    print(f"风险等级: {analysis['risk_level']}")
                    
                    # 保存图片
                    if demo['visualization']['image']:
                        filename = f"server_demo_{i}.png"
                        client.save_image(demo['visualization']['image'], filename)
                        print(f"图片已保存: {filename}")
                else:
                    print(f"错误: {demo['error']}")
            
            print("\n✅ 服务器模式演示完成！")
            
        except Exception as e:
            print(f"❌ 服务器连接失败: {e}")
            print("\n🚀 请先启动可视化服务器:")
            print("python -m openclaw_security.api.visualization_server")
            
    except ImportError as e:
        print(f"❌ 导入错误: {e}")

if __name__ == "__main__":
    print("🎨 OpenClaw 威胁可视化效果演示")
    print("=" * 50)
    print("请选择演示模式:")
    print("1. 独立演示 (不需要服务器)")
    print("2. 服务器演示 (需要先启动服务器)")
    print()
    
    choice = input("请输入选择 (1/2): ").strip()
    
    if choice == "1":
        print("\n🚀 启动独立演示...")
        output_dir = demo_standalone_visualization()
        
        if output_dir:
            print(f"\n📁 演示文件保存在: {output_dir}")
            print("🌐 请查看生成的HTML文件和PNG图片")
            
    elif choice == "2":
        print("\n🌐 启动服务器演示...")
        demo_server_mode()
        
    else:
        print("❌ 无效选择")
    
    print("\n💡 提示:")
    print("- 独立演示会生成本地图片和HTML预览")
    print("- 服务器演示需要先启动可视化服务器")
    print("- 建议先尝试独立演示查看效果")
