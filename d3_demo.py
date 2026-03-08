#!/usr/bin/env python3
"""
OpenClaw D3.js 威胁力导向图演示脚本
快速展示D3.js交互式威胁可视化效果
"""

import sys
import os
import time
import webbrowser
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

def demo_d3_force_graph():
    """演示D3.js力导向图"""
    print("🎨 OpenClaw D3.js 威胁力导向图演示")
    print("=" * 60)
    
    try:
        from openclaw_security.visualization.d3_force_graph import create_d3_force_graph, save_d3_graph
        
        # 测试用例
        test_cases = [
            {
                "name": "SQL注入攻击",
                "content": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
                "description": "检测SQL注入威胁的交互式可视化"
            },
            {
                "name": "XSS攻击",
                "content": "<script>alert('XSS攻击')</script><img src=x onerror=alert('XSS')>",
                "description": "检测跨站脚本攻击的交互式可视化"
            },
            {
                "name": "复合威胁",
                "content": "用户输入：admin' OR '1'='1'; <script>document.cookie</script> ../../../etc/passwd",
                "description": "检测多种威胁类型的复杂交互式可视化"
            },
            {
                "name": "敏感信息泄露",
                "content": "API密钥：sk-1234567890abcdef，密码：admin123，邮箱：user@domain.com",
                "description": "检测敏感数据泄露的交互式可视化"
            },
            {
                "name": "正常内容",
                "content": "这是一个安全的文本内容，不包含任何威胁模式。",
                "description": "安全内容的交互式可视化展示"
            }
        ]
        
        # 创建输出目录
        output_dir = Path("d3_force_graph_demo")
        output_dir.mkdir(exist_ok=True)
        
        print(f"📁 输出目录: {output_dir.absolute()}")
        print()
        
        # 处理每个测试用例
        generated_files = []
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"--- 测试用例 {i}: {test_case['name']} ---")
            print(f"内容: {test_case['content']}")
            print(f"描述: {test_case['description']}")
            
            # 生成D3.js图表
            start_time = time.time()
            
            # 生成HTML内容
            html_content = create_d3_force_graph(
                test_case['content'], 
                title=f"D3.js {test_case['name']}分析"
            )
            
            # 保存到文件
            filename = output_dir / f"d3_test_{i}_{test_case['name'].replace(' ', '_')}.html"
            save_d3_graph(test_case['content'], str(filename), f"D3.js {test_case['name']}分析")
            
            end_time = time.time()
            
            print(f"⏱️  处理时间: {(end_time - start_time)*1000:.1f}ms")
            print(f"🖼️  HTML文件: {filename}")
            print(f"📏 文件大小: {len(html_content)/1024:.1f}KB")
            
            generated_files.append(filename)
            print()
        
        # 生成HTML预览页面
        html_preview = create_d3_html_preview(test_cases, output_dir)
        preview_file = output_dir / "d3_preview.html"
        
        with open(preview_file, 'w', encoding='utf-8') as f:
            f.write(html_preview)
        
        print(f"🌐 HTML预览页面: {preview_file.absolute()}")
        
        # 自动打开浏览器
        try:
            webbrowser.open(f"file://{preview_file.absolute()}")
            print("🚀 已在浏览器中打开D3.js预览页面")
        except:
            print("⚠️  无法自动打开浏览器，请手动打开HTML文件")
        
        print(f"\n✅ D3.js演示完成！")
        print(f"📁 所有文件保存在: {output_dir.absolute()}")
        print()
        print("🎯 D3.js力导向图特性:")
        print("• 🎨 交互式节点拖拽")
        print("• 🔍 缩放和平移功能")
        print("• 💡 悬停提示信息")
        print("• 🖱️ 节点点击详情")
        print("• ⚡ 动态力导向布局")
        print("• 📱 响应式设计")
        print("• 🖼️ 图片导出功能")
        print("• 🎯 多种威胁类型展示")
        
        return output_dir
        
    except ImportError as e:
        print(f"❌ 导入错误: {e}")
        print("请确保已安装所需依赖:")
        print("pip install flask flask-cors requests")
        return None
    except Exception as e:
        print(f"❌ 演示错误: {e}")
        import traceback
        traceback.print_exc()
        return None

def create_d3_html_preview(test_cases, output_dir):
    """创建D3.js HTML预览页面"""
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw D3.js 威胁力导向图演示</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 3em;
            font-weight: 300;
        }}
        
        .header p {{
            margin: 15px 0 0 0;
            opacity: 0.9;
            font-size: 1.2em;
        }}
        
        .features {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .feature {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        
        .feature:hover {{
            transform: translateY(-5px);
        }}
        
        .feature-icon {{
            font-size: 2.5em;
            margin-bottom: 15px;
        }}
        
        .feature h3 {{
            margin: 0 0 10px 0;
            color: #667eea;
        }}
        
        .demo-section {{
            padding: 40px;
        }}
        
        .demo-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }}
        
        .demo-card {{
            background: #f8f9fa;
            border-radius: 15px;
            padding: 25px;
            border: 2px solid #e9ecef;
            transition: all 0.3s ease;
        }}
        
        .demo-card:hover {{
            border-color: #667eea;
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.15);
        }}
        
        .demo-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }}
        
        .demo-description {{
            color: #666;
            margin-bottom: 15px;
        }}
        
        .demo-content {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.9em;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }}
        
        .demo-link {{
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 12px 24px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: background 0.3s ease;
        }}
        
        .demo-link:hover {{
            background: #5a67d8;
        }}
        
        .instructions {{
            background: #e7f3ff;
            border-left: 4px solid #667eea;
            padding: 25px;
            margin: 40px;
            border-radius: 8px;
        }}
        
        .instructions h3 {{
            margin: 0 0 15px 0;
            color: #667eea;
        }}
        
        .instructions ul {{
            margin: 0;
            padding-left: 20px;
        }}
        
        .instructions li {{
            margin: 10px 0;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e9ecef;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎨 OpenClaw D3.js 威胁力导向图</h1>
            <p>交互式威胁可视化系统 - 实时威胁检测与动态展示</p>
        </div>
        
        <div class="features">
            <div class="feature">
                <div class="feature-icon">🎨</div>
                <h3>交互式可视化</h3>
                <p>基于D3.js的动态力导向图，支持节点拖拽、缩放平移</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔍</div>
                <h3>实时威胁检测</h3>
                <p>智能识别SQL注入、XSS、路径遍历等多种威胁类型</p>
            </div>
            <div class="feature">
                <div class="feature-icon">⚡</div>
                <h3>动态布局</h3>
                <p>力导向算法自动布局，展示威胁之间的关系网络</p>
            </div>
            <div class="feature">
                <div class="feature-icon">💡</div>
                <h3>详细信息</h3>
                <p>悬停显示威胁详情，点击查看完整分析报告</p>
            </div>
        </div>
        
        <div class="demo-section">
            <h2 style="text-align: center; margin-bottom: 10px;">🎯 威胁可视化演示</h2>
            <p style="text-align: center; color: #666; margin-bottom: 30px;">点击下方链接查看不同威胁类型的交互式可视化效果</p>
            
            <div class="demo-grid">
"""
    
    for i, test_case in enumerate(test_cases, 1):
        html += f"""
                <div class="demo-card">
                    <div class="demo-title">🔍 演示 {i}: {test_case['name']}</div>
                    <div class="demo-description">{test_case['description']}</div>
                    <div class="demo-content">{test_case['content'][:50]}{'...' if len(test_case['content']) > 50 else ''}</div>
                    <a href="d3_test_{i}_{test_case['name'].replace(' ', '_')}.html" class="demo-link" target="_blank">
                        查看交互式图表 →
                    </a>
                </div>
"""
    
    html += f"""
            </div>
        </div>
        
        <div class="instructions">
            <h3>🎮 交互操作指南</h3>
            <ul>
                <li><strong>拖拽节点:</strong> 点击并拖动任意节点来重新排列布局</li>
                <li><strong>缩放图表:</strong> 使用鼠标滚轮或双击进行缩放</li>
                <li><strong>平移图表:</strong> 按住鼠标左键拖拽空白区域进行平移</li>
                <li><strong>查看详情:</strong> 悬停在节点上查看威胁详情</li>
                <li><strong>节点信息:</strong> 点击节点查看完整的威胁分析</li>
                <li><strong>重置视图:</strong> 点击"重置缩放"按钮恢复默认视图</li>
                <li><strong>切换标签:</strong> 使用"切换标签"按钮显示/隐藏节点标签</li>
                <li><strong>暂停动画:</strong> 使用"暂停/继续"按钮控制力导向动画</li>
                <li><strong>导出图片:</strong> 点击"导出图片"保存当前视图为PNG图片</li>
            </ul>
        </div>
        
        <div class="footer">
            <h3>🌟 系统特点</h3>
            <p>OpenClaw D3.js威胁可视化系统提供了直观、交互式的威胁分析体验</p>
            <p>通过动态力导向图，用户可以深入理解威胁之间的关系和影响范围</p>
            <p><small>生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}</small></p>
        </div>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    print("🎨 OpenClaw D3.js 威胁力导向图演示")
    print("=" * 60)
    print("📋 演示说明:")
    print("• 生成交互式D3.js力导向图")
    print("• 支持多种威胁类型检测")
    print("• 提供丰富的交互操作")
    print("• 自动在浏览器中打开演示")
    print()
    
    try:
        output_dir = demo_d3_force_graph()
        
        if output_dir:
            print(f"\n🎯 演示完成！")
            print(f"📁 演示文件保存在: {output_dir}")
            print(f"🌐 请在浏览器中查看交互式图表效果")
            print()
            print("💡 提示:")
            print("• 每个图表都是独立的HTML文件")
            print("• 可以直接在浏览器中打开查看")
            print("• 支持所有现代浏览器（Chrome、Firefox、Safari、Edge）")
            print("• 图表具有完整的交互功能")
            
    except KeyboardInterrupt:
        print("\n⏹️  演示被中断")
    except Exception as e:
        print(f"❌ 演示失败: {e}")
        print("\n💡 故障排除:")
        print("• 确保Python环境正确")
        print("• 检查项目依赖是否完整")
        print("• 确认输出目录有写入权限")
