#!/usr/bin/env python3
"""
简单的威胁可视化演示
直接运行查看效果
"""

import sys
import os
import re
import base64
import io
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from pathlib import Path
import webbrowser
from datetime import datetime

def create_simple_threat_graph(content, title="威胁分析图"):
    """创建简单的威胁图"""
    # 创建图形
    plt.figure(figsize=(12, 8), dpi=100)
    ax = plt.gca()
    
    # 检测威胁
    threats = detect_threats(content)
    
    if not threats:
        # 无威胁的情况
        ax.text(0.5, 0.5, '✅ 未检测到威胁\n\n内容安全', 
               horizontalalignment='center', verticalalignment='center',
               fontsize=20, color='green', transform=ax.transAxes,
               bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgreen", alpha=0.8))
    else:
        # 创建威胁图
        G = nx.Graph()
        
        # 添加节点
        threat_colors = {
            'sql_injection': '#F44336',
            'xss': '#FF9800', 
            'path_traversal': '#2196F3',
            'command_injection': '#9C27B0',
            'sensitive_data': '#4CAF50'
        }
        
        threat_icons = {
            'sql_injection': '🗃️',
            'xss': '🌐',
            'path_traversal': '📁', 
            'command_injection': '⚡',
            'sensitive_data': '🔑'
        }
        
        # 添加威胁节点
        for i, threat in enumerate(threats):
            node_id = f"threat_{i}"
            G.add_node(node_id, 
                       threat_type=threat['type'],
                       content=threat['content'][:30] + '...' if len(threat['content']) > 30 else threat['content'],
                       level=threat['level'])
        
        # 添加内容节点
        G.add_node('content', content=content[:50] + '...' if len(content) > 50 else content, 
                  type='content')
        
        # 连接威胁到内容
        for i in range(len(threats)):
            G.add_edge(f"threat_{i}", 'content')
        
        # 创建布局
        pos = nx.spring_layout(G, k=3, iterations=50, seed=42)
        
        # 绘制边
        nx.draw_networkx_edges(G, pos, ax=ax, alpha=0.3, edge_color='gray')
        
        # 绘制节点
        for node in G.nodes():
            node_pos = pos[node]
            
            if node == 'content':
                # 内容节点
                color = '#E3F2FD'
                size = 2000
                ax.scatter(node_pos[0], node_pos[1], s=size, c=color, 
                          edgecolors='blue', linewidth=2, zorder=2)
                ax.text(node_pos[0], node_pos[1], '📄', fontsize=16, 
                       ha='center', va='center', zorder=3)
            else:
                # 威胁节点
                threat_data = G.nodes[node]
                threat_type = threat_data['threat_type']
                color = threat_colors.get(threat_type, '#9E9E9E')
                icon = threat_icons.get(threat_type, '⚠️')
                
                # 根据威胁等级调整大小
                level_sizes = {'low': 800, 'medium': 1200, 'high': 1800, 'critical': 2500}
                size = level_sizes.get(threat_data['level'], 1000)
                
                ax.scatter(node_pos[0], node_pos[1], s=size, c=color, 
                          alpha=0.8, edgecolors='black', linewidth=1, zorder=2)
                ax.text(node_pos[0], node_pos[1], icon, fontsize=14, 
                       ha='center', va='center', zorder=3)
        
        # 添加标签
        labels = {}
        for node in G.nodes():
            if node != 'content':
                threat_data = G.nodes[node]
                labels[node] = threat_data['threat_type'].replace('_', '\n')
        
        nx.draw_networkx_labels(G, pos, labels, ax=ax, font_size=8, font_weight='bold')
        
        # 添加标题
        ax.set_title(f"🔍 {title}\n检测到 {len(threats)} 个威胁", 
                    fontsize=16, fontweight='bold', pad=20)
        
        # 添加统计信息
        threat_levels = {}
        for threat in threats:
            level = threat['level']
            threat_levels[level] = threat_levels.get(level, 0) + 1
        
        stats_text = f"威胁分布: "
        for level, count in threat_levels.items():
            stats_text += f"{level.upper()}: {count} "
        
        ax.text(0.5, -0.15, stats_text, transform=ax.transAxes,
               ha='center', va='top', fontsize=10,
               bbox=dict(boxstyle="round,pad=0.3", facecolor="lightyellow", alpha=0.8))
    
    # 设置图形属性
    ax.set_xlim(-1.5, 1.5)
    ax.set_ylim(-1.5, 1.5)
    ax.axis('off')
    ax.set_facecolor('#f8f9fa')
    
    # 保存图片
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', pad_inches=0.2, 
               facecolor='#f8f9fa', dpi=100)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.getvalue()).decode()
    plt.close()
    
    return image_base64, threats

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
                'type': 'sql_injection',
                'level': 'high',
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
                'type': 'xss',
                'level': 'medium',
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
                'type': 'path_traversal',
                'level': 'medium',
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
                'type': 'command_injection',
                'level': 'high',
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
                'type': 'sensitive_data',
                'level': 'critical',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}"
            })
    
    return threats

def run_demo():
    """运行演示"""
    print("🎨 OpenClaw 威胁可视化演示")
    print("=" * 50)
    
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
    output_dir = Path("threat_demo_output")
    output_dir.mkdir(exist_ok=True)
    
    print(f"📁 输出目录: {output_dir.absolute()}")
    print()
    
    # 处理每个测试用例
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"--- 测试 {i}: {test_case['name']} ---")
        print(f"内容: {test_case['content']}")
        
        # 生成威胁图
        image_base64, threats = create_simple_threat_graph(test_case['content'], test_case['name'])
        
        # 显示检测结果
        print(f"检测到 {len(threats)} 个威胁")
        
        if threats:
            print("威胁详情:")
            for j, threat in enumerate(threats, 1):
                print(f"  {j}. {threat['type']} ({threat['level']}): {threat['content']}")
        else:
            print("✅ 无威胁检测")
        
        # 保存图片
        image_data = base64.b64decode(image_base64)
        filename = output_dir / f"test_{i}_{test_case['name'].replace(' ', '_')}.png"
        
        with open(filename, 'wb') as f:
            f.write(image_data)
        
        print(f"🖼️  图片已保存: {filename}")
        print(f"📏 图片大小: {len(image_data)/1024:.1f}KB")
        print()
        
        results.append({
            'name': test_case['name'],
            'content': test_case['content'],
            'description': test_case['description'],
            'threats': threats,
            'image_file': filename,
            'image_base64': image_base64
        })
    
    # 生成HTML预览
    html_content = create_html_demo(results)
    html_file = output_dir / "demo.html"
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"🌐 HTML预览: {html_file.absolute()}")
    
    # 自动打开浏览器
    try:
        webbrowser.open(f"file://{html_file.absolute()}")
        print("🚀 已在浏览器中打开演示页面")
    except:
        print("⚠️  无法自动打开浏览器，请手动打开HTML文件")
    
    print(f"\n✅ 演示完成！")
    print(f"📁 所有文件保存在: {output_dir.absolute()}")
    
    return output_dir

def create_html_demo(results):
    """创建HTML演示页面"""
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw 威胁可视化演示</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }}
        .header {{
            text-align: center;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .demo-item {{
            background: white;
            margin: 20px 0;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .demo-title {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        .content-box {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            margin: 15px 0;
            border-left: 4px solid #007bff;
        }}
        .threat-info {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
        }}
        .threat-item {{
            margin: 8px 0;
            padding: 8px;
            background: white;
            border-radius: 5px;
        }}
        .threat-type {{
            font-weight: bold;
            color: #dc3545;
        }}
        .threat-level {{
            float: right;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            color: white;
        }}
        .level-critical {{ background: #dc3545; }}
        .level-high {{ background: #fd7e14; }}
        .level-medium {{ background: #ffc107; color: #333; }}
        .level-low {{ background: #28a745; }}
        .image-container {{
            text-align: center;
            margin: 20px 0;
        }}
        .threat-image {{
            max-width: 100%;
            height: auto;
            border: 2px solid #ddd;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .no-threat {{
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background: white;
            border-radius: 15px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎨 OpenClaw 威胁可视化演示</h1>
        <p>数据安全分级防护系统 - 威胁力导向图展示</p>
        <p><small>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small></p>
    </div>
"""
    
    for i, result in enumerate(results, 1):
        html += f"""
    <div class="demo-item">
        <h2 class="demo-title">🔍 测试 {i}: {result['name']}</h2>
        <p><strong>描述:</strong> {result['description']}</p>
        
        <div class="content-box">
            <strong>测试内容:</strong><br>
            {result['content']}
        </div>
        
        <div class="threat-info">
            <strong>🔍 威胁检测结果:</strong>
"""
        
        if result['threats']:
            for threat in result['threats']:
                level_class = f"level-{threat['level']}"
                html += f"""
            <div class="threat-item">
                <span class="threat-type">{threat['type']}</span>
                <span class="threat-level {level_class}">{threat['level'].upper()}</span>
                <div>{threat['content']}</div>
            </div>
"""
        else:
            html += """
            <div class="no-threat">
                ✅ 未检测到威胁 - 内容安全
            </div>
"""
        
        html += f"""
        </div>
        
        <div class="image-container">
            <img src="test_{i}_{result['name'].replace(' ', '_')}.png" 
                 alt="威胁可视化图" class="threat-image">
        </div>
    </div>
"""
    
    html += """
    <div class="footer">
        <h3>🎯 演示说明</h3>
        <p>本演示展示了OpenClaw威胁可视化系统的核心功能：</p>
        <ul style="text-align: left; max-width: 600px; margin: 0 auto;">
            <li>🔍 自动检测多种威胁类型（SQL注入、XSS、路径遍历、命令注入、敏感数据）</li>
            <li>📊 生成直观的力导向图可视化</li>
            <li>⚠️ 提供威胁等级评估和风险分析</li>
            <li>🎨 不同威胁类型用不同颜色和图标区分</li>
            <li>🔗 展示威胁与内容之间的关系</li>
        </ul>
        <p style="margin-top: 20px;">
            <strong>特点:</strong> 不拦截输出，仅提供可视化威胁提示，帮助用户理解安全风险
        </p>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    try:
        output_dir = run_demo()
        print(f"\n🎯 演示完成！请查看 {output_dir} 目录中的文件")
        print("🌐 打开 demo.html 文件查看完整的可视化效果")
    except Exception as e:
        print(f"❌ 演示失败: {e}")
        print("\n💡 请确保已安装所需依赖:")
        print("pip install matplotlib networkx numpy")
