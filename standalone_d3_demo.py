#!/usr/bin/env python3
"""
独立的OpenClaw D3.js 威胁力导向图演示
不依赖项目模块，直接生成D3.js交互式图表
"""

import re
import json
from datetime import datetime
from pathlib import Path
import webbrowser

class ThreatLevel:
    """威胁等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType:
    """威胁类型"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SENSITIVE_DATA = "sensitive_data"

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
    
    for i, pattern in enumerate(sql_patterns):
        matches = re.finditer(pattern, content)
        for match in matches:
            threats.append({
                'type': ThreatType.SQL_INJECTION,
                'level': ThreatLevel.HIGH,
                'icon': '🗃️',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.8,
                'description': "SQL注入攻击：可能尝试访问或修改数据库"
            })
    
    # XSS模式
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:\s*\w+',
        r'on\w+\s*=\s*["\'][^"\']*["\']',
        r'<iframe[^>]*>.*?</iframe>'
    ]
    
    for i, pattern in enumerate(xss_patterns):
        matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            threats.append({
                'type': ThreatType.XSS,
                'level': ThreatLevel.MEDIUM,
                'icon': '🌐',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.7,
                'description': "跨站脚本攻击：可能执行恶意JavaScript代码"
            })
    
    # 路径遍历模式
    path_patterns = [
        r'\.\./|\.\.\\',
        r'/etc/passwd',
        r'/proc/version',
        r'windows/system32'
    ]
    
    for i, pattern in enumerate(path_patterns):
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            threats.append({
                'type': ThreatType.PATH_TRAVERSAL,
                'level': ThreatLevel.MEDIUM,
                'icon': '📁',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.6,
                'description': "路径遍历攻击：可能访问系统敏感文件"
            })
    
    # 命令注入模式
    cmd_patterns = [
        r'[;&|`$(){}\[\]]',
        r'eval\s*\(',
        r'system\s*\(',
        r'exec\s*\('
    ]
    
    for i, pattern in enumerate(cmd_patterns):
        matches = re.finditer(pattern, content)
        for match in matches:
            threats.append({
                'type': ThreatType.COMMAND_INJECTION,
                'level': ThreatLevel.HIGH,
                'icon': '⚡',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.75,
                'description': "命令注入攻击：可能执行系统命令"
            })
    
    # 敏感数据模式
    sensitive_patterns = [
        r'(?i)(api[_-]?key|secret[_-]?key|password|token|private[_-]?key)\s*[:=]\s*[^\s]{8,}',
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ]
    
    for i, pattern in enumerate(sensitive_patterns):
        matches = re.finditer(pattern, content)
        for match in matches:
            threats.append({
                'type': ThreatType.SENSITIVE_DATA,
                'level': ThreatLevel.CRITICAL,
                'icon': '🔑',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.9,
                'description': "敏感数据泄露：包含可能的敏感信息"
            })
    
    return threats

def create_d3_data(content):
    """创建D3.js格式的数据"""
    threats = detect_threats(content)
    
    # 颜色配置
    level_colors = {
        ThreatLevel.LOW: "#4CAF50",
        ThreatLevel.MEDIUM: "#FF9800",
        ThreatLevel.HIGH: "#F44336",
        ThreatLevel.CRITICAL: "#9C27B0"
    }
    
    # 创建节点和边
    nodes = []
    links = []
    
    # 添加内容节点
    content_node = {
        "id": "content",
        "name": "原始内容",
        "type": "content",
        "content": content[:100] + "..." if len(content) > 100 else content,
        "level": "safe",
        "color": "#E3F2FD",
        "icon": "📄",
        "description": "原始输入内容",
        "size": 30
    }
    nodes.append(content_node)
    
    # 添加威胁节点
    for i, threat in enumerate(threats):
        d3_node = {
            "id": f"threat_{i}",
            "name": threat['type'].replace('_', ' ').title(),
            "type": threat['type'],
            "content": threat['content'],
            "level": threat['level'],
            "color": level_colors[threat['level']],
            "icon": threat['icon'],
            "description": threat['description'],
            "confidence": threat['confidence'],
            "position": threat['position'],
            "size": 20 + threat['confidence'] * 20
        }
        nodes.append(d3_node)
        
        # 连接威胁到内容
        links.append({
            "source": "content",
            "target": f"threat_{i}",
            "relationship": "contains",
            "strength": 0.8,
            "value": 8
        })
    
    # 计算统计信息
    total_threats = len(threats)
    risk_score = 0
    risk_weights = {
        ThreatLevel.LOW: 1,
        ThreatLevel.MEDIUM: 5,
        ThreatLevel.HIGH: 10,
        ThreatLevel.CRITICAL: 20
    }
    
    for threat in threats:
        risk_score += risk_weights[threat['level']] * threat['confidence']
    
    if risk_score >= 50:
        risk_level = "CRITICAL"
    elif risk_score >= 20:
        risk_level = "HIGH"
    elif risk_score >= 10:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    # 生成建议
    recommendations = []
    if risk_level == "CRITICAL":
        recommendations.append("🚨 检测到关键威胁，建议立即审查内容")
    elif risk_level == "HIGH":
        recommendations.append("⚠️ 检测到高风险威胁，需要关注")
    elif risk_level == "MEDIUM":
        recommendations.append("⚡ 检测到中等风险威胁")
    else:
        recommendations.append("✅ 内容相对安全")
    
    return {
        "nodes": nodes,
        "links": links,
        "statistics": {
            "total_threats": total_threats,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendations": recommendations
        }
    }

def create_d3_html(content, title="威胁力导向图"):
    """创建D3.js HTML文件"""
    data = create_d3_data(content)
    
    html_template = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            overflow-x: hidden;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
            box-shadow: 0 0 50px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
            position: relative;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .stats-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: #667eea;
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            font-weight: 500;
        }}
        
        .risk-critical {{ color: #9C27B0; }}
        .risk-high {{ color: #F44336; }}
        .risk-medium {{ color: #FF9800; }}
        .risk-low {{ color: #4CAF50; }}
        .risk-safe {{ color: #2196F3; }}
        
        .graph-container {{
            height: 600px;
            margin: 0 30px 30px 30px;
            border-radius: 15px;
            background: #fafafa;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.1);
            position: relative;
            overflow: hidden;
        }}
        
        .graph-container svg {{
            width: 100%;
            height: 100%;
        }}
        
        .node {{
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .node circle {{
            stroke: #fff;
            stroke-width: 3px;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2));
            transition: all 0.3s ease;
        }}
        
        .node:hover circle {{
            stroke-width: 5px;
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.3));
        }}
        
        .node text {{
            font-size: 14px;
            pointer-events: none;
            text-anchor: middle;
            fill: #333;
            font-weight: 500;
        }}
        
        .link {{
            fill: none;
            stroke-opacity: 0.6;
            transition: all 0.3s ease;
        }}
        
        .tooltip {{
            position: absolute;
            padding: 20px;
            background: rgba(0, 0, 0, 0.95);
            color: white;
            border-radius: 12px;
            font-size: 14px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s ease;
            max-width: 350px;
            z-index: 1000;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
        }}
        
        .controls {{
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
            justify-content: center;
        }}
        
        .btn {{
            padding: 12px 24px;
            border: none;
            border-radius: 25px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }}
        
        .btn:active {{
            transform: translateY(0);
        }}
        
        .recommendations {{
            padding: 30px;
            background: linear-gradient(135deg, #e7f3ff, #f0f8ff);
            border-left: 4px solid #667eea;
        }}
        
        .recommendations h3 {{
            margin: 0 0 20px 0;
            color: #667eea;
            font-size: 1.3em;
        }}
        
        .recommendations ul {{
            margin: 0;
            padding-left: 20px;
        }}
        
        .recommendations li {{
            margin: 12px 0;
            font-size: 1.05em;
            line-height: 1.5;
        }}
        
        .legend {{
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .legend h3 {{
            margin: 0 0 20px 0;
            color: #333;
            font-size: 1.3em;
        }}
        
        .legend-items {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            justify-content: center;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            background: white;
            padding: 10px 15px;
            border-radius: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .legend-color {{
            width: 24px;
            height: 24px;
            border-radius: 50%;
            border: 3px solid #fff;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }}
        
        .footer {{
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
        }}
        
        .footer p {{
            margin: 5px 0;
            opacity: 0.9;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2em;
            }}
            
            .stats-container {{
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
                padding: 20px;
            }}
            
            .graph-container {{
                height: 400px;
                margin: 0 20px 20px 20px;
            }}
            
            .controls {{
                padding: 15px 20px;
            }}
            
            .btn {{
                padding: 10px 20px;
                font-size: 13px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎨 {title}</h1>
            <p>OpenClaw 威胁可视化系统 - 交互式力导向图</p>
        </div>
        
        <div class="stats-container">
            <div class="stat-card">
                <div class="stat-value" id="total-threats">{data['statistics']['total_threats']}</div>
                <div class="stat-label">威胁数量</div>
            </div>
            <div class="stat-card">
                <div class="stat-value risk-{{data['statistics']['risk_level'].lower()}}" id="risk-level">{data['statistics']['risk_level']}</div>
                <div class="stat-label">风险等级</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="risk-score">{data['statistics']['risk_score']}</div>
                <div class="stat-label">风险评分</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="node-count">{len(data['nodes'])}</div>
                <div class="stat-label">图节点</div>
            </div>
        </div>
        
        <div class="graph-container" id="graph"></div>
        
        <div class="controls">
            <button class="btn" onclick="resetZoom()">🔄 重置缩放</button>
            <button class="btn" onclick="toggleLabels()">🏷️ 切换标签</button>
            <button class="btn" onclick="toggleForce()">⏸️ 暂停/继续</button>
            <button class="btn" onclick="exportImage()">📸 导出图片</button>
        </div>
        
        <div class="recommendations">
            <h3>💡 安全建议</h3>
            <ul>
                {''.join(f'<li>{rec}</li>' for rec in data['statistics']['recommendations'])}
            </ul>
        </div>
        
        <div class="legend">
            <h3>🎨 图例说明</h3>
            <div class="legend-items">
                <div class="legend-item">
                    <div class="legend-color" style="background: #E3F2FD;"></div>
                    <span>原始内容</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #4CAF50;"></div>
                    <span>低风险</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #FF9800;"></div>
                    <span>中风险</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #F44336;"></div>
                    <span>高风险</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #9C27B0;"></div>
                    <span>关键风险</span>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>🎯 交互操作指南</strong></p>
            <p>🖱️ 拖拽节点 | 🔍 滚轮缩放 | 💡 悬停查看详情 | 🖱️ 点击节点信息</p>
            <p><small>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small></p>
        </div>
    </div>
    
    <div class="tooltip" id="tooltip"></div>
    
    <script>
        // 数据
        const data = {json.dumps(data, indent=2)};
        
        // 设置SVG尺寸
        const container = document.getElementById('graph');
        const width = container.clientWidth;
        const height = 600;
        
        // 创建SVG
        const svg = d3.select("#graph")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
        
        // 创建缩放行为
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => {{
                containerGroup.attr("transform", event.transform);
            }});
        
        svg.call(zoom);
        
        // 创建容器
        const containerGroup = svg.append("g");
        
        // 创建力导向图
        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links)
                .id(d => d.id)
                .distance(120)
                .strength(d => d.strength))
            .force("charge", d3.forceManyBody().strength(-400))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => d.size + 8));
        
        // 创建边
        const link = containerGroup.append("g")
            .selectAll("line")
            .data(data.links)
            .enter().append("line")
            .attr("class", "link")
            .attr("stroke", "#999")
            .attr("stroke-width", d => Math.sqrt(d.value) * 2)
            .attr("stroke-opacity", d => d.strength);
        
        // 创建节点
        const node = containerGroup.append("g")
            .selectAll("g")
            .data(data.nodes)
            .enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // 添加圆形
        node.append("circle")
            .attr("r", d => d.size)
            .attr("fill", d => d.color)
            .on("mouseover", showTooltip)
            .on("mouseout", hideTooltip)
            .on("click", nodeClick);
        
        // 添加图标
        node.append("text")
            .attr("dy", ".35em")
            .style("font-size", d => d.size * 0.6 + "px")
            .style("pointer-events", "none")
            .text(d => d.icon);
        
        // 添加标签
        const labels = node.append("text")
            .attr("dy", d => d.size + 20)
            .style("font-size", "12px")
            .style("text-anchor", "middle")
            .style("fill", "#333")
            .style("font-weight", "500")
            .style("pointer-events", "none")
            .text(d => d.name);
        
        // 更新位置
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        // 拖拽函数
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        // 工具提示
        const tooltip = document.getElementById("tooltip");
        
        function showTooltip(event, d) {{
            const confidenceText = d.confidence ? `置信度: ${{(d.confidence * 100).toFixed(1)}}%` : '';
            const positionText = d.position ? `位置: ${{d.position}}` : '';
            
            tooltip.innerHTML = `
                <strong>${{d.name}}</strong><br>
                类型: ${{d.type}}<br>
                等级: ${{d.level}}<br>
                ${{confidenceText}}<br>
                ${{positionText}}<br><br>
                ${{d.description}}
                ${{d.content ? '<br><br><strong>内容:</strong> ' + d.content.substring(0, 60) + (d.content.length > 60 ? '...' : '') : ''}}
            `;
            tooltip.style.left = event.pageX + 15 + "px";
            tooltip.style.top = event.pageY - 10 + "px";
            tooltip.style.opacity = 1;
        }}
        
        function hideTooltip() {{
            tooltip.style.opacity = 0;
        }}
        
        // 节点点击
        function nodeClick(event, d) {{
            if (d.type === "content") {{
                alert("📄 原始内容:\\n\\n" + d.content);
            }} else {{
                alert(`🔍 威胁详情:\\n\\n类型: ${{d.name}}\\n等级: ${{d.level.toUpperCase()}}\\n置信度: ${{(d.confidence * 100).toFixed(1)}}%\\n\\n威胁内容: ${{d.content}}\\n\\n描述: ${{d.description}}`);
            }}
        }}
        
        // 控制函数
        function resetZoom() {{
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity.translate(0, 0).scale(1)
            );
        }}
        
        let labelsVisible = true;
        function toggleLabels() {{
            labelsVisible = !labelsVisible;
            labels.style("display", labelsVisible ? "block" : "none");
        }}
        
        let forceRunning = true;
        function toggleForce() {{
            if (forceRunning) {{
                simulation.stop();
                document.querySelector('.btn:nth-child(3)').innerHTML = '▶️ 继续动画';
            }} else {{
                simulation.restart();
                document.querySelector('.btn:nth-child(3)').innerHTML = '⏸️ 暂停动画';
            }}
            forceRunning = !forceRunning;
        }}
        
        function exportImage() {{
            alert("📸 图片导出功能\\n\\n由于浏览器安全限制，您可以使用以下方法保存图表：\\n\\n1. Windows: Win + Shift + S (截图工具)\\n2. Mac: Cmd + Shift + 4 (截图)\\n3. 浏览器: F12 → 截图功能\\n\\n建议在图表布局稳定后截图以获得最佳效果。");
        }}
        
        // 响应式调整
        window.addEventListener("resize", () => {{
            const newWidth = container.clientWidth;
            svg.attr("width", newWidth);
            simulation.force("center", d3.forceCenter(newWidth / 2, height / 2));
            simulation.alpha(0.3).restart();
        }});
        
        // 添加初始动画效果
        setTimeout(() => {{
            simulation.alpha(0.3).restart();
        }}, 1000);
    </script>
</body>
</html>
"""
    
    return html_template

def run_standalone_d3_demo():
    """运行独立D3.js演示"""
    print("🎨 OpenClaw D3.js 威胁力导向图演示 (独立版)")
    print("=" * 70)
    
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
            "name": "敏感信息",
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
    output_dir = Path("d3_standalone_demo")
    output_dir.mkdir(exist_ok=True)
    
    print(f"📁 输出目录: {output_dir.absolute()}")
    print()
    
    # 处理每个测试用例
    generated_files = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"--- 生成测试 {i}: {test_case['name']} ---")
        print(f"内容: {test_case['content']}")
        print(f"描述: {test_case['description']}")
        
        # 生成D3.js HTML
        html_content = create_d3_html(test_case['content'], f"D3.js {test_case['name']}分析")
        
        # 保存文件
        filename = output_dir / f"d3_demo_{i}_{test_case['name'].replace(' ', '_')}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ 已保存: {filename}")
        print(f"📏 文件大小: {len(html_content)/1024:.1f}KB")
        
        generated_files.append(filename)
        print()
    
    # 生成预览页面
    preview_html = create_preview_page(test_cases, output_dir)
    preview_file = output_dir / "index.html"
    
    with open(preview_file, 'w', encoding='utf-8') as f:
        f.write(preview_html)
    
    print(f"🌐 预览页面: {preview_file.absolute()}")
    
    # 自动打开浏览器
    try:
        webbrowser.open(f"file://{preview_file.absolute()}")
        print("🚀 已在浏览器中打开D3.js演示页面")
    except:
        print("⚠️  无法自动打开浏览器，请手动打开HTML文件")
    
    print(f"\n✅ D3.js演示完成！")
    print(f"📁 所有文件保存在: {output_dir.absolute()}")
    print()
    print("🎯 D3.js力导向图特性:")
    print("• 🎨 完全交互式的力导向图")
    print("• 🖱️ 节点拖拽和动态布局")
    print("• 🔍 平滑缩放和视图控制")
    print("• 💡 详细的悬停提示信息")
    print("• 🖱️ 节点点击查看详情")
    print("• ⚡ 实时物理模拟动画")
    print("• 📱 响应式设计适配")
    print("• 🎨 现代化视觉效果")
    print("• 📊 实时威胁统计分析")
    print("• 💡 智能安全建议")
    
    return output_dir

def create_preview_page(test_cases, output_dir):
    """创建预览页面"""
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw D3.js 威胁力导向图演示</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            margin-bottom: 40px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .header p {{
            font-size: 1.2em;
            color: #666;
            margin-bottom: 20px;
        }}
        
        .features {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .feature {{
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }}
        
        .feature:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }}
        
        .feature-icon {{
            font-size: 3em;
            margin-bottom: 15px;
        }}
        
        .feature h3 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .demo-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }}
        
        .demo-card {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 6px 25px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }}
        
        .demo-card:hover {{
            border-color: #667eea;
            transform: translateY(-5px);
            box-shadow: 0 12px 35px rgba(102, 126, 234, 0.2);
        }}
        
        .demo-title {{
            font-size: 1.4em;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }}
        
        .demo-description {{
            color: #666;
            margin-bottom: 15px;
            line-height: 1.5;
        }}
        
        .demo-content {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
            word-break: break-all;
        }}
        
        .demo-link {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 15px 30px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        
        .demo-link:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }}
        
        .instructions {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            border-left: 5px solid #667eea;
            box-shadow: 0 6px 25px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }}
        
        .instructions h3 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        .instructions ul {{
            list-style: none;
            padding: 0;
        }}
        
        .instructions li {{
            margin: 15px 0;
            padding-left: 30px;
            position: relative;
            line-height: 1.6;
        }}
        
        .instructions li:before {{
            content: "✨";
            position: absolute;
            left: 0;
        }}
        
        .footer {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 6px 25px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header {{
                padding: 30px 20px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .demo-grid {{
                grid-template-columns: 1fr;
                gap: 20px;
            }}
            
            .features {{
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎨 OpenClaw D3.js 威胁力导向图</h1>
            <p>交互式威胁可视化系统 - 实时威胁检测与动态展示</p>
            <p><strong>基于D3.js的现代Web可视化技术</strong></p>
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
        
        <div class="demo-grid">
"""
    
    for i, test_case in enumerate(test_cases, 1):
        html += f"""
            <div class="demo-card">
                <div class="demo-title">🔍 演示 {i}: {test_case['name']}</div>
                <div class="demo-description">{test_case['description']}</div>
                <div class="demo-content">{test_case['content'][:80]}{'...' if len(test_case['content']) > 80 else ''}</div>
                <a href="d3_demo_{i}_{test_case['name'].replace(' ', '_')}.html" class="demo-link" target="_blank">
                    🚀 查看交互式图表 →
                </a>
            </div>
"""
    
    html += f"""
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
            </ul>
        </div>
        
        <div class="footer">
            <h3>🌟 系统特点</h3>
            <p>OpenClaw D3.js威胁可视化系统提供了直观、交互式的威胁分析体验</p>
            <p>通过动态力导向图，用户可以深入理解威胁之间的关系和影响范围</p>
            <p><small>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | 技术栈: D3.js v7 + HTML5 + CSS3</small></p>
        </div>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    print("🎨 OpenClaw D3.js 威胁力导向图演示 (独立版)")
    print("=" * 70)
    print("📋 演示特点:")
    print("• 🌐 完全基于Web技术，无需服务器")
    print("• 🎨 现代化D3.js交互式图表")
    print("• 📱 响应式设计，支持各种设备")
    print("• 🖱️ 丰富的交互操作")
    print("• 💡 实时威胁检测和分析")
    print()
    
    try:
        output_dir = run_standalone_d3_demo()
        
        print(f"\n🎯 演示成功完成！")
        print(f"📁 演示文件保存在: {output_dir}")
        print(f"🌐 请在浏览器中查看交互式图表效果")
        print()
        print("💡 使用提示:")
        print("• 每个HTML文件都是独立的交互式图表")
        print("• 可以直接在浏览器中打开查看")
        print("• 支持所有现代浏览器")
        print("• 无需安装额外软件或依赖")
        print()
        print("🚀 立即体验:")
        print(f"• 打开 {output_dir}/index.html 查看演示首页")
        print("• 点击各个演示链接查看不同威胁类型的可视化")
        print("• 体验完整的交互功能")
        
    except KeyboardInterrupt:
        print("\n⏹️  演示被中断")
    except Exception as e:
        print(f"❌ 演示失败: {e}")
        import traceback
        traceback.print_exc()
        print("\n💡 故障排除:")
        print("• 确保Python环境正确")
        print("• 检查输出目录权限")
        print("• 确认浏览器支持JavaScript")
