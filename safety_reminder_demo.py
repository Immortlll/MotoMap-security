#!/usr/bin/env python3
"""
OpenClaw 安全提醒演示脚本
使用D3.js力导向图提醒用户哪些内容输入会有危险
"""

import re
import json
from datetime import datetime
from pathlib import Path
import webbrowser

class SafetyLevel:
    """安全等级"""
    SAFE = "safe"           # 安全
    CAUTION = "caution"     # 注意
    WARNING = "warning"     # 警告
    DANGER = "danger"       # 危险

class RiskType:
    """风险类型"""
    PERSONAL_INFO = "personal_info"      # 个人信息
    FINANCIAL = "financial"             # 财务信息
    ACCOUNT = "account"                 # 账户信息
    TECHNICAL = "technical"             # 技术信息
    PRIVACY = "privacy"                 # 隐私信息

def analyze_safety_risks(content):
    """分析内容的安全风险"""
    risks = []
    
    # 个人信息风险
    personal_patterns = [
        r'\b\d{3}[-\s]?\d{4}[-\s]?\d{4}\b',  # 手机号
        r'\b\d{18}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{4}\b',  # 身份证
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # 邮箱
        r'[\u4e00-\u9fa5]{2,4}(先生|女士|同学|老师)',  # 姓名+称谓
    ]
    
    for i, pattern in enumerate(personal_patterns):
        matches = re.finditer(pattern, content)
        for match in matches:
            risks.append({
                'type': RiskType.PERSONAL_INFO,
                'level': SafetyLevel.WARNING,
                'icon': '👤',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.9,
                'message': "包含个人信息，请注意保护隐私",
                'suggestion': "建议：避免在公开场合输入个人联系方式"
            })
    
    # 财务信息风险
    financial_patterns = [
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 银行卡
        r'(支付宝|微信支付|银行卡|信用卡|借记卡)',
        r'(付款|转账|收款|红包|余额)',
        r'(密码|支付密码|交易密码|取款密码)',
    ]
    
    for i, pattern in enumerate(financial_patterns):
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            risks.append({
                'type': RiskType.FINANCIAL,
                'level': SafetyLevel.DANGER,
                'icon': '💰',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.95,
                'message': "包含财务信息，存在资金安全风险",
                'suggestion': "建议：切勿在非官方渠道输入银行卡、密码等财务信息"
            })
    
    # 账户信息风险
    account_patterns = [
        r'(账号|账户|用户名|登录名)',
        r'(密码|口令|验证码)',
        r'(API密钥|API Key|Secret Key)',
        r'(token|access token|refresh token)',
        r'(私钥|公钥|密钥对)',
    ]
    
    for i, pattern in enumerate(account_patterns):
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            risks.append({
                'type': RiskType.ACCOUNT,
                'level': SafetyLevel.DANGER,
                'icon': '🔐',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.85,
                'message': "包含账户信息，存在账号安全风险",
                'suggestion': "建议：仅在官方可信网站输入账号密码，定期更换密码"
            })
    
    # 技术信息风险
    technical_patterns = [
        r'(数据库|database|DB)',
        r'(服务器|server|host)',
        r'(IP地址|IP|内网|外网)',
        r'(端口|port)',
        r'(配置文件|config|configuration)',
        r'(源代码|source code|代码)',
    ]
    
    for i, pattern in enumerate(technical_patterns):
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            risks.append({
                'type': RiskType.TECHNICAL,
                'level': SafetyLevel.CAUTION,
                'icon': '💻',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.7,
                'message': "包含技术信息，可能存在信息泄露风险",
                'suggestion': "建议：避免在公开平台讨论内部技术架构和配置"
            })
    
    # 隐私信息风险
    privacy_patterns = [
        r'(家庭住址|住址|地址|居住地)',
        r'(身份证|身份证号|ID)',
        r'(电话|手机|联系方式)',
        r'(出生日期|生日|年龄)',
        r'(职业|工作单位|公司)',
        r'(学校|班级|学号)',
    ]
    
    for i, pattern in enumerate(privacy_patterns):
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            risks.append({
                'type': RiskType.PRIVACY,
                'level': SafetyLevel.WARNING,
                'icon': '🏠',
                'content': match.group(),
                'position': f"{match.start()}-{match.end()}",
                'confidence': 0.8,
                'message': "包含隐私信息，建议谨慎处理",
                'suggestion': "建议：保护个人隐私，避免在公共场合分享敏感信息"
            })
    
    return risks

def create_safety_reminder_data(content):
    """创建安全提醒D3.js数据"""
    risks = analyze_safety_risks(content)
    
    # 安全等级颜色
    level_colors = {
        SafetyLevel.SAFE: "#4CAF50",      # 绿色
        SafetyLevel.CAUTION: "#FF9800",   # 橙色
        SafetyLevel.WARNING: "#FF5722",   # 深橙色
        SafetyLevel.DANGER: "#F44336"      # 红色
    }
    
    # 风险类型图标
    type_icons = {
        RiskType.PERSONAL_INFO: "👤",
        RiskType.FINANCIAL: "💰",
        RiskType.ACCOUNT: "🔐",
        RiskType.TECHNICAL: "💻",
        RiskType.PRIVACY: "🏠"
    }
    
    # 创建节点和边
    nodes = []
    links = []
    
    # 添加用户输入节点
    user_node = {
        "id": "user_input",
        "name": "用户输入",
        "type": "user_input",
        "content": content[:50] + "..." if len(content) > 50 else content,
        "level": "user",
        "color": "#2196F3",
        "icon": "📝",
        "description": "您的输入内容",
        "size": 35
    }
    nodes.append(user_node)
    
    # 添加风险节点
    for i, risk in enumerate(risks):
        risk_node = {
            "id": f"risk_{i}",
            "name": get_risk_type_name(risk['type']),
            "type": risk['type'],
            "content": risk['content'],
            "level": risk['level'],
            "color": level_colors[risk['level']],
            "icon": type_icons[risk['type']],
            "message": risk['message'],
            "suggestion": risk['suggestion'],
            "confidence": risk['confidence'],
            "position": risk['position'],
            "size": 25 + risk['confidence'] * 15
        }
        nodes.append(risk_node)
        
        # 连接风险到用户输入
        links.append({
            "source": "user_input",
            "target": f"risk_{i}",
            "relationship": "contains",
            "strength": risk['confidence'],
            "value": risk['confidence'] * 10
        })
    
    # 计算安全统计
    total_risks = len(risks)
    risk_score = 0
    
    level_weights = {
        SafetyLevel.SAFE: 0,
        SafetyLevel.CAUTION: 10,
        SafetyLevel.WARNING: 25,
        SafetyLevel.DANGER: 50
    }
    
    for risk in risks:
        risk_score += level_weights[risk['level']] * risk['confidence']
    
    # 确定整体安全等级
    if risk_score >= 100:
        safety_level = "DANGER"
        safety_emoji = "🚨"
        safety_message = "输入内容存在高风险，强烈建议修改"
    elif risk_score >= 50:
        safety_level = "WARNING"
        safety_emoji = "⚠️"
        safety_message = "输入内容存在中风险，建议谨慎处理"
    elif risk_score >= 20:
        safety_level = "CAUTION"
        safety_emoji = "🔍"
        safety_message = "输入内容存在低风险，建议注意保护"
    else:
        safety_level = "SAFE"
        safety_emoji = "✅"
        safety_message = "输入内容相对安全"
    
    # 生成建议
    recommendations = generate_safety_recommendations(risks, safety_level)
    
    return {
        "nodes": nodes,
        "links": links,
        "statistics": {
            "total_risks": total_risks,
            "risk_score": risk_score,
            "safety_level": safety_level,
            "safety_emoji": safety_emoji,
            "safety_message": safety_message,
            "recommendations": recommendations
        }
    }

def get_risk_type_name(risk_type):
    """获取风险类型的中文名称"""
    names = {
        RiskType.PERSONAL_INFO: "个人信息",
        RiskType.FINANCIAL: "财务信息",
        RiskType.ACCOUNT: "账户信息",
        RiskType.TECHNICAL: "技术信息",
        RiskType.PRIVACY: "隐私信息"
    }
    return names.get(risk_type, "未知风险")

def generate_safety_recommendations(risks, safety_level):
    """生成安全建议"""
    recommendations = []
    
    if safety_level == "DANGER":
        recommendations.append("🚨 立即停止输入！这些信息可能造成严重后果")
        recommendations.append("🔒 请在官方可信环境中输入敏感信息")
    elif safety_level == "WARNING":
        recommendations.append("⚠️ 请谨慎处理这些信息")
        recommendations.append("🛡️ 建议使用加密或匿名化处理")
    elif safety_level == "CAUTION":
        recommendations.append("🔍 请注意保护这些信息")
        recommendations.append("📝 建议避免在公开场合分享")
    else:
        recommendations.append("✅ 内容相对安全，继续保持警惕")
    
    # 基于风险类型的建议
    risk_types = set(risk['type'] for risk in risks)
    
    if RiskType.FINANCIAL in risk_types:
        recommendations.append("💰 财务安全：切勿在非官方渠道输入银行卡、密码")
    
    if RiskType.ACCOUNT in risk_types:
        recommendations.append("🔐 账户安全：定期更换密码，使用强密码")
    
    if RiskType.PERSONAL_INFO in risk_types:
        recommendations.append("👤 隐私保护：避免在公开平台分享个人信息")
    
    if RiskType.TECHNICAL in risk_types:
        recommendations.append("💻 技术保密：避免泄露内部技术信息")
    
    return recommendations

def create_safety_reminder_html(content, title="安全提醒"):
    """创建安全提醒D3.js HTML文件"""
    data = create_safety_reminder_data(content)
    
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
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
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
            font-size: 2.2em;
            font-weight: 300;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .safety-status {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .status-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }}
        
        .status-card:hover {{
            transform: translateY(-5px);
            border-color: #667eea;
        }}
        
        .status-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .status-label {{
            color: #666;
            font-size: 0.9em;
            font-weight: 500;
        }}
        
        .safety-safe {{ color: #4CAF50; }}
        .safety-caution {{ color: #FF9800; }}
        .safety-warning {{ color: #FF5722; }}
        .safety-danger {{ color: #F44336; }}
        
        .graph-container {{
            height: 500px;
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
        
        .suggestions {{
            padding: 30px;
            background: linear-gradient(135deg, #e7f3ff, #f0f8ff);
            border-left: 4px solid #667eea;
        }}
        
        .suggestions h3 {{
            margin: 0 0 20px 0;
            color: #667eea;
            font-size: 1.3em;
        }}
        
        .suggestions ul {{
            margin: 0;
            padding-left: 20px;
        }}
        
        .suggestions li {{
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
                font-size: 1.8em;
            }}
            
            .safety-status {{
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
            <h1>🛡️ {title}</h1>
            <p>智能安全提醒系统 - 保护您的信息安全</p>
        </div>
        
        <div class="safety-status">
            <div class="status-card">
                <div class="status-value">{data['statistics']['safety_emoji']}</div>
                <div class="status-label">安全状态</div>
            </div>
            <div class="status-card">
                <div class="status-value safety-{{data['statistics']['safety_level'].lower()}}">{data['statistics']['safety_level']}</div>
                <div class="status-label">风险等级</div>
            </div>
            <div class="status-card">
                <div class="status-value">{data['statistics']['total_risks']}</div>
                <div class="status-label">风险数量</div>
            </div>
            <div class="status-card">
                <div class="status-value">{data['statistics']['risk_score']}</div>
                <div class="status-label">风险评分</div>
            </div>
        </div>
        
        <div class="graph-container" id="graph"></div>
        
        <div class="controls">
            <button class="btn" onclick="resetZoom()">🔄 重置视图</button>
            <button class="btn" onclick="toggleLabels()">🏷️ 切换标签</button>
            <button class="btn" onclick="toggleForce()">⏸️ 暂停动画</button>
            <button class="btn" onclick="showDetails()">📋 查看详情</button>
        </div>
        
        <div class="suggestions">
            <h3>💡 安全建议</h3>
            <p style="margin-bottom: 20px; font-size: 1.1em; color: #333;">{data['statistics']['safety_message']}</p>
            <ul>
                {''.join(f'<li>{rec}</li>' for rec in data['statistics']['recommendations'])}
            </ul>
        </div>
        
        <div class="legend">
            <h3>🎨 风险类型说明</h3>
            <div class="legend-items">
                <div class="legend-item">
                    <div class="legend-color" style="background: #2196F3;"></div>
                    <span>用户输入</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #4CAF50;"></div>
                    <span>安全</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #FF9800;"></div>
                    <span>注意</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #FF5722;"></div>
                    <span>警告</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #F44336;"></div>
                    <span>危险</span>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>🛡️ 安全提醒</strong></p>
            <p>保护您的信息安全，谨慎处理敏感内容</p>
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
        const height = 500;
        
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
                .distance(100)
                .strength(d => d.strength))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => d.size + 5));
        
        // 创建边
        const link = containerGroup.append("g")
            .selectAll("line")
            .data(data.links)
            .enter().append("line")
            .attr("class", "link")
            .attr("stroke", "#999")
            .attr("stroke-width", d => Math.sqrt(d.value))
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
            .style("font-size", d => d.size * 0.5 + "px")
            .style("pointer-events", "none")
            .text(d => d.icon);
        
        // 添加标签
        const labels = node.append("text")
            .attr("dy", d => d.size + 18)
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
            let content = `<strong>${{d.name}}</strong><br>`;
            content += `类型: ${{d.type}}<br>`;
            content += `等级: ${{d.level}}<br>`;
            content += `置信度: ${{(d.confidence * 100).toFixed(1)}}%<br>`;
            
            if (d.message) {{
                content += `<br><strong>⚠️ 风险提示:</strong><br>${{d.message}}`;
            }}
            
            if (d.suggestion) {{
                content += `<br><strong>💡 建议:</strong><br>${{d.suggestion}}`;
            }}
            
            if (d.content && d.content !== d.name) {{
                content += `<br><br><strong>内容:</strong> ${{d.content.substring(0, 50)}}${{d.content.length > 50 ? '...' : ''}}`;
            }}
            
            tooltip.innerHTML = content;
            tooltip.style.left = event.pageX + 15 + "px";
            tooltip.style.top = event.pageY - 10 + "px";
            tooltip.style.opacity = 1;
        }}
        
        function hideTooltip() {{
            tooltip.style.opacity = 0;
        }}
        
        // 节点点击
        function nodeClick(event, d) {{
            if (d.type === "user_input") {{
                alert("📝 用户输入:\\n\\n" + d.content);
            }} else {{
                let message = `🔍 风险详情:\\n\\n类型: ${{d.name}}\\n等级: ${{d.level.toUpperCase()}}\\n置信度: ${{(d.confidence * 100).toFixed(1)}}%\\n\\n`;
                
                if (d.message) {{
                    message += `⚠️ 风险提示: ${{d.message}}\\n\\n`;
                }}
                
                if (d.suggestion) {{
                    message += `💡 安全建议: ${{d.suggestion}}\\n\\n`;
                }}
                
                message += `检测内容: ${{d.content}}`;
                
                alert(message);
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
        
        function showDetails() {{
            let details = `📋 安全分析详情\\n\\n`;
            details += `📊 统计信息:\\n`;
            details += `  • 安全状态: ${{data.statistics.safety_emoji}} ${{data.statistics.safety_level}}\\n`;
            details += `  • 风险数量: ${{data.statistics.total_risks}}\\n`;
            details += `  • 风险评分: ${{data.statistics.risk_score}}\\n\\n`;
            details += `💡 安全建议:\\n`;
            
            data.statistics.recommendations.forEach((rec, i) => {{
                details += `  ${{i + 1}}. ${{rec}}\\n`;
            }});
            
            alert(details);
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

def create_safety_reminder_demo():
    """创建安全提醒演示"""
    print("🛡️ OpenClaw 安全提醒演示")
    print("=" * 60)
    
    # 测试用例
    test_cases = [
        {
            "name": "个人信息输入",
            "content": "我叫张三，电话是13812345678，邮箱是zhangsan@example.com",
            "description": "检测个人信息泄露风险"
        },
        {
            "name": "财务信息输入",
            "content": "我的银行卡号是6222021234567890123，支付宝账户是zhangsan@alipay.com",
            "description": "检测财务信息安全风险"
        },
        {
            "name": "账户信息输入",
            "content": "用户名是admin，密码是password123，API密钥是sk-abcdef123456",
            "description": "检测账户安全风险"
        },
        {
            "name": "技术信息输入",
            "content": "服务器IP是192.168.1.100，数据库是MySQL，端口是3306",
            "description": "检测技术信息泄露风险"
        },
        {
            "name": "正常输入",
            "content": "今天天气很好，我想去公园散步",
            "description": "安全输入示例"
        }
    ]
    
    # 创建输出目录
    output_dir = Path("safety_reminder_demo")
    output_dir.mkdir(exist_ok=True)
    
    print(f"📁 输出目录: {output_dir.absolute()}")
    print()
    
    # 处理每个测试用例
    for i, test_case in enumerate(test_cases, 1):
        print(f"--- 安全提醒 {i}: {test_case['name']} ---")
        print(f"内容: {test_case['content']}")
        print(f"描述: {test_case['description']}")
        
        # 生成安全提醒HTML
        html_content = create_safety_reminder_html(
            test_case['content'], 
            f"安全提醒 - {test_case['name']}"
        )
        
        # 保存文件
        filename = output_dir / f"safety_{i}_{test_case['name'].replace(' ', '_')}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ 已保存: {filename}")
        print(f"📏 文件大小: {len(html_content)/1024:.1f}KB")
        print()
    
    # 生成预览页面
    preview_html = create_safety_preview_page(test_cases, output_dir)
    preview_file = output_dir / "index.html"
    
    with open(preview_file, 'w', encoding='utf-8') as f:
        f.write(preview_html)
    
    print(f"🌐 预览页面: {preview_file.absolute()}")
    
    # 自动打开浏览器
    try:
        webbrowser.open(f"file://{preview_file.absolute()}")
        print("🚀 已在浏览器中打开安全提醒演示页面")
    except:
        print("⚠️  无法自动打开浏览器，请手动打开HTML文件")
    
    print(f"\n✅ 安全提醒演示完成！")
    print(f"📁 所有文件保存在: {output_dir.absolute()}")
    print()
    print("🛡️ 安全提醒特点:")
    print("• 🔍 智能识别各类信息安全风险")
    print("• 💡 提供具体的安全保护建议")
    print("• 🎨 直观的D3.js可视化展示")
    print("• 📊 实时风险评估和统计")
    print("• 🖱️ 丰富的交互操作")
    print("• 📱 响应式设计适配")
    
    return output_dir

def create_safety_preview_page(test_cases, output_dir):
    """创建安全提醒预览页面"""
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw 安全提醒系统</title>
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
            content: "🛡️";
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
            <h1>🛡️ OpenClaw 安全提醒系统</h1>
            <p>智能安全提醒系统 - 保护您的信息安全，避免不必要的风险</p>
            <p><strong>不是攻击检测，而是安全提醒！</strong></p>
        </div>
        
        <div class="features">
            <div class="feature">
                <div class="feature-icon">🔍</div>
                <h3>智能风险识别</h3>
                <p>自动识别个人信息、财务信息、账户信息等敏感内容</p>
            </div>
            <div class="feature">
                <div class="feature-icon">💡</div>
                <h3>安全建议</h3>
                <p>提供具体的安全保护建议，帮助用户避免风险</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🎨</div>
                <h3>可视化提醒</h3>
                <p>使用D3.js力导向图直观展示风险类型和等级</p>
            </div>
            <div class="feature">
                <div class="feature-icon">📊</div>
                <h3>实时评估</h3>
                <p>实时计算风险评分，提供整体安全状态评估</p>
            </div>
        </div>
        
        <div class="demo-grid">
"""
    
    for i, test_case in enumerate(test_cases, 1):
        html += f"""
            <div class="demo-card">
                <div class="demo-title">🔍 安全提醒 {i}: {test_case['name']}</div>
                <div class="demo-description">{test_case['description']}</div>
                <div class="demo-content">{test_case['content'][:80]}{'...' if len(test_case['content']) > 80 else ''}</div>
                <a href="safety_{i}_{test_case['name'].replace(' ', '_')}.html" class="demo-link" target="_blank">
                    🛡️ 查看安全提醒 →
                </a>
            </div>
"""
    
    html += f"""
        </div>
        
        <div class="instructions">
            <h3>🛡️ 安全提醒使用指南</h3>
            <ul>
                <li><strong>识别风险:</strong> 系统会自动识别输入内容中的敏感信息</li>
                <li><strong>风险评估:</strong> 根据信息类型和敏感度评估风险等级</li>
                <li><strong>可视化展示:</strong> 使用力导向图直观展示风险分布</li>
                <li><strong>安全建议:</strong> 提供具体的安全保护建议和注意事项</li>
                <li><strong>交互操作:</strong> 支持拖拽、缩放、悬停查看详情等操作</li>
            </ul>
        </div>
        
        <div class="footer">
            <h3>🌟 系统特点</h3>
            <p>OpenClaw安全提醒系统专注于帮助用户识别和保护敏感信息</p>
            <p>通过友好的可视化界面，让安全提醒更加直观易懂</p>
            <p><small>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small></p>
        </div>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    print("🛡️ OpenClaw 安全提醒系统演示")
    print("=" * 60)
    print("📋 系统特点:")
    print("• 🔍 不是攻击检测，而是安全提醒")
    print("• 💡 帮助用户识别敏感信息风险")
    print("• 🎨 使用D3.js可视化展示")
    print("• 📊 提供具体的安全建议")
    print("• 🖱️ 支持丰富的交互操作")
    print()
    
    try:
        output_dir = create_safety_reminder_demo()
        
        print(f"\n🎯 安全提醒演示完成！")
        print(f"📁 演示文件保存在: {output_dir}")
        print(f"🌐 请在浏览器中查看安全提醒效果")
        print()
        print("💡 使用场景:")
        print("• 📝 表单输入前的安全检查")
        print("• 💬 聊天软件的敏感信息提醒")
        print("• 🌐 网页表单的安全提示")
        print("• 📱 移动应用输入验证")
        print()
        print("🚀 立即体验:")
        print(f"• 打开 {output_dir}/index.html 查看演示首页")
        print("• 点击各个演示链接查看不同类型的安全提醒")
        print("• 体验完整的安全提醒功能")
        
    except KeyboardInterrupt:
        print("\n⏹️  演示被中断")
    except Exception as e:
        print(f"❌ 演示失败: {e}")
        import traceback
        traceback.print_exc()
