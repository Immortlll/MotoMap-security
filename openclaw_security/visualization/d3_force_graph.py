"""
OpenClaw D3.js 威胁力导向图生成器
生成交互式的D3.js力导向图HTML文件
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import uuid

class ThreatLevel(Enum):
    """威胁等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    """威胁类型"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SENSITIVE_DATA = "sensitive_data"
    MALICIOUS_SCRIPT = "malicious_script"
    SUSPICIOUS_PATTERN = "suspicious_pattern"

@dataclass
class ThreatNode:
    """威胁节点"""
    id: str
    threat_type: ThreatType
    level: ThreatLevel
    content: str
    position: str
    confidence: float
    description: str

@dataclass
class ThreatEdge:
    """威胁关系边"""
    source: str
    target: str
    relationship: str
    strength: float

class D3ForceGraphGenerator:
    """D3.js力导向图生成器"""
    
    def __init__(self):
        self.threat_nodes: List[ThreatNode] = []
        self.threat_edges: List[ThreatEdge] = []
        
        # 颜色配置
        self.level_colors = {
            ThreatLevel.LOW: "#4CAF50",      # 绿色
            ThreatLevel.MEDIUM: "#FF9800",   # 橙色
            ThreatLevel.HIGH: "#F44336",     # 红色
            ThreatLevel.CRITICAL: "#9C27B0"  # 紫色
        }
        
        # 威胁类型图标
        self.type_icons = {
            ThreatType.SQL_INJECTION: "🗃️",
            ThreatType.XSS: "🌐",
            ThreatType.PATH_TRAVERSAL: "📁",
            ThreatType.COMMAND_INJECTION: "⚡",
            ThreatType.SENSITIVE_DATA: "🔑",
            ThreatType.MALICIOUS_SCRIPT: "📜",
            ThreatType.SUSPICIOUS_PATTERN: "⚠️"
        }
        
        # 威胁描述
        self.threat_descriptions = {
            ThreatType.SQL_INJECTION: "SQL注入攻击：可能尝试访问或修改数据库",
            ThreatType.XSS: "跨站脚本攻击：可能执行恶意JavaScript代码",
            ThreatType.PATH_TRAVERSAL: "路径遍历攻击：可能访问系统敏感文件",
            ThreatType.COMMAND_INJECTION: "命令注入攻击：可能执行系统命令",
            ThreatType.SENSITIVE_DATA: "敏感数据泄露：包含可能的敏感信息",
            ThreatType.MALICIOUS_SCRIPT: "恶意脚本：包含可疑的脚本代码",
            ThreatType.SUSPICIOUS_PATTERN: "可疑模式：包含异常的字符序列"
        }
    
    def analyze_content(self, content: str) -> List[ThreatNode]:
        """分析内容并生成威胁节点"""
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
                node = ThreatNode(
                    id=f"sql_{i}_{match.start()}",
                    threat_type=ThreatType.SQL_INJECTION,
                    level=ThreatLevel.HIGH,
                    content=match.group(),
                    position=f"{match.start()}-{match.end()}",
                    confidence=0.8,
                    description=self.threat_descriptions[ThreatType.SQL_INJECTION]
                )
                threats.append(node)
                self.threat_nodes.append(node)
        
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
                node = ThreatNode(
                    id=f"xss_{i}_{match.start()}",
                    threat_type=ThreatType.XSS,
                    level=ThreatLevel.MEDIUM,
                    content=match.group(),
                    position=f"{match.start()}-{match.end()}",
                    confidence=0.7,
                    description=self.threat_descriptions[ThreatType.XSS]
                )
                threats.append(node)
                self.threat_nodes.append(node)
        
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
                node = ThreatNode(
                    id=f"path_{i}_{match.start()}",
                    threat_type=ThreatType.PATH_TRAVERSAL,
                    level=ThreatLevel.MEDIUM,
                    content=match.group(),
                    position=f"{match.start()}-{match.end()}",
                    confidence=0.6,
                    description=self.threat_descriptions[ThreatType.PATH_TRAVERSAL]
                )
                threats.append(node)
                self.threat_nodes.append(node)
        
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
                node = ThreatNode(
                    id=f"cmd_{i}_{match.start()}",
                    threat_type=ThreatType.COMMAND_INJECTION,
                    level=ThreatLevel.HIGH,
                    content=match.group(),
                    position=f"{match.start()}-{match.end()}",
                    confidence=0.75,
                    description=self.threat_descriptions[ThreatType.COMMAND_INJECTION]
                )
                threats.append(node)
                self.threat_nodes.append(node)
        
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
                node = ThreatNode(
                    id=f"sensitive_{i}_{match.start()}",
                    threat_type=ThreatType.SENSITIVE_DATA,
                    level=ThreatLevel.CRITICAL,
                    content=match.group(),
                    position=f"{match.start()}-{match.end()}",
                    confidence=0.9,
                    description=self.threat_descriptions[ThreatType.SENSITIVE_DATA]
                )
                threats.append(node)
                self.threat_nodes.append(node)
        
        return threats
    
    def create_relationships(self):
        """创建威胁节点之间的关系"""
        if len(self.threat_nodes) > 1:
            for i, node1 in enumerate(self.threat_nodes):
                for j, node2 in enumerate(self.threat_nodes[i+1:], i+1):
                    relationship = self._determine_relationship(node1, node2)
                    if relationship:
                        strength = self._calculate_relationship_strength(node1, node2)
                        edge = ThreatEdge(
                            source=node1.id,
                            target=node2.id,
                            relationship=relationship,
                            strength=strength
                        )
                        self.threat_edges.append(edge)
    
    def _determine_relationship(self, node1: ThreatNode, node2: ThreatNode) -> Optional[str]:
        """确定两个威胁节点之间的关系"""
        # 相同位置的威胁
        if node1.position == node2.position:
            return "overlap"
        
        # 相邻位置的威胁
        pos1_start = int(node1.position.split('-')[0])
        pos1_end = int(node1.position.split('-')[1])
        pos2_start = int(node2.position.split('-')[0])
        pos2_end = int(node2.position.split('-')[1])
        
        if abs(pos1_start - pos2_start) < 20:
            return "adjacent"
        
        # 相同类型的威胁
        if node1.threat_type == node2.threat_type:
            return "similar"
        
        # 高威胁和低威胁的关系
        if (node1.level == ThreatLevel.CRITICAL and node2.level != ThreatLevel.CRITICAL) or \
           (node2.level == ThreatLevel.CRITICAL and node1.level != ThreatLevel.CRITICAL):
            return "escalation"
        
        return None
    
    def _calculate_relationship_strength(self, node1: ThreatNode, node2: ThreatNode) -> float:
        """计算关系强度"""
        base_strength = 0.5
        
        # 基于置信度调整
        confidence_factor = (node1.confidence + node2.confidence) / 2
        
        # 基于威胁等级调整
        level_weights = {
            ThreatLevel.LOW: 0.25,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.HIGH: 0.75,
            ThreatLevel.CRITICAL: 1.0
        }
        
        level_factor = (level_weights[node1.level] + level_weights[node2.level]) / 2
        
        return base_strength * confidence_factor * level_factor
    
    def generate_d3_data(self, content: str) -> Dict:
        """生成D3.js格式的数据"""
        # 分析内容
        self.analyze_content(content)
        
        # 创建关系
        self.create_relationships()
        
        # 转换为D3.js格式
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
        for node in self.threat_nodes:
            d3_node = {
                "id": node.id,
                "name": node.threat_type.value.replace('_', ' ').title(),
                "type": node.threat_type.value,
                "content": node.content,
                "level": node.level.value,
                "color": self.level_colors[node.level],
                "icon": self.type_icons[node.threat_type],
                "description": node.description,
                "confidence": node.confidence,
                "position": node.position,
                "size": 20 + node.confidence * 20
            }
            nodes.append(d3_node)
        
        # 添加边
        for edge in self.threat_edges:
            d3_link = {
                "source": edge.source,
                "target": edge.target,
                "relationship": edge.relationship,
                "strength": edge.strength,
                "value": edge.strength * 10
            }
            links.append(d3_link)
        
        # 连接威胁到内容
        for node in self.threat_nodes:
            links.append({
                "source": "content",
                "target": node.id,
                "relationship": "contains",
                "strength": 0.8,
                "value": 8
            })
        
        return {
            "nodes": nodes,
            "links": links,
            "statistics": self._calculate_statistics()
        }
    
    def _calculate_statistics(self) -> Dict:
        """计算统计信息"""
        if not self.threat_nodes:
            return {
                "total_threats": 0,
                "risk_level": "SAFE",
                "risk_score": 0,
                "threat_breakdown": {},
                "recommendations": ["内容安全，无需特别关注"]
            }
        
        # 计算威胁统计
        total_threats = len(self.threat_nodes)
        level_counts = {}
        type_counts = {}
        
        for node in self.threat_nodes:
            level_counts[node.level] = level_counts.get(node.level, 0) + 1
            type_counts[node.threat_type] = type_counts.get(node.threat_type, 0) + 1
        
        # 计算风险评分
        risk_score = 0
        risk_weights = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 5,
            ThreatLevel.HIGH: 10,
            ThreatLevel.CRITICAL: 20
        }
        
        for node in self.threat_nodes:
            risk_score += risk_weights[node.level] * node.confidence
        
        # 确定风险等级
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 20:
            risk_level = "HIGH"
        elif risk_score >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # 生成建议
        recommendations = self._generate_recommendations(level_counts, type_counts)
        
        return {
            "total_threats": total_threats,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendations": recommendations,
            "threat_breakdown": {
                "by_level": {k.value: v for k, v in level_counts.items()},
                "by_type": {k.value: v for k, v in type_counts.items()}
            }
        }
    
    def _generate_recommendations(self, level_counts: Dict, type_counts: Dict) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        # 基于威胁等级的建议
        if level_counts.get(ThreatLevel.CRITICAL, 0) > 0:
            recommendations.append("🚨 检测到关键威胁，建议立即审查内容")
        
        if level_counts.get(ThreatLevel.HIGH, 0) > 2:
            recommendations.append("⚠️ 检测到多个高风险威胁，建议增强监控")
        
        if level_counts.get(ThreatLevel.MEDIUM, 0) > 5:
            recommendations.append("🔍 检测到多个中等风险威胁，建议定期检查")
        
        # 基于威胁类型的建议
        if type_counts.get(ThreatType.SQL_INJECTION, 0) > 0:
            recommendations.append("🗃️ 检测到SQL注入模式，建议验证数据库查询")
        
        if type_counts.get(ThreatType.XSS, 0) > 0:
            recommendations.append("🌐 检测到XSS模式，建议过滤用户输入")
        
        if type_counts.get(ThreatType.SENSITIVE_DATA, 0) > 0:
            recommendations.append("🔑 检测到敏感数据，建议加密存储")
        
        if not recommendations:
            recommendations.append("✅ 内容相对安全，建议保持常规监控")
        
        return recommendations
    
    def generate_html(self, content: str, title: str = "威胁力导向图") -> str:
        """生成完整的HTML文件"""
        data = self.generate_d3_data(content)
        
        html_template = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
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
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .risk-critical {{ color: #9C27B0; }}
        .risk-high {{ color: #F44336; }}
        .risk-medium {{ color: #FF9800; }}
        .risk-low {{ color: #4CAF50; }}
        .risk-safe {{ color: #2196F3; }}
        
        .graph-container {{
            height: 600px;
            border: 1px solid #e0e0e0;
            margin: 0 30px 30px 30px;
            border-radius: 10px;
            background: #fafafa;
        }}
        
        .node {{
            cursor: pointer;
        }}
        
        .node circle {{
            stroke: #fff;
            stroke-width: 2px;
        }}
        
        .node text {{
            font-size: 12px;
            pointer-events: none;
            text-anchor: middle;
            fill: #333;
        }}
        
        .link {{
            fill: none;
            stroke-opacity: 0.6;
        }}
        
        .tooltip {{
            position: absolute;
            padding: 15px;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            border-radius: 8px;
            font-size: 14px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s;
            max-width: 300px;
            z-index: 1000;
        }}
        
        .controls {{
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}
        
        .btn {{
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background: #667eea;
            color: white;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s ease;
        }}
        
        .btn:hover {{
            background: #5a67d8;
        }}
        
        .recommendations {{
            padding: 20px 30px;
            background: #e7f3ff;
            border-left: 4px solid #667eea;
        }}
        
        .recommendations h3 {{
            margin: 0 0 15px 0;
            color: #667eea;
        }}
        
        .recommendations ul {{
            margin: 0;
            padding-left: 20px;
        }}
        
        .recommendations li {{
            margin: 8px 0;
        }}
        
        .legend {{
            padding: 20px 30px;
            background: #f8f9fa;
        }}
        
        .legend h3 {{
            margin: 0 0 15px 0;
            color: #333;
        }}
        
        .legend-items {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            border: 2px solid #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
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
            <button class="btn" onclick="resetZoom()">重置缩放</button>
            <button class="btn" onclick="toggleLabels()">切换标签</button>
            <button class="btn" onclick="toggleForce()">暂停/继续</button>
            <button class="btn" onclick="exportImage()">导出图片</button>
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
    </div>
    
    <div class="tooltip" id="tooltip"></div>
    
    <script>
        // 数据
        const data = {json.dumps(data, indent=2)};
        
        // 设置SVG尺寸
        const width = document.getElementById('graph').clientWidth;
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
                container.attr("transform", event.transform);
            }});
        
        svg.call(zoom);
        
        // 创建容器
        const container = svg.append("g");
        
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
        const link = container.append("g")
            .selectAll("line")
            .data(data.links)
            .enter().append("line")
            .attr("class", "link")
            .attr("stroke", "#999")
            .attr("stroke-width", d => Math.sqrt(d.value))
            .attr("stroke-opacity", d => d.strength);
        
        // 创建节点
        const node = container.append("g")
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
            .style("font-size", "16px")
            .style("pointer-events", "none")
            .text(d => d.icon);
        
        // 添加标签
        const labels = node.append("text")
            .attr("dy", d => d.size + 15)
            .style("font-size", "12px")
            .style("text-anchor", "middle")
            .style("fill", "#333")
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
            tooltip.innerHTML = `
                <strong>${{d.name}}</strong><br>
                类型: ${{d.type}}<br>
                等级: ${{d.level}}<br>
                置信度: ${{(d.confidence * 100).toFixed(1)}}%<br>
                ${{d.description}}
                ${{d.content ? '<br><br><strong>内容:</strong> ' + d.content.substring(0, 50) + (d.content.length > 50 ? '...' : '') : ''}}
            `;
            tooltip.style.left = event.pageX + 10 + "px";
            tooltip.style.top = event.pageY - 10 + "px";
            tooltip.style.opacity = 1;
        }}
        
        function hideTooltip() {{
            tooltip.style.opacity = 0;
        }}
        
        // 节点点击
        function nodeClick(event, d) {{
            if (d.type === "content") {{
                alert("原始内容: " + d.content);
            }} else {{
                alert(`威胁类型: ${{d.name}}\\n威胁等级: ${{d.level}}\\n威胁内容: ${{d.content}}\\n描述: ${{d.description}}`);
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
            }} else {{
                simulation.restart();
            }}
            forceRunning = !forceRunning;
        }}
        
        function exportImage() {{
            // 简单的导出功能
            const svgData = new XMLSerializer().serializeToString(svg.node());
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");
            const img = new Image();
            
            canvas.width = width;
            canvas.height = height;
            
            img.onload = function() {{
                ctx.drawImage(img, 0, 0);
                const link = document.createElement("a");
                link.download = "threat-graph.png";
                link.href = canvas.toDataURL();
                link.click();
            }};
            
            img.src = "data:image/svg+xml;base64," + btoa(svgData);
        }}
        
        // 响应式调整
        window.addEventListener("resize", () => {{
            const newWidth = document.getElementById("graph").clientWidth;
            svg.attr("width", newWidth);
            simulation.force("center", d3.forceCenter(newWidth / 2, height / 2));
            simulation.alpha(0.3).restart();
        }});
    </script>
</body>
</html>
"""
        
        return html_template

# 便捷函数
def create_d3_force_graph(content: str, title: str = "威胁力导向图") -> str:
    """
    创建D3.js力导向图HTML文件
    
    Args:
        content: 待分析的内容
        title: 图表标题
        
    Returns:
        str: HTML文件内容
    """
    generator = D3ForceGraphGenerator()
    return generator.generate_html(content, title)

def save_d3_graph(content: str, filename: str = "threat_graph.html", title: str = "威胁力导向图") -> str:
    """
    保存D3.js力导向图到文件
    
    Args:
        content: 待分析的内容
        filename: 保存的文件名
        title: 图表标题
        
    Returns:
        str: 保存的文件路径
    """
    html_content = create_d3_force_graph(content, title)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename
