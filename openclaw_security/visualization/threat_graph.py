"""
OpenClaw 威胁力导向图可视化系统
生成威胁提示图片，不拦截输出
"""

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch
import numpy as np
from typing import Dict, List, Tuple, Optional
import io
import base64
from dataclasses import dataclass
from enum import Enum
import colorsys
import math

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
    position: str  # 在原文中的位置
    confidence: float  # 置信度 0-1
    description: str

@dataclass
class ThreatEdge:
    """威胁关系边"""
    source: str
    target: str
    relationship: str
    strength: float  # 关系强度 0-1

class ThreatGraphVisualizer:
    """威胁力导向图可视化器"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.threat_nodes: List[ThreatNode] = []
        self.threat_edges: List[ThreatEdge] = []
        
        # 颜色配置
        self.level_colors = {
            ThreatLevel.LOW: '#4CAF50',      # 绿色
            ThreatLevel.MEDIUM: '#FF9800',   # 橙色
            ThreatLevel.HIGH: '#F44336',     # 红色
            ThreatLevel.CRITICAL: '#9C27B0'  # 紫色
        }
        
        # 威胁类型图标
        self.type_icons = {
            ThreatType.SQL_INJECTION: '🗃️',
            ThreatType.XSS: '🌐',
            ThreatType.PATH_TRAVERSAL: '📁',
            ThreatType.COMMAND_INJECTION: '⚡',
            ThreatType.SENSITIVE_DATA: '🔑',
            ThreatType.MALICIOUS_SCRIPT: '📜',
            ThreatType.SUSPICIOUS_PATTERN: '⚠️'
        }
        
        # 威胁描述模板
        self.threat_descriptions = {
            ThreatType.SQL_INJECTION: "SQL注入攻击：可能尝试访问或修改数据库",
            ThreatType.XSS: "跨站脚本攻击：可能执行恶意JavaScript代码",
            ThreatType.PATH_TRAVERSAL: "路径遍历攻击：可能访问系统敏感文件",
            ThreatType.COMMAND_INJECTION: "命令注入攻击：可能执行系统命令",
            ThreatType.SENSITIVE_DATA: "敏感数据泄露：包含可能的敏感信息",
            ThreatType.MALICIOUS_SCRIPT: "恶意脚本：包含可疑的脚本代码",
            ThreatType.SUSPICIOUS_PATTERN: "可疑模式：包含异常的字符序列"
        }
    
    def add_threat_node(self, node: ThreatNode):
        """添加威胁节点"""
        self.threat_nodes.append(node)
        
        # 添加到图结构
        self.graph.add_node(
            node.id,
            threat_type=node.threat_type.value,
            level=node.level.value,
            content=node.content,
            confidence=node.confidence,
            description=node.description,
            position=node.position
        )
    
    def add_threat_edge(self, edge: ThreatEdge):
        """添加威胁关系边"""
        self.threat_edges.append(edge)
        
        # 添加到图结构
        self.graph.add_edge(
            edge.source,
            edge.target,
            relationship=edge.relationship,
            strength=edge.strength
        )
    
    def analyze_content(self, content: str) -> List[ThreatNode]:
        """分析内容并生成威胁节点"""
        import re
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
                self.add_threat_node(node)
        
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
                self.add_threat_node(node)
        
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
                self.add_threat_node(node)
        
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
                self.add_threat_node(node)
        
        # 敏感数据模式
        sensitive_patterns = [
            r'(?i)(api[_-]?key|secret[_-]?key|password|token|private[_-]?key)\s*[:=]\s*[^\s]{8,}',
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 信用卡
            r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',  # 社会安全号
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'  # 邮箱
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
                self.add_threat_node(node)
        
        return threats
    
    def create_threat_relationships(self):
        """创建威胁节点之间的关系"""
        # 如果有多个威胁节点，创建关系
        if len(self.threat_nodes) > 1:
            for i, node1 in enumerate(self.threat_nodes):
                for j, node2 in enumerate(self.threat_nodes[i+1:], i+1):
                    # 基于威胁类型和位置创建关系
                    relationship = self._determine_relationship(node1, node2)
                    if relationship:
                        strength = self._calculate_relationship_strength(node1, node2)
                        edge = ThreatEdge(
                            source=node1.id,
                            target=node2.id,
                            relationship=relationship,
                            strength=strength
                        )
                        self.add_threat_edge(edge)
    
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
        
        if abs(pos1_start - pos2_start) < 20:  # 20个字符内
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
    
    def generate_force_directed_graph(self, width: int = 1200, height: int = 800) -> str:
        """生成力导向图并返回base64编码的图片"""
        # 创建图形布局
        plt.figure(figsize=(width/100, height/100), dpi=100)
        ax = plt.gca()
        
        # 如果没有威胁节点，创建空图
        if not self.threat_nodes:
            ax.text(0.5, 0.5, '✅ 未检测到威胁', 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=20, color='green', transform=ax.transAxes)
            ax.set_xlim(0, 1)
            ax.set_ylim(0, 1)
            ax.axis('off')
            
            # 保存图片
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight', pad_inches=0.1)
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            return image_base64
        
        # 创建力导向布局
        pos = nx.spring_layout(self.graph, k=2, iterations=50, seed=42)
        
        # 绘制边
        for edge in self.threat_edges:
            source_pos = pos[edge.source]
            target_pos = pos[edge.target]
            
            # 边的透明度基于强度
            alpha = edge.strength * 0.6 + 0.2
            
            # 绘制边
            ax.plot([source_pos[0], target_pos[0]], 
                   [source_pos[1], target_pos[1]], 
                   'gray', alpha=alpha, linewidth=1, zorder=1)
            
            # 添加关系标签
            mid_x = (source_pos[0] + target_pos[0]) / 2
            mid_y = (source_pos[1] + target_pos[1]) / 2
            ax.text(mid_x, mid_y, edge.relationship, 
                   fontsize=8, alpha=0.7, ha='center', va='center')
        
        # 绘制节点
        for node in self.threat_nodes:
            node_pos = pos[node.id]
            color = self.level_colors[node.level]
            icon = self.type_icons[node.threat_type]
            
            # 节点大小基于威胁等级
            size_map = {
                ThreatLevel.LOW: 300,
                ThreatLevel.MEDIUM: 500,
                ThreatLevel.HIGH: 800,
                ThreatLevel.CRITICAL: 1200
            }
            node_size = size_map[node.level]
            
            # 绘制节点
            circle = plt.Circle(node_pos, node_size/10000, 
                              color=color, alpha=0.8, zorder=2)
            ax.add_patch(circle)
            
            # 添加图标
            ax.text(node_pos[0], node_pos[1], icon, 
                   fontsize=12, ha='center', va='center', zorder=3)
            
            # 添加威胁类型标签
            ax.text(node_pos[0], node_pos[1] - 0.15, 
                   node.threat_type.value.replace('_', '\n'),
                   fontsize=8, ha='center', va='top', zorder=3)
        
        # 添加图例
        self._add_legend(ax)
        
        # 添加标题和统计信息
        self._add_title_and_stats(ax)
        
        # 设置图形属性
        ax.set_xlim(-1.5, 1.5)
        ax.set_ylim(-1.5, 1.5)
        ax.axis('off')
        ax.set_facecolor('#f8f9fa')
        
        # 保存图片
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight', pad_inches=0.1, 
                   facecolor='#f8f9fa')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return image_base64
    
    def _add_legend(self, ax):
        """添加图例"""
        legend_elements = []
        
        # 威胁等级图例
        for level, color in self.level_colors.items():
            legend_elements.append(patches.Patch(color=color, label=level.value.upper()))
        
        # 威胁类型图例
        type_legend = []
        for threat_type, icon in self.type_icons.items():
            type_legend.append(f"{icon} {threat_type.value.replace('_', ' ').title()}")
        
        # 添加图例到图形
        legend1 = ax.legend(handles=legend_elements, loc='upper left', 
                           title='威胁等级', frameon=True, fancybox=True, shadow=True)
        legend2 = ax.legend(type_legend, loc='upper right', 
                           title='威胁类型', frameon=True, fancybox=True, shadow=True)
        
        # 添加第二个图例
        ax.add_artist(legend1)
    
    def _add_title_and_stats(self, ax):
        """添加标题和统计信息"""
        # 计算统计信息
        total_threats = len(self.threat_nodes)
        level_counts = {}
        for node in self.threat_nodes:
            level_counts[node.level] = level_counts.get(node.level, 0) + 1
        
        # 添加标题
        title = f"🔍 威胁分析力导向图"
        ax.text(0, 1.3, title, fontsize=16, fontweight='bold', 
               ha='center', va='top', transform=ax.transAxes)
        
        # 添加统计信息
        stats_text = f"总威胁数: {total_threats}\n"
        for level, count in level_counts.items():
            stats_text += f"{level.value.upper()}: {count} "
        
        ax.text(0, -1.3, stats_text, fontsize=10, ha='center', va='bottom',
               bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.8),
               transform=ax.transAxes)
    
    def generate_threat_summary(self) -> Dict:
        """生成威胁摘要"""
        if not self.threat_nodes:
            return {
                "total_threats": 0,
                "risk_level": "SAFE",
                "recommendations": ["内容安全，无需特别关注"],
                "threat_breakdown": {}
            }
        
        # 计算威胁统计
        total_threats = len(self.threat_nodes)
        level_counts = {}
        type_counts = {}
        
        for node in self.threat_nodes:
            level_counts[node.level] = level_counts.get(node.level, 0) + 1
            type_counts[node.threat_type] = type_counts.get(node.threat_type, 0) + 1
        
        # 计算总体风险等级
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

# 便捷函数
def create_threat_visualization(content: str) -> Dict:
    """
    创建威胁可视化
    
    Args:
        content: 待分析的内容
        
    Returns:
        Dict: 包含图片和威胁分析结果
    """
    visualizer = ThreatGraphVisualizer()
    
    # 分析内容
    threats = visualizer.analyze_content(content)
    
    # 创建关系
    visualizer.create_threat_relationships()
    
    # 生成图片
    image_base64 = visualizer.generate_force_directed_graph()
    
    # 生成摘要
    summary = visualizer.generate_threat_summary()
    
    return {
        "image": image_base64,
        "threats": threats,
        "summary": summary,
        "graph_data": {
            "nodes": len(visualizer.threat_nodes),
            "edges": len(visualizer.threat_edges)
        }
    }
