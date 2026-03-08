"""
OpenClaw 威胁可视化API服务器
提供威胁力导向图生成服务，不拦截输出
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from datetime import datetime
import base64
from typing import Dict, Any

from ..visualization.threat_graph import create_threat_visualization, ThreatLevel
from ..core.security_enhancements import EnhancedSecurityFilter, SecurityContext

def create_visualization_server():
    """创建可视化API服务器"""
    app = Flask(__name__)
    CORS(app)
    
    # 配置日志
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # 初始化安全过滤器（用于威胁检测）
    security_filter = EnhancedSecurityFilter()
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """健康检查"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '2.1.0',
            'features': {
                'threat_visualization': True,
                'force_directed_graph': True,
                'no_blocking': True
            }
        })
    
    @app.route('/visualize', methods=['POST'])
    def visualize_threats():
        """
        威胁可视化接口
        不拦截内容，仅生成威胁分析图
        """
        try:
            data = request.get_json()
            
            if not data or 'content' not in data:
                return jsonify({
                    'error': 'Missing required field: content',
                    'code': 400
                }), 400
            
            content = data['content']
            user_id = data.get('user_id', 'anonymous')
            options = data.get('options', {})
            
            # 创建安全上下文（用于记录）
            context = SecurityContext(
                user_id=user_id,
                session_id=request.headers.get('X-Request-ID', ''),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            
            # 生成威胁可视化
            result = create_threat_visualization(content)
            
            # 构建响应
            response = {
                'success': True,
                'content': content,  # 原始内容，不修改
                'visualization': {
                    'image': result['image'],
                    'format': 'base64_png',
                    'nodes': result['graph_data']['nodes'],
                    'edges': result['graph_data']['edges']
                },
                'threat_analysis': {
                    'total_threats': result['summary']['total_threats'],
                    'risk_level': result['summary']['risk_level'],
                    'risk_score': result['summary']['risk_score'],
                    'recommendations': result['summary']['recommendations'],
                    'threat_breakdown': result['summary']['threat_breakdown']
                },
                'timestamp': datetime.now().isoformat(),
                'processing_mode': 'visualization_only'  # 明确表示仅可视化，不拦截
            }
            
            # 添加详细信息（如果请求）
            if options.get('include_details', False):
                response['threat_details'] = [
                    {
                        'id': threat.id,
                        'type': threat.threat_type.value,
                        'level': threat.level.value,
                        'content': threat.content,
                        'position': threat.position,
                        'confidence': threat.confidence,
                        'description': threat.description
                    }
                    for threat in result['threats']
                ]
            
            # 记录可视化事件（不记录为安全威胁）
            logger.info(f"Threat visualization generated for user {user_id}: "
                       f"{result['summary']['total_threats']} threats detected")
            
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"Visualization error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/visualize/batch', methods=['POST'])
    def visualize_batch():
        """批量威胁可视化"""
        try:
            data = request.get_json()
            
            if not data or 'contents' not in data:
                return jsonify({
                    'error': 'Missing required field: contents',
                    'code': 400
                }), 400
            
            contents = data['contents']
            user_id = data.get('user_id', 'anonymous')
            options = data.get('options', {})
            
            if not isinstance(contents, list):
                return jsonify({
                    'error': 'contents must be a list',
                    'code': 400
                }), 400
            
            # 限制批量大小
            if len(contents) > 10:
                return jsonify({
                    'error': 'Batch size cannot exceed 10 items',
                    'code': 400
                }), 400
            
            results = []
            total_threats = 0
            
            for i, content in enumerate(contents):
                try:
                    # 生成威胁可视化
                    viz_result = create_threat_visualization(content)
                    
                    result = {
                        'index': i,
                        'content': content,
                        'visualization': {
                            'image': viz_result['image'],
                            'nodes': viz_result['graph_data']['nodes'],
                            'edges': viz_result['graph_data']['edges']
                        },
                        'threat_analysis': viz_result['summary']
                    }
                    
                    results.append(result)
                    total_threats += viz_result['summary']['total_threats']
                    
                except Exception as e:
                    results.append({
                        'index': i,
                        'content': content,
                        'error': str(e),
                        'visualization': None,
                        'threat_analysis': None
                    })
            
            return jsonify({
                'success': True,
                'results': results,
                'summary': {
                    'total_contents': len(contents),
                    'total_threats': total_threats,
                    'processed_count': len(results),
                    'timestamp': datetime.now().isoformat()
                }
            })
            
        except Exception as e:
            logger.error(f"Batch visualization error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/analyze', methods=['POST'])
    def analyze_only():
        """
        仅威胁分析，不生成图片
        用于快速威胁评估
        """
        try:
            data = request.get_json()
            
            if not data or 'content' not in data:
                return jsonify({
                    'error': 'Missing required field: content',
                    'code': 400
                }), 400
            
            content = data['content']
            
            # 生成威胁分析
            result = create_threat_visualization(content)
            
            return jsonify({
                'success': True,
                'content': content,
                'threat_analysis': result['summary'],
                'threat_details': [
                    {
                        'id': threat.id,
                        'type': threat.threat_type.value,
                        'level': threat.level.value,
                        'content': threat.content,
                        'position': threat.position,
                        'confidence': threat.confidence,
                        'description': threat.description
                    }
                    for threat in result['threats']
                ],
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/export/image', methods=['POST'])
    def export_image():
        """
        导出威胁图片为文件
        返回可直接下载的图片
        """
        try:
            data = request.get_json()
            
            if not data or 'content' not in data:
                return jsonify({
                    'error': 'Missing required field: content',
                    'code': 400
                }), 400
            
            content = data['content']
            format_type = data.get('format', 'png')
            size = data.get('size', 'medium')  # small, medium, large
            
            # 根据大小设置图片尺寸
            size_map = {
                'small': (800, 600),
                'medium': (1200, 800),
                'large': (1600, 1000)
            }
            
            width, height = size_map.get(size, (1200, 800))
            
            # 生成威胁可视化
            result = create_threat_visualization(content)
            
            # 返回图片数据
            return jsonify({
                'success': True,
                'image': result['image'],
                'format': f'base64_{format_type}',
                'size': f'{width}x{height}',
                'filename': f'threat_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{format_type}'
            })
            
        except Exception as e:
            logger.error(f"Export error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/demo', methods=['GET'])
    def demo_visualization():
        """
        演示威胁可视化
        返回预设的威胁示例分析
        """
        demo_contents = [
            "用户输入：SELECT * FROM users WHERE id = 1; DROP TABLE users;",
            "脚本内容：<script>alert('XSS攻击')</script>",
            "路径访问：../../../etc/passwd",
            "敏感信息：API密钥sk-1234567890abcdef，密码admin123",
            "正常内容：这是一个安全的文本内容。"
        ]
        
        results = []
        for i, content in enumerate(demo_contents):
            try:
                viz_result = create_threat_visualization(content)
                
                result = {
                    'demo_id': i + 1,
                    'content': content,
                    'visualization': {
                        'image': viz_result['image'],
                        'nodes': viz_result['graph_data']['nodes'],
                        'edges': viz_result['graph_data']['edges']
                    },
                    'threat_analysis': viz_result['summary']
                }
                results.append(result)
                
            except Exception as e:
                results.append({
                    'demo_id': i + 1,
                    'content': content,
                    'error': str(e)
                })
        
        return jsonify({
            'success': True,
            'title': '威胁可视化演示',
            'description': '展示不同类型威胁的可视化效果',
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found', 'code': 404}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error', 'code': 500}), 500
    
    return app

def main():
    """启动可视化服务器"""
    app = create_visualization_server()
    print("🎨 OpenClaw 威胁可视化服务器启动...")
    print("📊 功能特性:")
    print("  ✅ 威胁力导向图生成")
    print("  ✅ 不拦截输出，仅可视化")
    print("  ✅ 多种威胁类型检测")
    print("  ✅ 实时风险评估")
    print("  ✅ 批量处理支持")
    print("\n📋 可用端点:")
    print("  GET  /health - 健康检查")
    print("  POST /visualize - 威胁可视化")
    print("  POST /visualize/batch - 批量可视化")
    print("  POST /analyze - 仅威胁分析")
    print("  POST /export/image - 导出图片")
    print("  GET  /demo - 演示示例")
    
    app.run(host='0.0.0.0', port=5001, debug=True)

if __name__ == '__main__':
    main()
