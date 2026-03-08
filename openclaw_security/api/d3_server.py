"""
OpenClaw D3.js 力导向图API服务器
提供交互式D3.js威胁可视化服务
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import logging
from datetime import datetime
import os
from pathlib import Path

from ..visualization.d3_force_graph import D3ForceGraphGenerator, create_d3_force_graph, save_d3_graph

def create_d3_server():
    """创建D3.js可视化服务器"""
    app = Flask(__name__)
    CORS(app)
    
    # 配置日志
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # 创建输出目录
    output_dir = Path("d3_graphs")
    output_dir.mkdir(exist_ok=True)
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """健康检查"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '2.2.0',
            'features': {
                'd3_force_graph': True,
                'interactive_visualization': True,
                'export_support': True
            }
        })
    
    @app.route('/generate', methods=['POST'])
    def generate_d3_graph():
        """
        生成D3.js力导向图
        """
        try:
            data = request.get_json()
            
            if not data or 'content' not in data:
                return jsonify({
                    'error': 'Missing required field: content',
                    'code': 400
                }), 400
            
            content = data['content']
            title = data.get('title', '威胁力导向图')
            save_to_file = data.get('save_to_file', False)
            
            # 生成D3.js图表
            html_content = create_d3_force_graph(content, title)
            
            response = {
                'success': True,
                'content': content,
                'html_content': html_content,
                'title': title,
                'timestamp': datetime.now().isoformat()
            }
            
            # 保存到文件
            if save_to_file:
                filename = f"graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                filepath = output_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                response['saved_file'] = str(filepath)
                response['file_url'] = f"/graphs/{filename}"
            
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"D3 graph generation error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/generate_and_save', methods=['POST'])
    def generate_and_save():
        """
        生成并保存D3.js力导向图
        """
        try:
            data = request.get_json()
            
            if not data or 'content' not in data:
                return jsonify({
                    'error': 'Missing required field: content',
                    'code': 400
                }), 400
            
            content = data['content']
            filename = data.get('filename', f"threat_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            title = data.get('title', '威胁力导向图')
            
            # 生成并保存
            filepath = save_d3_graph(content, str(output_dir / filename), title)
            
            return jsonify({
                'success': True,
                'content': content,
                'filename': filename,
                'filepath': filepath,
                'file_url': f"/graphs/{filename}",
                'title': title,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"D3 graph save error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/graphs/<filename>')
    def serve_graph(filename):
        """提供生成的HTML文件"""
        try:
            return send_from_directory(str(output_dir), filename)
        except FileNotFoundError:
            return jsonify({'error': 'File not found', 'code': 404}), 404
    
    @app.route('/graphs')
    def list_graphs():
        """列出所有生成的图表文件"""
        try:
            graphs = []
            for filepath in output_dir.glob("*.html"):
                stat = filepath.stat()
                graphs.append({
                    'filename': filepath.name,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'url': f"/graphs/{filepath.name}"
                })
            
            # 按创建时间排序
            graphs.sort(key=lambda x: x['created'], reverse=True)
            
            return jsonify({
                'success': True,
                'graphs': graphs,
                'total_count': len(graphs),
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"List graphs error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/demo')
    def demo_d3_graphs():
        """演示D3.js力导向图"""
        try:
            demo_cases = [
                {
                    'name': 'SQL注入攻击',
                    'content': "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
                    'description': '检测SQL注入威胁'
                },
                {
                    'name': 'XSS攻击',
                    'content': "<script>alert('XSS攻击')</script>",
                    'description': '检测跨站脚本威胁'
                },
                {
                    'name': '复合威胁',
                    'content': "用户输入：admin' OR '1'='1'; <script>document.cookie</script>",
                    'description': '检测多种威胁类型'
                },
                {
                    'name': '敏感信息',
                    'content': "API密钥：sk-1234567890abcdef，密码：admin123",
                    'description': '检测敏感数据泄露'
                },
                {
                    'name': '正常内容',
                    'content': "这是一个安全的文本内容，不包含任何威胁。",
                    'description': '安全内容测试'
                }
            ]
            
            demo_results = []
            
            for i, case in enumerate(demo_cases):
                try:
                    # 生成HTML内容
                    html_content = create_d3_force_graph(case['content'], f"演示 {i+1}: {case['name']}")
                    
                    # 保存文件
                    filename = f"demo_{i+1}_{case['name'].replace(' ', '_')}.html"
                    filepath = str(output_dir / filename)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    
                    demo_results.append({
                        'demo_id': i + 1,
                        'name': case['name'],
                        'content': case['content'],
                        'description': case['description'],
                        'filename': filename,
                        'url': f"/graphs/{filename}",
                        'html_content': html_content
                    })
                    
                except Exception as e:
                    demo_results.append({
                        'demo_id': i + 1,
                        'name': case['name'],
                        'content': case['content'],
                        'description': case['description'],
                        'error': str(e)
                    })
            
            return jsonify({
                'success': True,
                'title': 'D3.js 威胁力导向图演示',
                'description': '交互式威胁可视化演示',
                'results': demo_results,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"D3 demo error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/template')
    def get_template():
        """获取D3.js模板"""
        template = {
            'title': 'D3.js 威胁力导向图模板',
            'description': '用于展示威胁关系的交互式图表',
            'features': [
                '交互式节点拖拽',
                '缩放和平移',
                '悬停提示信息',
                '节点点击详情',
                '力导向布局',
                '响应式设计',
                '导出图片功能'
            ],
            'usage': {
                'generate': 'POST /generate - 生成图表',
                'save': 'POST /generate_and_save - 生成并保存',
                'list': 'GET /graphs - 列出图表文件',
                'view': 'GET /graphs/:filename - 查看图表',
                'demo': 'GET /demo - 演示示例'
            },
            'example_request': {
                'method': 'POST',
                'url': '/generate',
                'headers': {'Content-Type': 'application/json'},
                'body': {
                    'content': 'SELECT * FROM users; DROP TABLE users;',
                    'title': 'SQL注入威胁分析',
                    'save_to_file': True
                }
            }
        }
        
        return jsonify(template)
    
    @app.route('/')
    def index():
        """首页"""
        return jsonify({
            'name': 'OpenClaw D3.js 威胁可视化服务器',
            'version': '2.2.0',
            'description': '提供交互式D3.js力导向图威胁可视化服务',
            'endpoints': {
                'health': 'GET /health - 健康检查',
                'generate': 'POST /generate - 生成图表',
                'save': 'POST /generate_and_save - 生成并保存',
                'graphs': 'GET /graphs - 列出图表',
                'view': 'GET /graphs/:filename - 查看图表',
                'demo': 'GET /demo - 演示示例',
                'template': 'GET /template - 获取模板信息'
            },
            'features': [
                '交互式力导向图',
                '实时威胁检测',
                '多种威胁类型',
                '风险评估',
                '导出功能',
                '响应式设计'
            ]
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
    """启动D3.js服务器"""
    app = create_d3_server()
    print("🎨 OpenClaw D3.js 威胁可视化服务器启动...")
    print("📊 功能特性:")
    print("  ✅ 交互式D3.js力导向图")
    print("  ✅ 实时威胁检测")
    print("  ✅ 节点拖拽和缩放")
    print("  ✅ 悬停提示信息")
    print("  ✅ 导出图片功能")
    print("  ✅ 响应式设计")
    print("\n📋 可用端点:")
    print("  GET  / - 服务信息")
    print("  GET  /health - 健康检查")
    print("  POST /generate - 生成图表")
    print("  POST /generate_and_save - 生成并保存")
    print("  GET  /graphs - 列出图表")
    print("  GET  /graphs/:filename - 查看图表")
    print("  GET  /demo - 演示示例")
    print("  GET  /template - 获取模板")
    
    app.run(host='0.0.0.0', port=5002, debug=True)

if __name__ == '__main__':
    main()
