"""
OpenClaw 安全过滤器 API 服务器
提供 REST API 接口供外部系统调用
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from datetime import datetime
from security_filter import SecurityFilter, SecurityException
from security_config import SecurityLevel

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 初始化安全过滤器
security_filter = SecurityFilter(enable_audit=True)

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/filter', methods=['POST'])
def filter_content():
    """
    内容过滤接口
    
    POST /filter
    {
        "content": "待过滤的内容",
        "user_id": "用户ID（可选）",
        "return_details": "是否返回详细信息（可选，默认false）"
    }
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
        return_details = data.get('return_details', False)
        
        # 执行安全过滤
        result = security_filter.filter_content(content, user_id)
        
        # 构建响应
        response = {
            'success': True,
            'filtered_content': result.filtered_content,
            'is_blocked': result.is_blocked,
            'action_taken': result.action_taken,
            'security_level': result.security_level.value if result.security_level else None,
            'risk_score': result.risk_score
        }
        
        # 如果需要详细信息
        if return_details:
            response.update({
                'detected_patterns': result.detected_patterns,
                'original_length': len(content),
                'filtered_length': len(result.filtered_content),
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Filter error: {str(e)}")
        return jsonify({
            'error': str(e),
            'code': 500
        }), 500

@app.route('/batch_filter', methods=['POST'])
def batch_filter():
    """
    批量内容过滤接口
    
    POST /batch_filter
    {
        "contents": ["内容1", "内容2", ...],
        "user_id": "用户ID（可选）",
        "return_details": "是否返回详细信息（可选，默认false）"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'contents' not in data:
            return jsonify({
                'error': 'Missing required field: contents',
                'code': 400
            }), 400
        
        contents = data['contents']
        user_id = data.get('user_id', 'anonymous')
        return_details = data.get('return_details', False)
        
        if not isinstance(contents, list):
            return jsonify({
                'error': 'contents must be a list',
                'code': 400
            }), 400
        
        # 批量处理
        results = []
        blocked_count = 0
        
        for content in contents:
            try:
                result = security_filter.filter_content(content, user_id)
                
                response_item = {
                    'filtered_content': result.filtered_content,
                    'is_blocked': result.is_blocked,
                    'action_taken': result.action_taken,
                    'security_level': result.security_level.value if result.security_level else None,
                    'risk_score': result.risk_score
                }
                
                if return_details:
                    response_item.update({
                        'detected_patterns': result.detected_patterns
                    })
                
                results.append(response_item)
                
                if result.is_blocked:
                    blocked_count += 1
                    
            except Exception as e:
                results.append({
                    'error': str(e),
                    'filtered_content': content,
                    'is_blocked': True,
                    'action_taken': 'error'
                })
        
        return jsonify({
            'success': True,
            'results': results,
            'total_count': len(contents),
            'blocked_count': blocked_count,
            'processed_count': len(contents),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Batch filter error: {str(e)}")
        return jsonify({
            'error': str(e),
            'code': 500
        }), 500

@app.route('/check_security', methods=['POST'])
def check_security():
    """
    安全检查接口（不修改内容，只返回安全评估）
    
    POST /check_security
    {
        "content": "待检查的内容",
        "user_id": "用户ID（可选）"
    }
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
        
        # 只检测，不修改内容
        detections = security_filter._detect_sensitive_data(content)
        risk_score = security_filter._calculate_risk_score(detections)
        
        # 确定最高安全等级
        highest_level = None
        for level in [SecurityLevel.L4_TOP_SECRET, SecurityLevel.L3_CONFIDENTIAL, SecurityLevel.L2_INTERNAL]:
            if detections[level]:
                highest_level = level
                break
        
        return jsonify({
            'success': True,
            'is_safe': highest_level is None or highest_level == SecurityLevel.L1_PUBLIC,
            'security_level': highest_level.value if highest_level else 'public',
            'risk_score': risk_score,
            'detected_patterns': {
                level.value: patterns for level, patterns in detections.items() if patterns
            },
            'recommendations': _get_recommendations(highest_level),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Security check error: {str(e)}")
        return jsonify({
            'error': str(e),
            'code': 500
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """
    获取统计信息接口
    """
    try:
        # 这里可以实现统计信息的获取逻辑
        # 目前返回模拟数据
        return jsonify({
            'success': True,
            'stats': {
                'total_requests': 0,
                'blocked_requests': 0,
                'masked_requests': 0,
                'watermarked_requests': 0,
                'average_risk_score': 0.0,
                'uptime': '0h 0m 0s'
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({
            'error': str(e),
            'code': 500
        }), 500

def _get_recommendations(security_level):
    """根据安全等级获取建议"""
    if not security_level or security_level == SecurityLevel.L1_PUBLIC:
        return ["内容安全，可以正常输出"]
    
    recommendations = []
    
    if security_level == SecurityLevel.L2_INTERNAL:
        recommendations.append("建议添加内部水印")
        recommendations.append("限制访问权限")
    elif security_level == SecurityLevel.L3_CONFIDENTIAL:
        recommendations.append("必须进行脱敏处理")
        recommendations.append("记录访问日志")
    elif security_level == SecurityLevel.L4_TOP_SECRET:
        recommendations.append("立即阻断输出")
        recommendations.append("触发安全告警")
        recommendations.append("联系安全管理员")
    
    return recommendations

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found', 'code': 404}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'code': 500}), 500

if __name__ == '__main__':
    print("🚀 OpenClaw Security Filter API Server Starting...")
    print("📊 Available endpoints:")
    print("  GET  /health - 健康检查")
    print("  POST /filter - 内容过滤")
    print("  POST /batch_filter - 批量过滤")
    print("  POST /check_security - 安全检查")
    print("  GET  /stats - 统计信息")
    print("\n🔗 Example usage:")
    print("  curl -X POST http://localhost:5000/filter -H 'Content-Type: application/json' -d '{\"content\":\"用户手机号13812345678\"}'")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
