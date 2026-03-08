"""
OpenClaw 增强安全API服务器
融合Sub2API的安全特性和我们的数据分级系统
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import logging
from datetime import datetime
import time
import hmac
import hashlib
from typing import Dict, Optional

from ..core.security_enhancements import (
    EnhancedSecurityFilter, 
    SecurityContext, 
    security_config,
    ThreatLevel
)
from ..core.filter import SecurityFilter

def create_enhanced_server(config=None):
    """创建增强安全API服务器"""
    app = Flask(__name__)
    CORS(app)
    
    # 配置日志
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # 初始化安全过滤器
    enhanced_filter = EnhancedSecurityFilter()
    original_filter = SecurityFilter()
    
    # API密钥验证中间件
    @app.before_request
    def authenticate_request():
        """API密钥验证中间件"""
        # 跳过健康检查等公开端点
        if request.endpoint in ['health_check', 'root']:
            return
        
        # 获取API密钥
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'error': 'Missing API key',
                'code': 401,
                'message': 'API key is required. Include it in X-API-Key header or api_key parameter.'
            }), 401
        
        # 验证API密钥
        key_info = enhanced_filter.validate_api_key(api_key)
        if not key_info:
            return jsonify({
                'error': 'Invalid API key',
                'code': 401,
                'message': 'The provided API key is invalid or has been revoked.'
            }), 401
        
        # 检查速率限制
        user_id = key_info['user_id']
        is_allowed, message = enhanced_filter.check_rate_limit(user_id, api_key)
        if not is_allowed:
            return jsonify({
                'error': 'Rate limit exceeded',
                'code': 429,
                'message': message
            }), 429
        
        # 创建安全上下文
        g.security_context = SecurityContext(
            user_id=user_id,
            session_id=request.headers.get('X-Request-ID', ''),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            request_count=key_info.get('usage_count', 0)
        )
        
        g.api_key_info = key_info
    
    @app.after_request
    def add_security_headers(response):
        """添加安全响应头"""
        if hasattr(g, 'security_context'):
            headers = enhanced_filter.create_security_headers(g.security_context)
            for key, value in headers.items():
                response.headers[key] = value
        
        return response
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """健康检查"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '2.0.0',
            'security_features': {
                'enhanced_filtering': True,
                'rate_limiting': True,
                'threat_detection': True,
                'api_key_management': True
            }
        })
    
    @app.route('/api/keys', methods=['POST'])
    def generate_api_key():
        """生成新的API密钥"""
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            permissions = data.get('permissions', ['read', 'filter'])
            
            if not user_id:
                return jsonify({
                    'error': 'Missing user_id',
                    'code': 400
                }), 400
            
            # 检查用户密钥数量限制
            user_keys = [k for k, v in enhanced_filter.api_keys.items() if v['user_id'] == user_id]
            max_keys = security_config.get_config('api_key_management', 'max_keys_per_user')
            
            if len(user_keys) >= max_keys:
                return jsonify({
                    'error': f'Maximum API keys per user exceeded ({max_keys})',
                    'code': 400
                }), 400
            
            # 生成新密钥
            api_key, key_hash = enhanced_filter.generate_secure_api_key(user_id, permissions)
            
            # 记录安全事件
            if hasattr(g, 'security_context'):
                enhanced_filter.audit_security_event('api_key_generated', g.security_context, {
                    'key_hash': key_hash,
                    'permissions': permissions
                })
            
            return jsonify({
                'success': True,
                'api_key': api_key,
                'permissions': permissions,
                'created_at': enhanced_filter.api_keys[api_key]['created_at']
            })
            
        except Exception as e:
            logger.error(f"API key generation error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/api/keys', methods=['GET'])
    def list_api_keys():
        """列出用户的API密钥"""
        try:
            if not hasattr(g, 'security_context'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            user_id = g.security_context.user_id
            user_keys = []
            
            for key, info in enhanced_filter.api_keys.items():
                if info['user_id'] == user_id:
                    user_keys.append({
                        'key_prefix': key[:20] + '...',
                        'created_at': info['created_at'],
                        'last_used': info['last_used'],
                        'usage_count': info['usage_count'],
                        'permissions': info['permissions']
                    })
            
            return jsonify({
                'success': True,
                'keys': user_keys,
                'total_count': len(user_keys)
            })
            
        except Exception as e:
            logger.error(f"API key list error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/filter', methods=['POST'])
    def enhanced_filter_content():
        """增强内容过滤接口"""
        try:
            data = request.get_json()
            
            if not data or 'content' not in data:
                return jsonify({
                    'error': 'Missing required field: content',
                    'code': 400
                }), 400
            
            content = data['content']
            return_details = data.get('return_details', False)
            enhanced_mode = data.get('enhanced_mode', True)  # 默认使用增强模式
            
            if not hasattr(g, 'security_context'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            # 应用增强安全过滤
            if enhanced_mode:
                result = enhanced_filter.apply_security_filters(content, g.security_context)
            else:
                # 使用原有过滤器
                original_result = original_filter.filter_content(content, g.security_context.user_id)
                result = {
                    'original_content': content,
                    'filtered_content': original_result.filtered_content,
                    'security_actions': [original_result.action_taken],
                    'threats_detected': [],
                    'risk_score': original_result.risk_score,
                    'blocked': original_result.is_blocked
                }
            
            # 构建响应
            response = {
                'success': True,
                'filtered_content': result['filtered_content'],
                'is_blocked': result['blocked'],
                'security_actions': result['security_actions'],
                'risk_score': result['risk_score'],
                'enhanced_mode': enhanced_mode,
                'timestamp': datetime.now().isoformat()
            }
            
            # 添加详细信息
            if return_details:
                response.update({
                    'original_length': len(content),
                    'filtered_length': len(result['filtered_content']),
                    'threats_detected': result['threats_detected'],
                    'api_key_info': {
                        'usage_count': g.api_key_info.get('usage_count', 0),
                        'permissions': g.api_key_info.get('permissions', [])
                    }
                })
            
            # 审计安全事件
            if result['blocked'] or result['risk_score'] > 50:
                enhanced_filter.audit_security_event('content_filtered', g.security_context, {
                    'risk_score': result['risk_score'],
                    'security_actions': result['security_actions'],
                    'threats_count': len(result['threats_detected'])
                })
            
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"Enhanced filter error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/security/scan', methods=['POST'])
    def security_scan():
        """安全扫描接口"""
        try:
            data = request.get_json()
            content = data.get('content', '')
            
            if not hasattr(g, 'security_context'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            # 执行安全扫描
            threats = enhanced_filter.detect_suspicious_patterns(content)
            
            # 评估整体安全状态
            risk_score = 0
            for threat in threats:
                if threat['threat_level'] == ThreatLevel.CRITICAL.value:
                    risk_score += 50
                elif threat['threat_level'] == ThreatLevel.HIGH.value:
                    risk_score += 30
                elif threat['threat_level'] == ThreatLevel.MEDIUM.value:
                    risk_score += 15
                else:
                    risk_score += 5
            
            security_status = 'safe'
            if risk_score > 80:
                security_status = 'dangerous'
            elif risk_score > 50:
                security_status = 'suspicious'
            elif risk_score > 20:
                security_status = 'caution'
            
            return jsonify({
                'success': True,
                'security_status': security_status,
                'risk_score': risk_score,
                'threats_detected': threats,
                'recommendations': _get_security_recommendations(threats, risk_score),
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Security scan error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/security/metrics', methods=['GET'])
    def security_metrics():
        """获取安全指标"""
        try:
            if not hasattr(g, 'security_context'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            # 检查权限
            if 'admin' not in g.api_key_info.get('permissions', []):
                return jsonify({
                    'error': 'Admin permission required',
                    'code': 403
                }), 403
            
            metrics = enhanced_filter.get_security_metrics()
            return jsonify({
                'success': True,
                'metrics': metrics
            })
            
        except Exception as e:
            logger.error(f"Security metrics error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    @app.route('/security/config', methods=['GET', 'POST'])
    def security_configuration():
        """安全配置管理"""
        try:
            if not hasattr(g, 'security_context'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            if request.method == 'GET':
                # 获取当前配置（只返回非敏感信息）
                config = security_config.get_config()
                safe_config = {
                    "rate_limiting": {
                        "enabled": config["rate_limiting"]["enabled"],
                        "requests_per_hour": config["rate_limiting"]["requests_per_hour"]
                    },
                    "threat_detection": {
                        "enabled": config["threat_detection"]["enabled"],
                        "auto_block_threshold": config["threat_detection"]["auto_block_threshold"]
                    }
                }
                return jsonify({
                    'success': True,
                    'config': safe_config
                })
            
            elif request.method == 'POST':
                # 更新配置（需要管理员权限）
                if 'admin' not in g.api_key_info.get('permissions', []):
                    return jsonify({
                        'error': 'Admin permission required',
                        'code': 403
                    }), 403
                
                data = request.get_json()
                section = data.get('section')
                key = data.get('key')
                value = data.get('value')
                
                if not all([section, key, value is not None]):
                    return jsonify({
                        'error': 'Missing required fields: section, key, value',
                        'code': 400
                    }), 400
                
                security_config.update_config(section, key, value)
                
                # 记录配置变更
                enhanced_filter.audit_security_event('config_changed', g.security_context, {
                    'section': section,
                    'key': key,
                    'new_value': value
                })
                
                return jsonify({
                    'success': True,
                    'message': f'Configuration updated: {section}.{key}'
                })
                
        except Exception as e:
            logger.error(f"Security config error: {str(e)}")
            return jsonify({
                'error': str(e),
                'code': 500
            }), 500
    
    def _get_security_recommendations(threats, risk_score):
        """获取安全建议"""
        recommendations = []
        
        if risk_score > 80:
            recommendations.append("立即阻止此内容，风险极高")
            recommendations.append("通知安全管理员")
        elif risk_score > 50:
            recommendations.append("需要人工审核")
            recommendations.append("增强监控级别")
        elif risk_score > 20:
            recommendations.append("记录详细日志")
            recommendations.append("考虑添加额外验证")
        
        # 基于威胁类型的建议
        threat_types = [t['threat_level'] for t in threats]
        if 'critical' in threat_types:
            recommendations.append("检测到关键威胁，立即处理")
        if 'high' in threat_types:
            recommendations.append("检测到高风险模式，建议阻止")
        if 'medium' in threat_types:
            recommendations.append("检测到可疑模式，需要关注")
        
        return recommendations
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found', 'code': 404}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error', 'code': 500}), 500
    
    return app

def main():
    """启动增强安全服务器"""
    app = create_enhanced_server()
    print("🚀 OpenClaw Enhanced Security API Server Starting...")
    print("🛡️  Security Features:")
    print("  ✅ API Key Authentication")
    print("  ✅ Rate Limiting")
    print("  ✅ Threat Detection")
    print("  ✅ Enhanced Content Filtering")
    print("  ✅ Security Auditing")
    print("  ✅ Security Headers")
    print("\n📊 Available endpoints:")
    print("  GET  /health - 健康检查")
    print("  POST /api/keys - 生成API密钥")
    print("  GET  /api/keys - 列出API密钥")
    print("  POST /filter - 增强内容过滤")
    print("  POST /security/scan - 安全扫描")
    print("  GET  /security/metrics - 安全指标")
    print("  GET/POST /security/config - 安全配置")
    
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    main()
