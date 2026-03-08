"""
OpenClaw 安全过滤器 FastAPI 服务器
高性能异步 API 接口
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor

from ..core.filter import SecurityFilter, SecurityException
from ..core.config import SecurityLevel

# Pydantic 模型定义
class FilterRequest(BaseModel):
    content: str = Field(..., description="待过滤的内容")
    user_id: Optional[str] = Field("anonymous", description="用户ID")
    return_details: Optional[bool] = Field(False, description="是否返回详细信息")

class BatchFilterRequest(BaseModel):
    contents: List[str] = Field(..., description="待过滤的内容列表")
    user_id: Optional[str] = Field("anonymous", description="用户ID")
    return_details: Optional[bool] = Field(False, description="是否返回详细信息")

class SecurityCheckRequest(BaseModel):
    content: str = Field(..., description="待检查的内容")
    user_id: Optional[str] = Field("anonymous", description="用户ID")

def create_fastapi_app():
    """创建FastAPI应用"""
    app = FastAPI(
        title="OpenClaw Security Filter API",
        description="高性能数据安全分级过滤服务",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # 添加 CORS 中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 配置日志
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # 初始化安全过滤器
    security_filter = SecurityFilter(enable_audit=True)
    # 线程池用于CPU密集型任务
    executor = ThreadPoolExecutor(max_workers=4)
    
    # 全局统计（实际应用中应使用数据库）
    stats = {
        'total_requests': 0,
        'blocked_requests': 0,
        'masked_requests': 0,
        'watermarked_requests': 0,
        'total_risk_score': 0.0,
        'start_time': datetime.now()
    }
    
    def update_stats(result):
        """更新统计信息"""
        stats['total_requests'] += 1
        stats['total_risk_score'] += result.risk_score
        
        if result.is_blocked:
            stats['blocked_requests'] += 1
        elif result.action_taken == 'masked':
            stats['masked_requests'] += 1
        elif result.action_taken == 'watermarked':
            stats['watermarked_requests'] += 1
    
    async def filter_content_async(content: str, user_id: str = "anonymous"):
        """异步过滤内容"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            executor, security_filter.filter_content, content, user_id
        )
    
    @app.get("/health")
    async def health_check():
        """健康检查接口"""
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
    
    @app.post("/filter")
    async def filter_content_endpoint(request: FilterRequest):
        """内容过滤接口"""
        try:
            # 异步执行过滤
            result = await filter_content_async(request.content, request.user_id)
            
            # 更新统计
            update_stats(result)
            
            # 构建响应
            response = {
                'success': True,
                'filtered_content': result.filtered_content,
                'is_blocked': result.is_blocked,
                'action_taken': result.action_taken,
                'security_level': result.security_level.value if result.security_level else None,
                'risk_score': result.risk_score,
                'timestamp': datetime.now().isoformat()
            }
            
            # 如果需要详细信息
            if request.return_details:
                response.update({
                    'detected_patterns': result.detected_patterns,
                    'original_length': len(request.content),
                    'filtered_length': len(result.filtered_content)
                })
            
            return response
            
        except Exception as e:
            logger.error(f"Filter error: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/batch_filter")
    async def batch_filter_endpoint(request: BatchFilterRequest):
        """批量内容过滤接口"""
        try:
            if len(request.contents) > 100:  # 限制批量大小
                raise HTTPException(status_code=400, detail="Batch size cannot exceed 100 items")
            
            # 并发处理批量请求
            tasks = [
                filter_content_async(content, request.user_id) 
                for content in request.contents
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            processed_results = []
            blocked_count = 0
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    # 处理异常
                    processed_results.append({
                        'error': str(result),
                        'filtered_content': request.contents[i],
                        'is_blocked': True,
                        'action_taken': 'error'
                    })
                    blocked_count += 1
                else:
                    # 正常结果
                    response_item = {
                        'filtered_content': result.filtered_content,
                        'is_blocked': result.is_blocked,
                        'action_taken': result.action_taken,
                        'security_level': result.security_level.value if result.security_level else None,
                        'risk_score': result.risk_score
                    }
                    
                    if request.return_details:
                        response_item['detected_patterns'] = result.detected_patterns
                    
                    processed_results.append(response_item)
                    update_stats(result)
                    
                    if result.is_blocked:
                        blocked_count += 1
            
            return {
                'success': True,
                'results': processed_results,
                'total_count': len(request.contents),
                'blocked_count': blocked_count,
                'processed_count': len(processed_results),
                'timestamp': datetime.now().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Batch filter error: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/check_security")
    async def check_security_endpoint(request: SecurityCheckRequest):
        """安全检查接口（不修改内容，只返回安全评估）"""
        try:
            loop = asyncio.get_event_loop()
            
            # 异步执行检测
            detections = await loop.run_in_executor(
                executor, security_filter._detect_sensitive_data, request.content
            )
            risk_score = await loop.run_in_executor(
                executor, security_filter._calculate_risk_score, detections
            )
            
            # 确定最高安全等级
            highest_level = None
            for level in [SecurityLevel.L4_TOP_SECRET, SecurityLevel.L3_CONFIDENTIAL, SecurityLevel.L2_INTERNAL]:
                if detections[level]:
                    highest_level = level
                    break
            
            # 获取建议
            recommendations = _get_recommendations(highest_level)
            
            return {
                'success': True,
                'is_safe': highest_level is None or highest_level == SecurityLevel.L1_PUBLIC,
                'security_level': highest_level.value if highest_level else 'public',
                'risk_score': risk_score,
                'detected_patterns': {
                    level.value: patterns for level, patterns in detections.items() if patterns
                },
                'recommendations': recommendations,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Security check error: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/stats")
    async def get_stats():
        """获取统计信息接口"""
        try:
            uptime = datetime.now() - stats['start_time']
            avg_risk = stats['total_risk_score'] / stats['total_requests'] if stats['total_requests'] > 0 else 0
            
            return {
                'success': True,
                'stats': {
                    'total_requests': stats['total_requests'],
                    'blocked_requests': stats['blocked_requests'],
                    'masked_requests': stats['masked_requests'],
                    'watermarked_requests': stats['watermarked_requests'],
                    'average_risk_score': round(avg_risk, 2),
                    'uptime': str(uptime).split('.')[0]  # 去掉微秒
                },
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Stats error: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
    
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
    
    @app.get("/")
    async def root():
        """根路径，返回API信息"""
        return {
            "name": "OpenClaw Security Filter API",
            "version": "1.0.0",
            "description": "高性能数据安全分级过滤服务",
            "docs": "/docs",
            "health": "/health"
        }
    
    return app

def main():
    """FastAPI服务器主函数"""
    import uvicorn
    
    app = create_fastapi_app()
    print("🚀 OpenClaw Security Filter FastAPI Server Starting...")
    print("📊 Available endpoints:")
    print("  GET  / - API信息")
    print("  GET  /health - 健康检查")
    print("  GET  /docs - Swagger文档")
    print("  GET  /redoc - ReDoc文档")
    print("  POST /filter - 内容过滤")
    print("  POST /batch_filter - 批量过滤")
    print("  POST /check_security - 安全检查")
    print("  GET  /stats - 统计信息")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()
