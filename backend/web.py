"""
AgentGuard - Web API 服务 (FastAPI)
提供网站安全扫描 API、报告查看、邮件通知等功能
部署到 Railway（Docker 容器化）
"""

import asyncio
import os
import time
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scan import (
    Scanner, ScanResult, ScanStatus, SecurityFinding, RiskLevel,
    init_db, save_scan_result, get_latest_scan, get_db_connection,
    send_scan_email, generate_html_report,
    get_cached_result, cache_result, SCAN_CACHE_TTL
)

# ==================== 日志配置 ====================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("agentguard")

# ==================== Pydantic 模型 ====================

class ScanRequest(BaseModel):
    url: str = Field(..., description="要扫描的网站 URL", example="https://example.com")
    email: str = Field(None, description="接收报告的邮箱地址（可选）")

class ScanResponse(BaseModel):
    scan_id: int
    url: str
    domain: str
    status: str
    risk_level: str
    scan_time: float
    findings_count: int
    message: str

class HealthResponse(BaseModel):
    status: str
    version: str = "2.0.0"
    uptime: float

# ==================== 全局状态 ====================

app_startup_time = time.time()
scanner = Scanner(timeout=10)
active_scans: dict = {}  # scan_id -> asyncio.Task

# CORS 配置
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://globalxyz.xyz,https://www.globalxyz.xyz")
origins = [origin.strip() for origin in CORS_ORIGINS.split(",")]

# ==================== 生命周期 ====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用启动/关闭事件"""
    # 启动时初始化
    logger.info("AgentGuard v2.0 启动中...")
    try:
        init_db()
        logger.info("数据库初始化完成")
    except Exception as e:
        logger.warning(f"数据库初始化失败（可能还未连接到 Railway PostgreSQL）: {e}")
    
    yield
    
    # 关闭时清理
    logger.info("AgentGuard 关闭中...")
    # 取消所有活跃的异步扫描
    for task in active_scans.values():
        task.cancel()
    logger.info("AgentGuard 已关闭")

# ==================== 应用实例 ====================

app = FastAPI(
    title="AgentGuard API",
    description="网站安全扫描 SaaS 服务",
    version="2.0.0",
    lifespan=lifespan
)

# CORS 中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== 工具函数 ====================

def normalize_url(url: str) -> str:
    """规范化 URL"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def extract_domain(url: str) -> str:
    """从 URL 提取域名"""
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc

def validate_url(url: str) -> bool:
    """验证 URL 格式"""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False

# ==================== API 路由 ====================

@app.get("/health", response_model=HealthResponse, tags=["系统"])
async def health_check():
    """健康检查端点"""
    # 测试数据库连接
    db_ok = False
    try:
        conn = get_db_connection()
        conn.close()
        db_ok = True
    except Exception:
        pass
    
    return HealthResponse(
        status="healthy" if db_ok else "degraded",
        uptime=time.time() - app_startup_time
    )

@app.post("/api/scan", response_model=ScanResponse, tags=["扫描"])
async def scan_website(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    发起网站安全扫描
    
    - **url**: 要扫描的网站 URL（支持不带协议的域名）
    - **email**: 可选，接收报告邮件的地址
    """
    # 验证 URL
    url = normalize_url(request.url)
    if not validate_url(url):
        raise HTTPException(status_code=400, detail="无效的 URL 格式")
    
    domain = extract_domain(url)
    
    # 检查缓存
    cached = get_cached_result(url)
    if cached:
        logger.info(f"返回缓存结果: {domain}")
        return ScanResponse(
            scan_id=-1,
            url=url,
            domain=domain,
            status=cached.status.value,
            risk_level=cached.get_overall_risk_level(),
            scan_time=cached.scan_time,
            findings_count=len([f for f in cached.findings if f.risk_level != RiskLevel.PASS]),
            message="返回缓存结果（24小时内扫描）"
        )
    
    # 执行扫描
    logger.info(f"开始扫描: {domain}")
    result = await scanner.scan(url)
    
    # 保存结果
    try:
        scan_id = save_scan_result(result)
    except Exception as e:
        logger.warning(f"数据库保存失败，跳过: {e}")
        scan_id = -1
    
    # 缓存结果
    cache_result(url, result)
    
    # 异步发送邮件
    if request.email and result.status == ScanStatus.COMPLETED:
        background_tasks.add_task(
            send_scan_email, request.email, domain, result
        )
    
    # 返回响应
    return ScanResponse(
        scan_id=scan_id,
        url=url,
        domain=domain,
        status=result.status.value,
        risk_level=result.get_overall_risk_level(),
        scan_time=result.scan_time,
        findings_count=len([f for f in result.findings if f.risk_level != RiskLevel.PASS]),
        message=f"扫描完成，发现 {len([f for f in result.findings if f.risk_level != RiskLevel.PASS])} 个问题"
    )

@app.get("/api/scan/{domain}", tags=["扫描"])
async def get_scan_result(domain: str):
    """
    获取指定域名的最新扫描结果
    
    - **domain**: 域名（如 example.com）
    """
    result = get_latest_scan(domain)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"未找到 {domain} 的扫描结果，请先发起扫描"
        )
    
    return {
        "url": result.url,
        "domain": result.domain,
        "ip_address": result.ip_address,
        "status_code": result.status_code,
        "status": result.status.value,
        "risk_level": result.get_overall_risk_level(),
        "scan_time": result.scan_time,
        "findings": [
            {
                "category": f.category,
                "title": f.title,
                "risk_level": f.risk_level.value,
                "description": f.description,
                "recommendation": f.recommendation
            }
            for f in result.findings
        ],
        "created_at": None  # 简化版，暂不返回数据库时间
    }

@app.get("/api/report/{domain}", response_class=HTMLResponse, tags=["报告"])
async def get_html_report(domain: str):
    """
    获取指定域名的 HTML 格式扫描报告
    
    可直接在浏览器中查看，也可通过邮件发送
    """
    result = get_latest_scan(domain)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"未找到 {domain} 的扫描结果，请先发起扫描"
        )
    
    html = generate_html_report(domain, result)
    return html

@app.get("/api/history", tags=["扫描"])
async def get_scan_history(limit: int = 10):
    """
    获取最近的扫描历史记录
    
    - **limit**: 返回条数（默认 10）
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT url, domain, status_code, status, risk_level, 
                   scan_time, created_at
            FROM scan_results
            WHERE status = 'completed'
            ORDER BY created_at DESC
            LIMIT %s;
        """, (limit,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        return {
            "total": len(rows),
            "scans": [
                {
                    "url": r[0],
                    "domain": r[1],
                    "status_code": r[2],
                    "status": r[3],
                    "risk_level": r[4],
                    "scan_time": r[5],
                    "created_at": str(r[6]) if r[6] else None
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.warning(f"查询历史记录失败: {e}")
        return {"total": 0, "scans": []}

# ==================== 前端页面 ====================

@app.get("/", response_class=HTMLResponse, tags=["前端"])
async def landing_page():
    """着陆页 - 简洁的扫描入口"""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AgentGuard - 网站安全扫描</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #fff;
            }
            .container {
                text-align: center;
                max-width: 600px;
                padding: 40px 20px;
            }
            .logo {
                font-size: 48px;
                margin-bottom: 10px;
            }
            h1 {
                font-size: 36px;
                margin-bottom: 10px;
                background: linear-gradient(90deg, #667eea, #764ba2);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            .subtitle {
                color: #aaa;
                font-size: 16px;
                margin-bottom: 40px;
            }
            .input-group {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
            }
            input[type="text"] {
                flex: 1;
                padding: 14px 20px;
                border: 2px solid rgba(255,255,255,0.1);
                border-radius: 12px;
                background: rgba(255,255,255,0.05);
                color: #fff;
                font-size: 16px;
                outline: none;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus {
                border-color: #667eea;
            }
            input[type="text"]::placeholder {
                color: #666;
            }
            button {
                padding: 14px 28px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #fff;
                border: none;
                border-radius: 12px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, opacity 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
                opacity: 0.9;
            }
            button:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none;
            }
            .result {
                margin-top: 30px;
                padding: 20px;
                border-radius: 12px;
                background: rgba(255,255,255,0.05);
                display: none;
            }
            .result.show { display: block; }
            .risk-badge {
                display: inline-block;
                padding: 6px 16px;
                border-radius: 20px;
                font-weight: 600;
                font-size: 14px;
                margin: 10px 0;
            }
            .risk-critical { background: #dc3545; }
            .risk-high { background: #fd7e14; }
            .risk-medium { background: #ffc107; color: #333; }
            .risk-low { background: #17a2b8; }
            .risk-pass { background: #28a745; }
            .stats {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 15px;
                margin: 20px 0;
            }
            .stat-item {
                background: rgba(255,255,255,0.05);
                padding: 15px;
                border-radius: 8px;
            }
            .stat-value {
                font-size: 24px;
                font-weight: 700;
            }
            .stat-label {
                font-size: 12px;
                color: #888;
                margin-top: 4px;
            }
            .features {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
                margin-top: 40px;
                text-align: left;
            }
            .feature {
                background: rgba(255,255,255,0.03);
                padding: 15px;
                border-radius: 8px;
                border: 1px solid rgba(255,255,255,0.05);
            }
            .feature-icon { font-size: 24px; margin-bottom: 8px; }
            .feature-title { font-weight: 600; margin-bottom: 4px; }
            .feature-desc { font-size: 13px; color: #888; }
            .spinner {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(255,255,255,0.3);
                border-radius: 50%;
                border-top-color: #fff;
                animation: spin 1s linear infinite;
                margin-right: 8px;
                vertical-align: middle;
            }
            @keyframes spin { to { transform: rotate(360deg); } }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🛡️</div>
            <h1>AgentGuard</h1>
            <p class="subtitle">网站安全扫描服务 — 8 大类风险检测，一键生成专业报告</p>
            
            <div class="input-group">
                <input type="text" id="urlInput" placeholder="输入网站地址，如 example.com" />
                <button onclick="startScan()" id="scanBtn">开始扫描</button>
            </div>
            
            <div class="result" id="result">
                <div id="resultContent"></div>
            </div>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">🔒</div>
                    <div class="feature-title">SSL/TLS 检测</div>
                    <div class="feature-desc">证书有效性、协议版本、加密强度</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">📋</div>
                    <div class="feature-title">HTTP 头安全</div>
                    <div class="feature-desc">CSP、HSTS、X-Frame-Options 等</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">🔍</div>
                    <div class="feature-title">敏感文件扫描</div>
                    <div class="feature-desc">.env、wp-config、.git 等泄露检测</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">📧</div>
                    <div class="feature-title">邮件报告</div>
                    <div class="feature-desc">生成 HTML 格式专业报告并发送邮件</div>
                </div>
            </div>
        </div>
        
        <script>
            async function startScan() {
                const input = document.getElementById('urlInput');
                const btn = document.getElementById('scanBtn');
                const result = document.getElementById('result');
                const content = document.getElementById('resultContent');
                
                const url = input.value.trim();
                if (!url) {
                    input.focus();
                    return;
                }
                
                btn.disabled = true;
                btn.innerHTML = '<span class="spinner"></span>扫描中...';
                result.classList.remove('show');
                
                try {
                    const resp = await fetch('/api/scan', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({url: url})
                    });
                    
                    const data = await resp.json();
                    
                    const riskClass = 'risk-' + data.risk_level;
                    const findingsHtml = data.findings_count > 0 
                        ? `<p>发现 <strong>${data.findings_count}</strong> 个安全问题</p>`
                        : '<p style="color: #28a745;">✅ 未发现安全问题！</p>';
                    
                    content.innerHTML = `
                        <div class="risk-badge ${riskClass}">${data.risk_level.toUpperCase()}</div>
                        <div class="stats">
                            <div class="stat-item">
                                <div class="stat-value">${data.findings_count}</div>
                                <div class="stat-label">发现问题</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">${data.scan_time.toFixed(1)}s</div>
                                <div class="stat-label">扫描耗时</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">${data.domain}</div>
                                <div class="stat-label">扫描目标</div>
                            </div>
                        </div>
                        ${findingsHtml}
                        <p style="margin-top: 15px; font-size: 13px; color: #888;">${data.message}</p>
                    `;
                    result.classList.add('show');
                } catch (err) {
                    content.innerHTML = `<p style="color: #dc3545;">扫描失败: ${err.message}</p>`;
                    result.classList.add('show');
                }
                
                btn.disabled = false;
                btn.textContent = '开始扫描';
            }
            
            // 回车键触发扫描
            document.getElementById('urlInput').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') startScan();
            });
        </script>
    </body>
    </html>
    """)

# ==================== 启动入口 ====================

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    logger.info(f"启动 AgentGuard API 服务，端口: {port}")
    uvicorn.run(
        "web:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info"
    )
