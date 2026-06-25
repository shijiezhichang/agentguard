"""
AgentGuard - 网站安全扫描引擎 v2.0
扫描目标网站的 SSL/TLS 配置、HTTP 安全头、常见漏洞、敏感文件泄露等
支持同步/异步扫描，结果存入 PostgreSQL
"""

import asyncio
import hashlib
import json
import os
import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from urllib.parse import urlparse
import urllib.request
import urllib.error
import certifi
import psycopg2
from psycopg2.extras import RealDictCursor


# ==================== 枚举类型 ====================

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ==================== 数据结构 ====================

@dataclass
class SecurityFinding:
    category: str
    title: str
    risk_level: RiskLevel
    description: str
    recommendation: str
    details: str = ""


@dataclass
class ScanResult:
    url: str
    domain: str
    ip_address: str
    status_code: int
    ssl_info: dict = field(default_factory=dict)
    http_headers: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    scan_time: float = 0.0
    status: ScanStatus = ScanStatus.PENDING
    error_message: str = ""

    def to_dict(self) -> dict:
        result = asdict(self)
        result["risk_level"] = self.get_overall_risk_level()
        return result

    def get_overall_risk_level(self) -> str:
        if not self.findings:
            return RiskLevel.PASS.value
        levels = [f.risk_level for f in self.findings if f.risk_level != RiskLevel.PASS]
        if RiskLevel.CRITICAL in levels:
            return RiskLevel.CRITICAL.value
        if RiskLevel.HIGH in levels:
            return RiskLevel.HIGH.value
        if RiskLevel.MEDIUM in levels:
            return RiskLevel.MEDIUM.value
        if RiskLevel.LOW in levels:
            return RiskLevel.LOW.value
        return RiskLevel.INFO.value


# ==================== 数据库操作 ====================

def get_db_connection():
    """获取 PostgreSQL 连接"""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL 环境变量未设置")
    return psycopg2.connect(database_url)


def init_db():
    """初始化数据库表"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            ip_address TEXT,
            status_code INTEGER,
            ssl_info JSONB,
            http_headers JSONB,
            findings JSONB,
            scan_time FLOAT,
            status TEXT DEFAULT 'pending',
            risk_level TEXT,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_scan_results_domain ON scan_results(domain);
        CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
        CREATE INDEX IF NOT EXISTS idx_scan_results_created ON scan_results(created_at DESC);
    """)
    conn.commit()
    cur.close()
    conn.close()


def save_scan_result(result: ScanResult):
    """保存扫描结果到数据库"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scan_results (
            url, domain, ip_address, status_code, ssl_info,
            http_headers, findings, scan_time, status, risk_level, error_message
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """, (
        result.url, result.domain, result.ip_address, result.status_code,
        json.dumps(result.ssl_info), json.dumps(result.http_headers),
        json.dumps([asdict(f) for f in result.findings]), result.scan_time,
        result.status.value, result.get_overall_risk_level(), result.error_message
    ))
    scan_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return scan_id


def get_latest_scan(domain: str) -> Optional[ScanResult]:
    """获取指定域名的最新扫描结果"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT * FROM scan_results
        WHERE domain = %s AND status = 'completed'
        ORDER BY created_at DESC LIMIT 1;
    """, (domain,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return _row_to_scan_result(row)


def _row_to_scan_result(row: dict) -> ScanResult:
    """将数据库行转换为 ScanResult 对象"""
    findings = []
    if row.get("findings"):
        for f in row["findings"]:
            findings.append(SecurityFinding(**f))
    return ScanResult(
        url=row["url"],
        domain=row["domain"],
        ip_address=row.get("ip_address", ""),
        status_code=row.get("status_code"),
        ssl_info=row.get("ssl_info", {}),
        http_headers=row.get("http_headers", {}),
        findings=findings,
        scan_time=row.get("scan_time", 0),
        status=ScanStatus(row["status"]),
        error_message=row.get("error_message", "")
    )


# ==================== 扫描引擎 ====================

class Scanner:
    """网站安全扫描器"""

    # 常见敏感文件/路径
    SENSITIVE_PATHS = [
        "/.env", "/wp-login.php", "/admin", "/administrator",
        "/phpmyadmin", "/.git/config", "/.svn/entries",
        "/backup.sql", "/database.sql", "/dump.sql",
        "/config.php", "/configuration.php", "/wp-config.php",
        "/server-status", "/server-info", "/.htaccess",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt", "/elmah.axd", "/trace.axd",
        "/web.config", "/composer.json", "/package.json",
        "/.DS_Store", "/Thumbs.db", "/phpinfo.php",
    ]

    # 危险的 HTTP 头
    MISSING_HEADERS = {
        "Content-Security-Policy": "内容安全策略，防止 XSS 攻击",
        "X-Content-Type-Options": "防止 MIME 类型嗅探",
        "X-Frame-Options": "防止点击劫持",
        "X-XSS-Protection": "XSS 过滤器",
        "Strict-Transport-Security": "HTTP 严格传输安全",
        "Referrer-Policy": "控制 Referrer 信息泄露",
        "Permissions-Policy": "控制浏览器功能权限",
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def scan(self, url: str) -> ScanResult:
        """执行完整扫描"""
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc
        scheme = parsed.scheme
        port = parsed.port or (443 if scheme == "https" else 80)

        result = ScanResult(
            url=url,
            domain=domain,
            ip_address="",
            status_code=0,
            status=ScanStatus.RUNNING
        )

        start_time = time.time()

        try:
            # 1. DNS 解析
            result.ip_address = await self._resolve_dns(domain)

            # 2. SSL/TLS 扫描
            result.ssl_info = await self._scan_ssl(domain, port, scheme)

            # 3. HTTP 头扫描
            result.status_code, result.http_headers = await self._scan_http_headers(url)

            # 4. 敏感文件扫描
            sensitive_findings = await self._scan_sensitive_files(domain, scheme, port)
            result.findings.extend(sensitive_findings)

            # 5. HTTP 头安全检查
            header_findings = self._check_security_headers(result.http_headers)
            result.findings.extend(header_findings)

            # 6. SSL 配置检查
            ssl_findings = self._check_ssl_config(result.ssl_info)
            result.findings.extend(ssl_findings)

            # 7. Cookie 安全检查
            cookie_findings = self._check_cookies(result.http_headers)
            result.findings.extend(cookie_findings)

            # 8. HTTPS 重定向检查
            redirect_findings = await self._check_https_redirect(url, scheme)
            result.findings.extend(redirect_findings)

            result.status = ScanStatus.COMPLETED
            result.scan_time = time.time() - start_time

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
            result.scan_time = time.time() - start_time

        return result

    async def _resolve_dns(self, domain: str) -> str:
        """DNS 解析"""
        try:
            addr_info = await asyncio.get_event_loop().getaddrinfo(
                domain, 443, socket.AF_INET
            )
            if addr_info:
                return addr_info[0][4][0]
        except Exception:
            pass
        return "unknown"

    async def _scan_ssl(self, domain: str, port: int, scheme: str) -> dict:
        """SSL/TLS 配置扫描"""
        if scheme != "https":
            return {"enabled": False, "reason": "非 HTTPS 协议"}

        try:
            loop = asyncio.get_event_loop()
            context = ssl.create_default_context(cafile=certifi.where())

            cert_data = await loop.run_in_executor(
                None, self._get_cert_sync, domain, port, context
            )
            return cert_data
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def _get_cert_sync(self, domain: str, port: int, context: ssl.SSLContext) -> dict:
        """同步获取证书信息"""
        try:
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=domain
            )
            conn.settimeout(self.timeout)
            conn.connect((domain, port))
            cert = conn.getpeercert(binary_form=True)
            cert_text = conn.getpeercert()
            conn.close()

            # 解析证书信息
            subject = dict(x[0] for x in cert_text.get("subject", ()))
            issuer = dict(x[0] for x in cert_text.get("issuer", ()))

            # 获取有效期
            not_before = cert_text.get("notBefore")
            not_after = cert_text.get("notAfter")

            # 获取协议版本
            protocol_version = conn.version()

            return {
                "enabled": True,
                "protocol": protocol_version,
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "serial_number": hex(int.from_bytes(cert[:4], "big")),
                "cipher": conn.cipher()
            }
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    async def _scan_http_headers(self, url: str) -> tuple:
        """HTTP 头扫描"""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AgentGuard/1.0 (Security Scanner)"}
            )
            resp = await asyncio.get_event_loop().run_in_executor(
                None, self._fetch_sync, req
            )
            headers = dict(resp.headers)
            status_code = resp.status
            resp.close()
            return status_code, headers
        except Exception as e:
            return 0, {"error": str(e)}

    def _fetch_sync(self, req: urllib.request.Request):
        """同步 HTTP 请求"""
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(
                context=ssl.create_default_context(cafile=certifi.where())
            )
        )
        return opener.open(req, timeout=self.timeout)

    async def _scan_sensitive_files(self, domain: str, scheme: str, port: int) -> list:
        """敏感文件/路径扫描"""
        findings = []
        base_url = f"{scheme}://{domain}:{port}" if port not in [80, 443] else f"{scheme}://{domain}"

        tasks = []
        for path in self.SENSITIVE_PATHS[:15]:  # 限制数量避免超时
            url = f"{base_url}{path}"
            tasks.append(self._check_sensitive_url(url, path))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for path, result in zip(self.SENSITIVE_PATHS[:15], results):
            if isinstance(result, Exception):
                continue
            if result:
                findings.append(SecurityFinding(
                    category="sensitive_files",
                    title=f"敏感路径可访问: {path}",
                    risk_level=RiskLevel.HIGH,
                    description=f"路径 {path} 可公开访问，可能泄露敏感信息",
                    recommendation=f"禁止公开访问 {path}，配置服务器拒绝访问",
                    details=result
                ))

        return findings

    async def _check_sensitive_url(self, url: str, path: str) -> Optional[str]:
        """检查单个敏感 URL"""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AgentGuard/1.0 (Security Scanner)"}
            )
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=5)
            )
            status = resp.status
            resp.close()
            if status in [200, 403]:
                return f"HTTP {status}"
            return None
        except urllib.error.HTTPError as e:
            if e.code in [200, 403]:
                return f"HTTP {e.code}"
            return None
        except Exception:
            return None

    def _check_security_headers(self, headers: dict) -> list:
        """检查安全 HTTP 头"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, description in self.MISSING_HEADERS.items():
            if header.lower() not in headers_lower:
                findings.append(SecurityFinding(
                    category="http_headers",
                    title=f"缺少安全头: {header}",
                    risk_level=RiskLevel.MEDIUM,
                    description=f"缺少 {header} 头，{description}",
                    recommendation=f"在服务器配置中添加 {header} 头"
                ))
            else:
                value = headers_lower[header.lower()]
                if header == "Strict-Transport-Security":
                    if "max-age=" not in value.lower() or "max-age=0" in value.lower():
                        findings.append(SecurityFinding(
                            category="http_headers",
                            title="HSTS 配置不当",
                            risk_level=RiskLevel.MEDIUM,
                            description="HSTS max-age 设置过短或未设置",
                            recommendation="设置 HSTS max-age 至少为 31536000 (1年)"
                        ))
                    else:
                        findings.append(SecurityFinding(
                            category="http_headers",
                            title=f"{header} 配置正确",
                            risk_level=RiskLevel.PASS,
                            description=f"{header} 已正确配置",
                            recommendation=""
                        ))
                elif header == "X-Frame-Options":
                    if value.upper() not in ["DENY", "SAMEORIGIN"]:
                        findings.append(SecurityFinding(
                            category="http_headers",
                            title="X-Frame-Options 配置不当",
                            risk_level=RiskLevel.MEDIUM,
                            description="X-Frame-Options 应设置为 DENY 或 SAMEORIGIN",
                            recommendation="设置 X-Frame-Options: DENY"
                        ))
                    else:
                        findings.append(SecurityFinding(
                            category="http_headers",
                            title=f"{header} 配置正确",
                            risk_level=RiskLevel.PASS,
                            description=f"{header} 已正确配置",
                            recommendation=""
                        ))
                else:
                    findings.append(SecurityFinding(
                        category="http_headers",
                        title=f"{header} 已配置",
                        risk_level=RiskLevel.PASS,
                        description=f"{description} 已启用",
                        recommendation=""
                    ))

        return findings

    def _check_ssl_config(self, ssl_info: dict) -> list:
        """检查 SSL 配置"""
        findings = []

        if not ssl_info.get("enabled"):
            findings.append(SecurityFinding(
                category="ssl",
                title="SSL/TLS 未启用",
                risk_level=RiskLevel.CRITICAL,
                description="网站未启用 HTTPS，数据传输不安全",
                recommendation="立即配置 SSL 证书并启用 HTTPS"
            ))
            return findings

        protocol = ssl_info.get("protocol", "")
        if protocol and ("SSLv3" in protocol or "TLSv1.0" in protocol or "TLSv1.1" in protocol):
            findings.append(SecurityFinding(
                category="ssl",
                title="使用过时 TLS 协议",
                risk_level=RiskLevel.HIGH,
                description=f"检测到过时的 TLS 协议版本: {protocol}",
                recommendation="禁用 SSLv3/TLSv1.0/TLSv1.1，仅启用 TLSv1.2+"
            ))
        else:
            findings.append(SecurityFinding(
                category="ssl",
                title="SSL/TLS 配置正常",
                risk_level=RiskLevel.PASS,
                description="SSL/TLS 协议版本正常",
                recommendation=""
            ))

        # 检查证书有效期
        not_after = ssl_info.get("not_after", "")
        if not_after:
            try:
                from datetime import datetime
                expiry_date = datetime.strptime(not_after.split(" ")[0], "%b %d %H:%M:%S %Y")
                days_left = (expiry_date - datetime.utcnow()).days
                if days_left < 30:
                    findings.append(SecurityFinding(
                        category="ssl",
                        title="SSL 证书即将过期",
                        risk_level=RiskLevel.HIGH,
                        description=f"SSL 证书将在 {days_left} 天后过期",
                        recommendation="尽快续期 SSL 证书"
                    ))
                elif days_left < 90:
                    findings.append(SecurityFinding(
                        category="ssl",
                        title="SSL 证书短期将过期",
                        risk_level=RiskLevel.MEDIUM,
                        description=f"SSL 证书将在 {days_left} 天后过期",
                        recommendation="建议尽快续期 SSL 证书"
                    ))
                else:
                    findings.append(SecurityFinding(
                        category="ssl",
                        title="SSL 证书有效期正常",
                        risk_level=RiskLevel.PASS,
                        description=f"SSL 证书还有 {days_left} 天过期",
                        recommendation=""
                    ))
            except Exception:
                pass

        return findings

    def _check_cookies(self, headers: dict) -> list:
        """检查 Cookie 安全设置"""
        findings = []
        set_cookie = headers.get("Set-Cookie", "")

        if not set_cookie:
            findings.append(SecurityFinding(
                category="cookies",
                title="未设置 Cookie",
                risk_level=RiskLevel.INFO,
                description="网站未设置 Cookie",
                recommendation=""
            ))
            return findings

        cookie_lower = set_cookie.lower()
        issues = []

        if "httponly" not in cookie_lower:
            issues.append("HttpOnly")
        if "secure" not in cookie_lower:
            issues.append("Secure")
        if "samesite" not in cookie_lower:
            issues.append("SameSite")

        if issues:
            findings.append(SecurityFinding(
                category="cookies",
                title="Cookie 安全标志缺失",
                risk_level=RiskLevel.MEDIUM,
                description=f"Cookie 缺少安全标志: {', '.join(issues)}",
                recommendation=f"为 Cookie 添加 HttpOnly, Secure, SameSite 标志"
            ))
        else:
            findings.append(SecurityFinding(
                category="cookies",
                title="Cookie 安全配置正常",
                risk_level=RiskLevel.PASS,
                description="Cookie 已正确配置安全标志",
                recommendation=""
            ))

        return findings

    async def _check_https_redirect(self, url: str, scheme: str) -> list:
        """检查 HTTPS 重定向"""
        findings = []

        if scheme == "https":
            findings.append(SecurityFinding(
                category="redirect",
                title="已使用 HTTPS",
                risk_level=RiskLevel.PASS,
                description="请求已通过 HTTPS 发送",
                recommendation=""
            ))
            return findings

        # 尝试 HTTPS 版本
        https_url = url.replace("http://", "https://")
        try:
            req = urllib.request.Request(
                https_url,
                headers={"User-Agent": "AgentGuard/1.0"}
            )
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=5)
            )
            status = resp.status
            resp.close()
            if status in [200, 301, 302]:
                findings.append(SecurityFinding(
                    category="redirect",
                    title="HTTPS 版本可访问",
                    risk_level=RiskLevel.PASS,
                    description=f"HTTPS 版本返回状态码 {status}",
                    recommendation="配置 HTTP 自动跳转到 HTTPS"
                ))
            else:
                findings.append(SecurityFinding(
                    category="redirect",
                    title="HTTPS 版本不可达",
                    risk_level=RiskLevel.HIGH,
                    description=f"HTTPS 版本返回状态码 {status}",
                    recommendation="配置 SSL 证书并确保 HTTPS 可访问"
                ))
        except Exception:
            findings.append(SecurityFinding(
                category="redirect",
                title="HTTPS 版本不可达",
                risk_level=RiskLevel.HIGH,
                description="无法通过 HTTPS 访问网站",
                recommendation="配置 SSL 证书并确保 HTTPS 可访问"
            ))

        # 检查 HTTP 是否重定向到 HTTPS
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AgentGuard/1.0"}
            )
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    if code in (301, 302, 303, 307, 308):
                        return None
                    return None
                def http_error_302(self, req, fp, code, msg, headers):
                    return fp
                http_error_301 = http_error_303 = http_error_307 = http_error_302

            opener = urllib.request.build_opener(NoRedirectHandler())
            resp = opener.open(req, timeout=5)
            resp.close()
        except urllib.error.HTTPError as e:
            if e.code in [301, 302, 303, 307, 308]:
                location = e.headers.get("Location", "")
                if location.startswith("https://"):
                    findings.append(SecurityFinding(
                        category="redirect",
                        title="HTTP 自动跳转 HTTPS",
                        risk_level=RiskLevel.PASS,
                        description="HTTP 请求自动重定向到 HTTPS",
                        recommendation=""
                    ))
                else:
                    findings.append(SecurityFinding(
                        category="redirect",
                        title="HTTP 未跳转 HTTPS",
                        risk_level=RiskLevel.MEDIUM,
                        description="HTTP 请求未自动跳转到 HTTPS",
                        recommendation="配置服务器将 HTTP 301 重定向到 HTTPS"
                    ))

        return findings


# ==================== 邮件发送 ====================

def send_scan_email(to_email: str, domain: str, result: ScanResult):
    """发送扫描报告邮件"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_user = os.environ.get("GMAIL_SMTP_USER")
    smtp_password = os.environ.get("GMAIL_SMTP_PASSWORD")

    if not smtp_user or not smtp_password:
        print("警告: Gmail SMTP 凭据未配置，跳过邮件发送")
        return

    # 生成 HTML 报告
    html_report = generate_html_report(domain, result)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"AgentGuard 安全扫描报告 - {domain}"
    msg["From"] = smtp_user
    msg["To"] = to_email

    msg.attach(MIMEText(html_report, "html", "utf-8"))

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, [to_email], msg.as_string())
        server.quit()
        print(f"扫描报告已发送至 {to_email}")
    except Exception as e:
        print(f"邮件发送失败: {e}")


def generate_html_report(domain: str, result: ScanResult) -> str:
    """生成 HTML 格式的安全扫描报告"""
    risk_level = result.get_overall_risk_level()
    risk_colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d",
        "pass": "#28a745"
    }
    risk_color = risk_colors.get(risk_level, "#6c757d")

    findings_html = ""
    for f in result.findings:
        level_color = risk_colors.get(f.risk_level.value, "#6c757d")
        findings_html += f"""
        <div style="border-left: 4px solid {level_color}; padding: 10px; margin: 8px 0; background: #f8f9fa;">
            <strong style="color: {level_color};">[{f.risk_level.value.upper()}]</strong> {f.title}
            <p style="margin: 5px 0; color: #666;">{f.description}</p>
            <p style="margin: 5px 0;"><em>建议: {f.recommendation}</em></p>
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }}
            .score {{ font-size: 48px; font-weight: bold; color: {risk_color}; }}
            .section {{ margin: 20px 0; }}
            .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ AgentGuard 安全扫描报告</h1>
            <p>扫描目标: {domain}</p>
            <div class="score" style="color: {risk_color};">{risk_level.upper()}</div>
            <p>总体风险等级</p>
            <p>扫描耗时: {result.scan_time:.1f} 秒</p>
        </div>

        <div class="section">
            <h2>📋 发现的安全问题 ({len([f for f in result.findings if f.risk_level != RiskLevel.PASS])})</h2>
            {findings_html if findings_html else '<p style="color: #28a745;">✅ 未发现安全问题！</p>'}
        </div>

        <div class="footer">
            <p>本报告由 AgentGuard 自动生成 | {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </body>
    </html>
    """


# ==================== 缓存 ====================

SCAN_CACHE = {}
SCAN_CACHE_TTL = int(os.environ.get("SCAN_CACHE_TTL", "86400"))  # 默认 24 小时


def get_cached_result(url: str) -> Optional[ScanResult]:
    """获取缓存的扫描结果"""
    if url in SCAN_CACHE:
        cached_time, result = SCAN_CACHE[url]
        if time.time() - cached_time < SCAN_CACHE_TTL:
            return result
        else:
            del SCAN_CACHE[url]
    return None


def cache_result(url: str, result: ScanResult):
    """缓存扫描结果"""
    SCAN_CACHE[url] = (time.time(), result)
