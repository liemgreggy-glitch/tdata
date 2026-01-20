#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Login API Service for Telegram Account Bot
Provides web interface and API endpoints for viewing login codes
"""

import os
import asyncio
import secrets
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from threading import Thread

# 定义北京时区常量
BEIJING_TZ = timezone(timedelta(hours=8))

try:
    from aiohttp import web
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    # Create dummy web class to avoid import errors
    class web:
        Application = None
        Request = None
        Response = None
        json_response = None
        AppRunner = None
        TCPSite = None
    print("⚠️ aiohttp未安装，Web Login API功能不可用")
    print("💡 请安装: pip install aiohttp")

try:
    from telethon import TelegramClient, events
    from telethon.tl.functions.account import GetPasswordRequest
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False


@dataclass
class AccountContext:
    """账号上下文信息"""
    token: str
    phone: str
    session_path: str
    api_id: int
    api_hash: str
    client: Optional[Any] = None
    has_2fa: Optional[bool] = None
    last_code: Optional[str] = None
    last_code_at: Optional[datetime] = None
    new_code_event: asyncio.Event = field(default_factory=asyncio.Event)
    is_connected: bool = False


class LoginApiService:
    """Web Login API 服务"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, public_base_url: str = ""):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for LoginApiService")
        
        self.host = host
        self.port = port
        self.public_base_url = public_base_url.rstrip('/')
        self.accounts: Dict[str, AccountContext] = {}
        self.app = None
        self.runner = None
        self.site = None
        self._loop = None
        
        print(f"🌐 Web Login API 服务初始化")
        print(f"   主机: {host}")
        print(f"   端口: {port}")
        if public_base_url:
            print(f"   公开URL: {public_base_url}")
    
    def _create_app(self) -> web.Application:
        """创建 aiohttp 应用"""
        app = web.Application()
        app.router.add_get('/login/{token}', self.handle_login_page)
        app.router.add_get('/api/v1/info/{token}', self.handle_api_info)
        app.router.add_get('/api/v1/code/{token}', self.handle_api_code)
        app.router.add_get('/healthz', self.handle_healthz)
        return app
    
    async def _start_server(self):
        """启动服务器"""
        try:
            self.app = self._create_app()
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            print(f"✅ Web Login API 服务已启动在 {self.host}:{self.port}")
        except Exception as e:
            print(f"❌ Web Login API 服务启动失败: {e}")
            raise
    
    def start_background(self):
        """在后台线程中启动服务器"""
        def run_server():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._start_server())
            self._loop.run_forever()
        
        thread = Thread(target=run_server, daemon=True)
        thread.start()
        print("🚀 Web Login API 服务后台线程已启动")
    
    def register_session(self, session_path: str, phone: Optional[str], api_id: int, api_hash: str) -> str:
        """注册一个 session 并返回访问 URL"""
        # 生成唯一 token
        token = secrets.token_urlsafe(16)
        
        # 从 session 路径提取手机号（如果未提供）
        if not phone:
            phone = self._extract_phone_from_path(session_path)
        
        # 创建账号上下文，确保类型正确
        # Note: int(api_id) and str(api_hash) are defensive conversions to prevent TypeError in Telethon
        account = AccountContext(
            token=token,
            phone=phone,
            session_path=session_path,
            api_id=int(api_id) if api_id is not None else 0,
            api_hash=str(api_hash) if api_hash is not None else ""
        )
        
        self.accounts[token] = account
        
        url = self.build_login_url(token)
        print(f"📝 注册 session: {phone} -> {url}")
        
        return url
    
    def build_login_url(self, token: str) -> str:
        """构建登录页面 URL"""
        base = self.public_base_url if self.public_base_url else f"http://{self.host}:{self.port}"
        return f"{base}/login/{token}"
    
    def _extract_phone_from_path(self, session_path: str) -> str:
        """从 session 路径提取手机号"""
        basename = os.path.basename(session_path)
        # 移除 .session 扩展名
        name = basename.replace('.session', '')
        # 如果是数字，假设是手机号
        if name.replace('+', '').replace('_', '').isdigit():
            return name
        return name
    
    async def _ensure_connected(self, account: AccountContext):
        """确保账号已连接到 Telegram"""
        if account.is_connected and account.client:
            return
        
        if not TELETHON_AVAILABLE:
            return
        
        try:
            # 创建客户端
            account.client = TelegramClient(
                account.session_path,
                int(account.api_id),
                str(account.api_hash)
            )
            
            await account.client.connect()
            
            # 检查是否已授权
            if not await account.client.is_user_authorized():
                account.is_connected = False
                return
            
            account.is_connected = True
            
            # 检查 2FA 状态
            try:
                password = await account.client(GetPasswordRequest())
                account.has_2fa = password.has_password if hasattr(password, 'has_password') else False
            except Exception as e:
                print(f"⚠️ 检查 2FA 状态失败 {account.phone}: {e}")
                account.has_2fa = None
            
            # 订阅 777000 消息
            @account.client.on(events.NewMessage(chats=[777000]))
            async def code_handler(event):
                code = self._extract_code(event.message.message)
                if code:
                    account.last_code = code
                    account.last_code_at = datetime.now(BEIJING_TZ)
                    account.new_code_event.set()
                    account.new_code_event.clear()
                    print(f"📥 收到验证码 {account.phone}: {code}")
            
            # 获取最近的验证码
            try:
                messages = await account.client.get_messages(777000, limit=1)
                if messages:
                    code = self._extract_code(messages[0].message)
                    if code:
                        account.last_code = code
                        account.last_code_at = messages[0].date
            except Exception as e:
                print(f"⚠️ 获取历史消息失败 {account.phone}: {e}")
            
        except Exception as e:
            print(f"❌ 连接失败 {account.phone}: {e}")
            account.is_connected = False
    
    def _extract_code(self, text: str) -> Optional[str]:
        """从消息文本中提取 5-6 位验证码"""
        # 匹配 5-6 位数字
        match = re.search(r'\b(\d{5,6})\b', text)
        return match.group(1) if match else None
    
    async def handle_login_page(self, request: web.Request) -> web.Response:
        """处理登录页面请求"""
        token = request.match_info['token']
        account = self.accounts.get(token)
        
        if not account:
            return web.Response(text="Invalid token", status=404)
        
        # 确保已连接
        if self._loop:
            asyncio.run_coroutine_threadsafe(self._ensure_connected(account), self._loop)
        
        # 生成 HTML
        html = self._generate_login_page_html(account)
        return web.Response(text=html, content_type='text/html')
    
    async def handle_api_info(self, request: web.Request) -> web.Response:
        """处理 API 信息请求"""
        token = request.match_info['token']
        account = self.accounts.get(token)
        
        if not account:
            return web.json_response({'error': 'Invalid token'}, status=404)
        
        # 确保已连接
        if self._loop:
            asyncio.run_coroutine_threadsafe(self._ensure_connected(account), self._loop)
        
        return web.json_response({
            'phone': account.phone,
            'has_2fa': account.has_2fa,
            'last_code': account.last_code,
            'last_code_at': account.last_code_at.isoformat() if account.last_code_at else None
        })
    
    async def handle_api_code(self, request: web.Request) -> web.Response:
        """处理代码轮询请求，支持长轮询"""
        token = request.match_info['token']
        account = self.accounts.get(token)
        
        if not account:
            return web.json_response({'error': 'Invalid token'}, status=404)
        
        # 确保已连接
        if self._loop:
            asyncio.run_coroutine_threadsafe(self._ensure_connected(account), self._loop)
        
        # 获取 wait 参数（长轮询秒数）
        wait = int(request.query.get('wait', '0'))
        wait = max(0, min(wait, 30))  # 限制在 0-30 秒
        
        if wait > 0 and account.is_connected:
            # 长轮询：等待新验证码
            try:
                await asyncio.wait_for(account.new_code_event.wait(), timeout=wait)
            except asyncio.TimeoutError:
                pass
        
        return web.json_response({
            'last_code': account.last_code,
            'last_code_at': account.last_code_at.isoformat() if account.last_code_at else None
        })
    
    async def handle_healthz(self, request: web.Request) -> web.Response:
        """健康检查"""
        return web.Response(text="OK", status=200)
    
    def _generate_login_page_html(self, account: AccountContext) -> str:
        """生成登录页面 HTML，匹配截图风格"""
        
        # 品牌配置（可自定义）
        brand_name = "PVBOT"
        brand_handle = "@PvBot"
        
        # 判断是否有最近的验证码（30分钟内）
        has_recent_code = False
        code_age_minutes = 999
        if account.last_code_at:
            age = datetime.now(BEIJING_TZ) - account.last_code_at
            code_age_minutes = age.total_seconds() / 60
            has_recent_code = code_age_minutes <= 30
        
        # 2FA 状态
        twofa_status = "✅ Enabled" if account.has_2fa else "❌ Disabled"
        if account.has_2fa is None:
            twofa_status = "⚠️ Unknown"
        
        # 验证码显示
        if has_recent_code and account.last_code:
            code_display = f'<div class="code-digits">{account.last_code}</div>'
            code_time_str = account.last_code_at.strftime('%Y-%m-%d %H:%M:%S')
            time_display = f'<div class="code-time">Received at {code_time_str}</div>'
        else:
            code_display = '<div class="no-code-block">'
            code_display += '<p class="no-code-zh">过去30分钟内没有登录消息</p>'
            code_display += '<p class="no-code-en">No login message in the past 30 minutes</p>'
            code_display += '</div>'
            time_display = ''
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Telegram Login API - {account.phone}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        
        .container {{
            display: flex;
            max-width: 1000px;
            width: 100%;
            min-height: 500px;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        
        /* 左侧红色面板 */
        .left-panel {{
            background: linear-gradient(180deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 40px 30px;
            width: 320px;
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
        }}
        
        .logo {{
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .left-title {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            text-align: center;
        }}
        
        .left-subtitle {{
            font-size: 14px;
            text-align: center;
            line-height: 1.6;
            opacity: 0.9;
            margin-bottom: 40px;
        }}
        
        /* 信封图标和徽章 */
        .envelope-container {{
            position: relative;
            margin-top: auto;
        }}
        
        .envelope-icon {{
            width: 80px;
            height: 80px;
        }}
        
        .badge {{
            position: absolute;
            top: -8px;
            right: -8px;
            background: #ff4444;
            color: white;
            border-radius: 50%;
            width: 28px;
            height: 28px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 16px;
            border: 3px solid white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }}
        
        /* 右侧内容区 */
        .right-panel {{
            flex: 1;
            padding: 40px;
            display: flex;
            flex-direction: column;
        }}
        
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }}
        
        .phone-display {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 20px;
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .copy-btn {{
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        }}
        
        .copy-btn:hover {{
            background: #2980b9;
        }}
        
        .status-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        .status-row {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }}
        
        .status-row:last-child {{
            margin-bottom: 0;
        }}
        
        .status-label {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        
        .status-value {{
            font-weight: 600;
            font-size: 14px;
        }}
        
        /* 验证码显示区域 */
        .code-section {{
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: #f8f9fa;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 20px;
        }}
        
        .code-digits {{
            font-size: 56px;
            font-weight: bold;
            color: #2c3e50;
            letter-spacing: 8px;
            margin-bottom: 10px;
        }}
        
        .code-time {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        
        .no-code-block {{
            text-align: center;
            padding: 20px;
        }}
        
        .no-code-zh {{
            font-size: 18px;
            color: #7f8c8d;
            margin-bottom: 10px;
        }}
        
        .no-code-en {{
            font-size: 14px;
            color: #95a5a6;
        }}
        
        /* 指示区域 */
        .instruction-box {{
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
        
        .instruction-box p {{
            color: #1976d2;
            font-size: 14px;
            line-height: 1.6;
        }}
        
        /* 刷新按钮 */
        .refresh-btn {{
            background: #27ae60;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: background 0.2s;
            width: 100%;
        }}
        
        .refresh-btn:hover {{
            background: #229954;
        }}
        
        /* 页脚 */
        .footer {{
            text-align: center;
            color: #95a5a6;
            font-size: 12px;
            margin-top: 20px;
        }}
        
        /* 响应式 */
        @media (max-width: 768px) {{
            .container {{
                flex-direction: column;
            }}
            
            .left-panel {{
                width: 100%;
                padding: 30px 20px;
            }}
            
            .right-panel {{
                padding: 30px 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- 左侧红色面板 -->
        <div class="left-panel">
            <div class="logo">{brand_name}</div>
            <div class="left-title">Telegram Login API</div>
            <div class="left-subtitle">
                验证码接收服务<br>
                Code Reception Service<br>
                实时获取登录验证码
            </div>
            
            <!-- 信封图标和徽章 -->
            <div class="envelope-container">
                <svg class="envelope-icon" viewBox="0 0 24 24" fill="white" opacity="0.9">
                    <path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/>
                </svg>
                <div class="badge">1</div>
            </div>
        </div>
        
        <!-- 右侧内容区 -->
        <div class="right-panel">
            <div class="header">
                <div class="phone-display">
                    📱 {account.phone}
                </div>
                <button class="copy-btn" onclick="copyPhone()">📋 Copy</button>
            </div>
            
            <!-- 状态信息 -->
            <div class="status-section">
                <div class="status-row">
                    <span class="status-label">2FA Status:</span>
                    <span class="status-value">{twofa_status}</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Session Status:</span>
                    <span class="status-value">{"🟢 Connected" if account.is_connected else "🔴 Disconnected"}</span>
                </div>
            </div>
            
            <!-- 验证码显示 -->
            <div class="code-section">
                {code_display}
                {time_display}
            </div>
            
            <!-- 使用说明 -->
            <div class="instruction-box">
                <p><strong>使用说明 / Instructions:</strong><br>
                请从 Telegram 客户端触发登录以接收验证码。验证码将自动显示在此页面。<br>
                <em>Please trigger a login from your Telegram client to receive the code. The code will appear here automatically.</em></p>
            </div>
            
            <!-- 刷新按钮 -->
            <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
            
            <!-- 页脚 -->
            <div class="footer">
                This page is created by {brand_handle}
            </div>
        </div>
    </div>
    
    <script>
        // 复制手机号
        function copyPhone() {{
            const phone = "{account.phone}";
            navigator.clipboard.writeText(phone).then(() => {{
                alert('Phone number copied: ' + phone);
            }});
        }}
        
        // 自动轮询更新验证码（每5秒）
        setInterval(() => {{
            fetch('/api/v1/code/{account.token}?wait=5')
                .then(response => response.json())
                .then(data => {{
                    if (data.last_code && data.last_code !== "{account.last_code}") {{
                        location.reload();
                    }}
                }})
                .catch(err => console.error('Poll error:', err));
        }}, 5000);
    </script>
</body>
</html>
"""
        return html