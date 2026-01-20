#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USDT-TRC20 支付监听服务
独立运行的支付系统，监听区块链交易并自动发放会员
"""

import os
import sys
import asyncio
import aiohttp
import sqlite3
import json
import time
import qrcode
import base58
import csv
from io import BytesIO, StringIO
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import random
import logging
from dotenv import load_dotenv
load_dotenv()  # 加载 .env 文件

# 导入 i18n 模块
try:
    from i18n import get_text as t, get_user_language
    I18N_AVAILABLE = True
except ImportError:
    I18N_AVAILABLE = False
    def t(user_id, key):
        return key
    def get_user_language(user_id):
        return 'zh'

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 北京时区
BEIJING_TZ = timezone(timedelta(hours=8))

# ================================
# 配置类
# ================================

class PaymentConfig:
    """支付配置"""
    # USDT-TRC20 官方合约地址
    USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    
    # 收款钱包地址（从环境变量读取）
    WALLET_ADDRESS = os. getenv("TRON_WALLET_ADDRESS", "")
    
    # TronGrid API配置 - 支持多Key轮换
    TRONGRID_API_KEY_STR = os.getenv("TRONGRID_API_KEY", "")
    TRONGRID_API_KEYS = [k.strip() for k in TRONGRID_API_KEY_STR.split(",") if k.strip()]
    TRONGRID_API_BASE = "https://api.trongrid.io"
    
    # Telegram配置
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_NOTIFY_CHAT_ID = os. getenv("TELEGRAM_NOTIFY_CHAT_ID", "")
    
    # 支付套餐配置 (价格单位:  USDT)
    PAYMENT_PLANS = {
        "plan_7d": {"days": 7, "price":  5.0, "name": "7天会员"},
        "plan_30d":  {"days": 30, "price": 15.0, "name": "30天会员"},
        "plan_120d": {"days":  120, "price": 50.0, "name": "120天会员"},
        "plan_365d": {"days":  365, "price": 100.0, "name": "365天会员"},
    }
    
    # 订单配置
    ORDER_TIMEOUT_MINUTES = 10  # 订单超时时间（分钟）
    MIN_CONFIRMATIONS = 20  # 最少区块确认数
    
    # 监听配置
    POLL_INTERVAL_SECONDS = 10  # 轮询间隔（秒）
    
    # 数据库配置
    PAYMENT_DB = "payment.db"
    MAIN_DB = "bot_data.db"  # 主数据库（用于授予会员）- 与 tdata.py 保持一致
    
    @classmethod
    def validate(cls) -> Tuple[bool, str]:
        """验证配置是否完整"""
        if not cls.WALLET_ADDRESS:
            return False, "未配置 TRON_WALLET_ADDRESS"
        if not cls.TELEGRAM_BOT_TOKEN:
            return False, "未配置 TELEGRAM_BOT_TOKEN"
        return True, "配置验证通过"
    
    @classmethod
    def get_api_keys_info(cls) -> str:
        """获取 API Keys 信息"""
        count = len(cls.TRONGRID_API_KEYS)
        if count == 0:
            return "未配置 API Key（使用免费额度）"
        return f"已配置 {count} 个 API Key"

# ================================
# 数据模型
# ================================

class OrderStatus(Enum):
    """订单状态"""
    PENDING = "pending"  # 待支付
    PAID = "paid"  # 已支付，等待确认
    COMPLETED = "completed"  # 已完成
    EXPIRED = "expired"  # 已过期
    CANCELLED = "cancelled"  # 已取消

@dataclass
class PaymentOrder:
    """支付订单"""
    order_id: str  # 订单ID
    user_id: int  # 用户ID
    plan_id: str  # 套餐ID
    amount: float  # 支付金额（带随机小数）
    status: OrderStatus  # 订单状态
    created_at: datetime  # 创建时间
    expires_at: datetime  # 过期时间
    tx_hash: Optional[str] = None  # 交易哈希
    paid_at: Optional[datetime] = None  # 支付时间
    completed_at: Optional[datetime] = None  # 完成时间

@dataclass
class TransactionRecord:
    """交易记录"""
    tx_hash: str  # 交易哈希
    from_address: str  # 发送地址
    to_address: str  # 接收地址
    amount: float  # 金额
    timestamp: int  # 区块时间戳
    block_number: int  # 区块号
    confirmations: int  # 确认数
    contract_address: str  # 合约地址
    processed: bool = False  # 是否已处理

# ================================
# 二维码生成器
# ================================

class QRCodeGenerator:
    """二维码生成器"""
    
    @staticmethod
    def generate_payment_qr(wallet_address: str, amount: float) -> bytes:
        """生成支付二维码 - 纯地址格式
        
        Args:
            wallet_address: 收款钱包地址
            amount: 支付金额（参数保留但不使用，用于兼容性）
            
        Returns:
            二维码图片字节流
        """
        # 修改：只用纯地址，不用 tronlink:// 链接
        # 这样用户可以用任何支持 TRC20 的钱包扫描
        qr_content = wallet_address
        
        # 生成二维码
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_content)
        qr.make(fit=True)
        
        # 转换为图片
        img = qr.make_image(fill_color="black", back_color="white")
        
        # 转换为字节流
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        return buffer.getvalue()

# ================================
# 支付数据库管理
# ================================

class PaymentDatabase:
    """支付数据库管理"""
    
    def __init__(self, db_path: str = PaymentConfig.PAYMENT_DB):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # 订单表
        c.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                plan_id TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                tx_hash TEXT,
                paid_at TEXT,
                completed_at TEXT
            )
        """)
        
        # 添加 message_id 列（如果不存在）
        try:
            c.execute("ALTER TABLE orders ADD COLUMN message_id INTEGER")
        except sqlite3.OperationalError:
            # 列已存在，忽略
            pass
        
        # 交易记录表
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash TEXT PRIMARY KEY,
                from_address TEXT NOT NULL,
                to_address TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                block_number INTEGER NOT NULL,
                confirmations INTEGER NOT NULL,
                contract_address TEXT NOT NULL,
                processed INTEGER DEFAULT 0,
                order_id TEXT,
                created_at TEXT NOT NULL
            )
        """)
        
        # 创建索引
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_transactions_processed ON transactions(processed)")
        
        conn.commit()
        conn.close()
        logger.info("✅ 支付数据库初始化完成")
    
    def create_order(self, order: PaymentOrder) -> bool:
        """创建订单"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("""
                INSERT INTO orders (order_id, user_id, plan_id, amount, status, 
                                   created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                order.order_id,
                order.user_id,
                order.plan_id,
                order.amount,
                order.status.value,
                order.created_at.isoformat(),
                order.expires_at.isoformat()
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"✅ 订单创建成功: {order.order_id}")
            return True
        except Exception as e:
            logger.error(f"❌ 创建订单失败: {e}")
            return False
    
    def get_order(self, order_id: str) -> Optional[PaymentOrder]:
        """获取订单"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,))
            row = c.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return PaymentOrder(
                order_id=row[0],
                user_id=row[1],
                plan_id=row[2],
                amount=row[3],
                status=OrderStatus(row[4]),
                created_at=datetime.fromisoformat(row[5]),
                expires_at=datetime.fromisoformat(row[6]),
                tx_hash=row[7],
                paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                completed_at=datetime.fromisoformat(row[9]) if row[9] else None
            )
        except Exception as e:
            logger.error(f"❌ 获取订单失败: {e}")
            return None
    
    def get_pending_orders(self) -> List[PaymentOrder]:
        """获取所有待支付订单"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("SELECT * FROM orders WHERE status = ?", (OrderStatus.PENDING.value,))
            rows = c.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append(PaymentOrder(
                    order_id=row[0],
                    user_id=row[1],
                    plan_id=row[2],
                    amount=row[3],
                    status=OrderStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    expires_at=datetime.fromisoformat(row[6]),
                    tx_hash=row[7],
                    paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                    completed_at=datetime.fromisoformat(row[9]) if row[9] else None
                ))
            
            return orders
        except Exception as e:
            logger.error(f"❌ 获取待支付订单失败: {e}")
            return []
    
    def get_user_pending_order(self, user_id: int) -> Optional[PaymentOrder]:
        """获取用户的待支付订单"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("""
                SELECT * FROM orders 
                WHERE user_id = ? AND status = ?
                ORDER BY created_at DESC
                LIMIT 1
            """, (user_id, OrderStatus.PENDING.value))
            
            row = c.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return PaymentOrder(
                order_id=row[0],
                user_id=row[1],
                plan_id=row[2],
                amount=row[3],
                status=OrderStatus(row[4]),
                created_at=datetime.fromisoformat(row[5]),
                expires_at=datetime.fromisoformat(row[6]),
                tx_hash=row[7],
                paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                completed_at=datetime.fromisoformat(row[9]) if row[9] else None
            )
        except Exception as e:
            logger.error(f"❌ 获取用户待支付订单失败: {e}")
            return None
    
    def update_order_status(self, order_id: str, status: OrderStatus, 
                           tx_hash: Optional[str] = None) -> bool:
        """更新订单状态"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            now = datetime.now(BEIJING_TZ).isoformat()
            
            if status == OrderStatus.PAID:
                c.execute("""
                    UPDATE orders 
                    SET status = ?, tx_hash = ?, paid_at = ?
                    WHERE order_id = ?
                """, (status.value, tx_hash, now, order_id))
            elif status == OrderStatus.COMPLETED:
                c.execute("""
                    UPDATE orders 
                    SET status = ?, completed_at = ?
                    WHERE order_id = ?
                """, (status.value, now, order_id))
            else:
                c.execute("""
                    UPDATE orders 
                    SET status = ?
                    WHERE order_id = ?
                """, (status.value, order_id))
            
            conn.commit()
            conn.close()
            logger.info(f"✅ 订单状态更新: {order_id} -> {status.value}")
            return True
        except Exception as e:
            logger.error(f"❌ 更新订单状态失败: {e}")
            return False
    
    def save_transaction(self, tx: TransactionRecord) -> bool:
        """保存交易记录"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("""
                INSERT OR REPLACE INTO transactions 
                (tx_hash, from_address, to_address, amount, timestamp, 
                 block_number, confirmations, contract_address, processed, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tx.tx_hash,
                tx.from_address,
                tx.to_address,
                tx.amount,
                tx.timestamp,
                tx.block_number,
                tx.confirmations,
                tx.contract_address,
                1 if tx.processed else 0,
                datetime.now(BEIJING_TZ).isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"❌ 保存交易记录失败: {e}")
            return False
    
    def is_transaction_processed(self, tx_hash: str) -> bool:
        """检查交易是否已处理"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("SELECT processed FROM transactions WHERE tx_hash = ?", (tx_hash,))
            row = c.fetchone()
            conn.close()
            
            return bool(row and row[0] == 1)
        except Exception as e:
            logger.error(f"❌ 检查交易是否已处理失败: {e}")
            return False
    
    def is_amount_in_use(self, amount: float) -> bool:
        """检查金额是否已被待支付订单使用"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("""
                SELECT 1 FROM orders 
                WHERE status = ? 
                AND ABS(amount - ?) < 0.00001
                LIMIT 1
            """, (OrderStatus.PENDING.value, amount))
            
            result = c.fetchone()
            conn.close()
            
            return result is not None
        except Exception as e:
            logger.error(f"❌ 检查金额失败: {e}")
            return True  # 出错时保守处理
    
    def update_order_message_id(self, order_id: str, message_id: int):
        """保存订单消息ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                UPDATE orders 
                SET message_id = ?
                WHERE order_id = ?
            """, (message_id, order_id))
            conn.commit()
            conn.close()
            logger.info(f"✅ 订单消息ID已保存: {order_id} -> {message_id}")
        except Exception as e:
            logger.error(f"❌ 保存消息ID失败: {e}")
    
    def get_order_message_id(self, order_id: str) -> Optional[int]:
        """获取订单消息ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT message_id FROM orders WHERE order_id = ?", (order_id,))
            row = c.fetchone()
            conn.close()
            return row[0] if row and row[0] else None
        except Exception as e:
            logger.error(f"❌ 获取消息ID失败: {e}")
            return None
    
    def get_expired_pending_orders(self) -> List[PaymentOrder]:
        """获取已过期的待支付订单"""
        try:
            now = datetime.now(BEIJING_TZ)
            
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("""
                SELECT * FROM orders 
                WHERE status = ? AND expires_at < ?
            """, (OrderStatus.PENDING.value, now.isoformat()))
            
            rows = c.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append(PaymentOrder(
                    order_id=row[0],
                    user_id=row[1],
                    plan_id=row[2],
                    amount=row[3],
                    status=OrderStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    expires_at=datetime.fromisoformat(row[6]),
                    tx_hash=row[7],
                    paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                    completed_at=datetime.fromisoformat(row[9]) if row[9] else None
                ))
            
            return orders
        except Exception as e:
            logger.error(f"❌ 获取过期订单失败: {e}")
            return []
    
    def get_orders_by_date_range(self, start_date: datetime, end_date: datetime) -> List[PaymentOrder]:
        """按日期范围获取订单"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("""
                SELECT * FROM orders 
                WHERE created_at >= ? AND created_at <= ?
                ORDER BY created_at DESC
            """, (start_date.isoformat(), end_date.isoformat()))
            
            rows = c.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append(PaymentOrder(
                    order_id=row[0],
                    user_id=row[1],
                    plan_id=row[2],
                    amount=row[3],
                    status=OrderStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    expires_at=datetime.fromisoformat(row[6]),
                    tx_hash=row[7],
                    paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                    completed_at=datetime.fromisoformat(row[9]) if row[9] else None
                ))
            
            return orders
        except Exception as e:
            logger.error(f"❌ 按日期范围获取订单失败: {e}")
            return []
    
    def get_orders_by_user(self, user_id: int) -> List[PaymentOrder]:
        """按用户ID获取订单"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute("""
                SELECT * FROM orders 
                WHERE user_id = ?
                ORDER BY created_at DESC
            """, (user_id,))
            
            rows = c.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append(PaymentOrder(
                    order_id=row[0],
                    user_id=row[1],
                    plan_id=row[2],
                    amount=row[3],
                    status=OrderStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    expires_at=datetime.fromisoformat(row[6]),
                    tx_hash=row[7],
                    paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                    completed_at=datetime.fromisoformat(row[9]) if row[9] else None
                ))
            
            return orders
        except Exception as e:
            logger.error(f"❌ 按用户ID获取订单失败: {e}")
            return []
    
    def get_orders_stats(self, start_date: datetime = None, end_date: datetime = None) -> dict:
        """获取订单统计
        
        返回:
        {
            'total_count': 100,
            'total_amount': 1234.5678,
            'completed_count': 80,
            'completed_amount': 1000.0000,
            'pending_count': 10,
            'pending_amount': 100.0000,
            'cancelled_count': 5,
            'cancelled_amount': 50.0000,
            'expired_count': 5,
            'expired_amount': 84.5678,
        }
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # 构建基础查询
            where_clause = ""
            params = []
            if start_date and end_date:
                where_clause = "WHERE created_at >= ? AND created_at <= ?"
                params = [start_date.isoformat(), end_date.isoformat()]
            
            # 获取总体统计
            query = f"SELECT COUNT(*), COALESCE(SUM(amount), 0) FROM orders {where_clause}"
            c.execute(query, params)
            total_count, total_amount = c.fetchone()
            
            # 按状态统计
            stats = {
                'total_count': total_count or 0,
                'total_amount': float(total_amount or 0),
            }
            
            for status in [OrderStatus.COMPLETED, OrderStatus.PENDING, OrderStatus.CANCELLED, OrderStatus.EXPIRED]:
                if where_clause:
                    query = f"SELECT COUNT(*), COALESCE(SUM(amount), 0) FROM orders {where_clause} AND status = ?"
                    c.execute(query, params + [status.value])
                else:
                    query = f"SELECT COUNT(*), COALESCE(SUM(amount), 0) FROM orders WHERE status = ?"
                    c.execute(query, [status.value])
                
                count, amount = c.fetchone()
                stats[f'{status.value}_count'] = count or 0
                stats[f'{status.value}_amount'] = float(amount or 0)
            
            conn.close()
            return stats
        except Exception as e:
            logger.error(f"❌ 获取订单统计失败: {e}")
            return {
                'total_count': 0,
                'total_amount': 0,
                'completed_count': 0,
                'completed_amount': 0,
                'pending_count': 0,
                'pending_amount': 0,
                'cancelled_count': 0,
                'cancelled_amount': 0,
                'expired_count': 0,
                'expired_amount': 0,
            }
    
    def get_today_stats(self) -> dict:
        """获取今日统计"""
        now = datetime.now(BEIJING_TZ)
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        return self.get_orders_stats(start, end)
    
    def get_week_stats(self) -> dict:
        """获取本周统计"""
        now = datetime.now(BEIJING_TZ)
        # 本周一
        start = now - timedelta(days=now.weekday())
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        # 本周日
        end = start + timedelta(days=6, hours=23, minutes=59, seconds=59, microseconds=999999)
        return self.get_orders_stats(start, end)
    
    def get_month_stats(self) -> dict:
        """获取本月统计"""
        now = datetime.now(BEIJING_TZ)
        # 本月第一天
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        # 本月最后一天
        if now.month == 12:
            end = now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(seconds=1)
        else:
            end = now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(seconds=1)
        return self.get_orders_stats(start, end)
    
    def get_orders_paginated(self, page: int = 1, per_page: int = 5, 
                           status: str = None, user_id: int = None,
                           start_date: datetime = None, end_date: datetime = None) -> Tuple[List[PaymentOrder], int]:
        """分页获取订单
        
        返回: (订单列表, 总页数)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # 构建查询条件
            where_conditions = []
            params = []
            
            if status:
                where_conditions.append("status = ?")
                params.append(status)
            
            if user_id:
                where_conditions.append("user_id = ?")
                params.append(user_id)
            
            if start_date and end_date:
                where_conditions.append("created_at >= ? AND created_at <= ?")
                params.extend([start_date.isoformat(), end_date.isoformat()])
            
            where_clause = ""
            if where_conditions:
                where_clause = "WHERE " + " AND ".join(where_conditions)
            
            # 获取总数
            count_query = f"SELECT COUNT(*) FROM orders {where_clause}"
            c.execute(count_query, params)
            total_count = c.fetchone()[0]
            total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
            
            # 分页查询
            offset = (page - 1) * per_page
            query = f"""
                SELECT * FROM orders {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """
            c.execute(query, params + [per_page, offset])
            rows = c.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append(PaymentOrder(
                    order_id=row[0],
                    user_id=row[1],
                    plan_id=row[2],
                    amount=row[3],
                    status=OrderStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    expires_at=datetime.fromisoformat(row[6]),
                    tx_hash=row[7],
                    paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                    completed_at=datetime.fromisoformat(row[9]) if row[9] else None
                ))
            
            return orders, total_pages
        except Exception as e:
            logger.error(f"❌ 分页获取订单失败: {e}")
            return [], 1
    
    def export_orders_csv(self, start_date: datetime = None, end_date: datetime = None) -> str:
        """导出订单为 CSV 格式字符串"""
        try:
            # 获取订单
            if start_date and end_date:
                orders = self.get_orders_by_date_range(start_date, end_date)
            else:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute("SELECT * FROM orders ORDER BY created_at DESC")
                rows = c.fetchall()
                conn.close()
                
                orders = []
                for row in rows:
                    orders.append(PaymentOrder(
                        order_id=row[0],
                        user_id=row[1],
                        plan_id=row[2],
                        amount=row[3],
                        status=OrderStatus(row[4]),
                        created_at=datetime.fromisoformat(row[5]),
                        expires_at=datetime.fromisoformat(row[6]),
                        tx_hash=row[7],
                        paid_at=datetime.fromisoformat(row[8]) if row[8] else None,
                        completed_at=datetime.fromisoformat(row[9]) if row[9] else None
                    ))
            
            # 生成 CSV
            output = StringIO()
            output.write('\ufeff')  # UTF-8 BOM for Excel
            writer = csv.writer(output)
            
            # 写入表头
            writer.writerow([
                '订单号', '用户ID', '套餐', '金额', '状态', 
                '创建时间', '支付时间', '完成时间', '交易哈希'
            ])
            
            # 写入数据
            for order in orders:
                # 获取套餐名称
                plan_name = PaymentConfig.PAYMENT_PLANS.get(order.plan_id, {}).get('name', order.plan_id)
                
                # 状态映射
                status_map = {
                    'pending': '待支付',
                    'paid': '已支付',
                    'completed': '已完成',
                    'expired': '已过期',
                    'cancelled': '已取消'
                }
                
                writer.writerow([
                    order.order_id,
                    order.user_id,
                    plan_name,
                    f'{order.amount:.4f}',
                    status_map.get(order.status.value, order.status.value),
                    order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    order.paid_at.strftime('%Y-%m-%d %H:%M:%S') if order.paid_at else '',
                    order.completed_at.strftime('%Y-%m-%d %H:%M:%S') if order.completed_at else '',
                    order.tx_hash or ''
                ])
            
            return output.getvalue()
        except Exception as e:
            logger.error(f"❌ 导出订单CSV失败: {e}")
            return ""


# ================================
# 订单管理器
# ================================

class OrderManager:
    """订单管理器"""
    
    def __init__(self, db: PaymentDatabase):
        self.db = db
    
    def create_payment_order(self, user_id: int, plan_id: str) -> Optional[PaymentOrder]:
        """创建支付订单
        
        Args:
            user_id: 用户ID
            plan_id: 套餐ID
            
        Returns:
            创建的订单对象，失败返回None
        """
        # 检查用户是否有待支付订单
        existing_order = self.db.get_user_pending_order(user_id)
        if existing_order:
            # 检查是否过期
            if datetime.now(BEIJING_TZ) < existing_order.expires_at.replace(tzinfo=BEIJING_TZ):
                logger.warning(f"⚠️ 用户 {user_id} 已有待支付订单: {existing_order.order_id}")
                return None
            else:
                # 过期订单，更新状态
                self.db.update_order_status(existing_order.order_id, OrderStatus.EXPIRED)
        
        # 获取套餐信息
        plan = PaymentConfig.PAYMENT_PLANS.get(plan_id)
        if not plan:
            logger.error(f"❌ 无效的套餐ID: {plan_id}")
            return None
        
        # 生成订单ID
        order_id = f"ORDER_{user_id}_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # 生成唯一金额，最多尝试 50 次
        base_amount = plan["price"]
        max_attempts = 50
        amount = None
        
        for attempt in range(max_attempts):
            random_decimal = random.randint(1, 9999) / 10000  # 0.0001 - 0.9999
            candidate_amount = base_amount + random_decimal
            
            if not self.db.is_amount_in_use(candidate_amount):
                amount = candidate_amount
                break
        
        if amount is None:
            logger.error(f"❌ 无法生成唯一金额")
            return None
        
        # 创建订单
        now = datetime.now(BEIJING_TZ)
        order = PaymentOrder(
            order_id=order_id,
            user_id=user_id,
            plan_id=plan_id,
            amount=amount,
            status=OrderStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(minutes=PaymentConfig.ORDER_TIMEOUT_MINUTES)
        )
        
        if self.db.create_order(order):
            logger.info(f"✅ 订单创建成功: {order_id}, 用户: {user_id}, 金额: {amount:.4f} USDT")
            return order
        
        return None
    
    def cancel_order(self, order_id: str) -> bool:
        """取消订单"""
        return self.db.update_order_status(order_id, OrderStatus.CANCELLED)
    
    def expire_old_orders(self):
        """过期超时订单"""
        orders = self.db.get_pending_orders()
        now = datetime.now(BEIJING_TZ)
        
        for order in orders:
            if now > order.expires_at.replace(tzinfo=BEIJING_TZ):
                self.db.update_order_status(order.order_id, OrderStatus.EXPIRED)
                logger.info(f"⏱️ 订单已过期: {order.order_id}")

# ================================
# TRON区块链监听器
# ================================

class TronUSDTMonitor: 
    """TRON USDT监听器 - 支持多API Key轮换"""
    
    def __init__(self, wallet_address: str, api_keys: List[str] = None):
        self.wallet_address = wallet_address
        self.api_keys = api_keys or []
        self.current_key_index = 0
        self.session:  Optional[aiohttp.ClientSession] = None
        self. failed_keys = set()  # 记录失败的 Key
    
    def _get_next_api_key(self) -> str:
        """轮换获取下一个 API Key"""
        if not self.api_keys:
            return ""
        
        # 尝试找到一个可用的 Key
        attempts = 0
        while attempts < len(self.api_keys):
            key = self.api_keys[self.current_key_index]
            self.current_key_index = (self. current_key_index + 1) % len(self.api_keys)
            
            # 跳过已失败的 Key（但每轮重试）
            if key not in self.failed_keys:
                return key
            attempts += 1
        
        # 所有 Key 都失败过，清空失败记录重试
        self.failed_keys.clear()
        key = self.api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key
    
    def _mark_key_failed(self, key: str):
        """标记 Key 失败"""
        if key: 
            self.failed_keys.add(key)
            logger.warning(f"⚠️ API Key 失败，已标记:  {key[: 8]}...")
    
    def _get_headers(self, api_key: str = None) -> Dict[str, str]: 
        """获取请求头"""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if api_key: 
            headers["TRON-PRO-API-KEY"] = api_key
        return headers
    
    async def init_session(self):
        """初始化HTTP会话（不带默认headers，每次请求单独设置）"""
        if not self.session:
            self.session = aiohttp.ClientSession()
    
    async def close_session(self):
        """关闭HTTP会话"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def get_trc20_transactions(self, limit: int = 20) -> List[TransactionRecord]:
        """获取TRC20转账记录 - 支持 Key 轮换和重试"""
        await self.init_session()
        
        max_retries = max(len(self.api_keys), 1) + 1  # 至少重试一次
        
        for attempt in range(max_retries):
            api_key = self._get_next_api_key()
            
            try:
                url = f"{PaymentConfig.TRONGRID_API_BASE}/v1/accounts/{self.wallet_address}/transactions/trc20"
                params = {
                    "limit": limit,
                    "only_to":  "true",
                    "contract_address": PaymentConfig.USDT_CONTRACT
                }
                
                headers = self._get_headers(api_key)
                
                async with self.session.get(url, params=params, headers=headers, timeout=30) as response:
                    if response.status == 401:
                        logger.error(f"❌ API Key 认证失败 (401): {api_key[: 8] if api_key else 'None'}...")
                        self._mark_key_failed(api_key)
                        continue  # 尝试下一个 Key
                    
                    if response.status == 429:
                        logger.warning(f"⚠️ API 请求限流 (429)，切换 Key...")
                        self._mark_key_failed(api_key)
                        await asyncio.sleep(1)
                        continue
                    
                    if response.status != 200:
                        logger.error(f"❌ TronGrid API 请求失败:  {response.status}")
                        continue
                    
                    data = await response.json()
                    
                    if not data.get("success"):
                        logger. error(f"❌ TronGrid API 返回错误: {data}")
                        continue
                    
                    # 成功，解析交易
                    transactions = []
                    for item in data.get("data", []):
                        try:
                            tx_hash = item.get("transaction_id")
                            from_addr = item.get("from")
                            to_addr = item.get("to")
                            value = int(item.get("value", "0"))
                            amount = value / 1_000_000
                            timestamp = item.get("block_timestamp", 0) // 1000
                            block_number = item. get("block", 0)
                            
                            current_block = await self. get_current_block_number()
                            confirmations = max(0, current_block - block_number)
                            
                            tx = TransactionRecord(
                                tx_hash=tx_hash,
                                from_address=from_addr,
                                to_address=to_addr,
                                amount=amount,
                                timestamp=timestamp,
                                block_number=block_number,
                                confirmations=confirmations,
                                contract_address=PaymentConfig.USDT_CONTRACT
                            )
                            transactions.append(tx)
                        except Exception as e:
                            logger.error(f"❌ 解析交易失败: {e}")
                            continue
                    
                    if api_key:
                        logger.debug(f"✅ 使用 API Key:  {api_key[: 8]}...  成功")
                    
                    return transactions
                    
            except asyncio.TimeoutError:
                logger. error(f"❌ TronGrid API 请求超时")
                self._mark_key_failed(api_key)
                continue
            except Exception as e: 
                logger.error(f"❌ 获取TRC20交易失败: {e}")
                self._mark_key_failed(api_key)
                continue
        
        logger.error(f"❌ 所有 API Key 都失败，跳过本次轮询")
        return []
    
    async def get_current_block_number(self) -> int:
        """获取当前区块高度"""
        await self.init_session()
        
        api_key = self._get_next_api_key()
        
        try: 
            url = f"{PaymentConfig. TRONGRID_API_BASE}/wallet/getnowblock"
            headers = self._get_headers(api_key)
            
            async with self.session.post(url, headers=headers, timeout=10) as response:
                if response.status != 200:
                    return 0
                
                data = await response.json()
                block_header = data.get("block_header", {})
                raw_data = block_header.get("raw_data", {})
                return raw_data.get("number", 0)
        except Exception as e: 
            logger.error(f"❌ 获取当前区块高度失败: {e}")
            return 0

# ================================
# Telegram通知器
# ================================

class TelegramNotifier:
    """Telegram通知器"""
    
    def __init__(self, db: 'PaymentDatabase' = None):
        self.bot_token = os.getenv("BOT_TOKEN") or os.getenv("TELEGRAM_BOT_TOKEN")
        if not self.bot_token:
            logger.error("❌ BOT_TOKEN 未配置！")
        self.api_base = f"https://api.telegram.org/bot{self.bot_token}"
        self.session = None
        self.notify_chat_id = os.getenv("NOTIFY_CHAT_ID") or os.getenv("TELEGRAM_NOTIFY_CHAT_ID")
        self.db = db  # 保存数据库引用以获取 message_id
    
    async def ensure_session(self):
        """确保 session 已初始化"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
    
    async def send_message(self, chat_id: int, text: str, retry: int = 3) -> bool:
        """发送消息 - 带重试"""
        for attempt in range(retry):
            try:
                if not self.bot_token:
                    logger.error("❌ BOT_TOKEN 未配置，无法发送消息")
                    return False
                
                await self.ensure_session()
                
                url = f"{self.api_base}/sendMessage"
                data = {
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML"
                }
                
                logger.info(f"📤 发送消息到 {chat_id}... (尝试 {attempt + 1}/{retry})")
                
                # 增加超时时间到 60 秒
                timeout = aiohttp.ClientTimeout(total=60)
                async with self.session.post(url, json=data, timeout=timeout) as response:
                    result = await response.json()
                    
                    if result.get("ok"):
                        logger.info(f"✅ 消息发送成功: {chat_id}")
                        return True
                    else:
                        error = result.get("description", "未知错误")
                        logger.error(f"❌ Telegram API 错误: {error}")
                        # 如果是用户屏蔽了 bot，不需要重试
                        if "bot was blocked" in error.lower() or "user is deactivated" in error.lower():
                            return False
                        
            except asyncio.TimeoutError:
                logger.warning(f"⏱️ 发送消息超时 (尝试 {attempt + 1}/{retry})")
                if attempt < retry - 1:
                    await asyncio.sleep(2)  # 等待 2 秒后重试
                    continue
            except aiohttp.ClientError as e:
                logger.warning(f"🌐 网络错误: {type(e).__name__}: {e} (尝试 {attempt + 1}/{retry})")
                if attempt < retry - 1:
                    await asyncio.sleep(2)
                    continue
            except Exception as e:
                logger.error(f"❌ 发送消息异常: {type(e).__name__}: {e}")
                if attempt < retry - 1:
                    await asyncio.sleep(2)
                    continue
        
        logger.error(f"❌ 发送消息最终失败: {chat_id}")
        return False
    
    async def close(self):
        """关闭 session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def send_sticker(self, chat_id: int, sticker_id: str, retry: int = 2) -> bool:
        """发送贴纸 - 带重试"""
        for attempt in range(retry):
            try:
                await self.ensure_session()
                url = f"{self.api_base}/sendSticker"
                data = {
                    "chat_id": chat_id,
                    "sticker": sticker_id
                }
                
                logger.info(f"🎉 发送贴纸到 {chat_id}... (尝试 {attempt + 1}/{retry})")
                
                timeout = aiohttp.ClientTimeout(total=30)
                async with self.session.post(url, json=data, timeout=timeout) as response:
                    result = await response.json()
                    if result.get("ok"):
                        logger.info(f"✅ 贴纸发送成功: {chat_id}")
                        return True
                    else:
                        error = result.get("description", "未知错误")
                        logger.warning(f"发送贴纸失败: {error}")
                        if "bot was blocked" in error.lower():
                            return False
                        
            except asyncio.TimeoutError:
                logger.warning(f"⏱️ 发送贴纸超时 (尝试 {attempt + 1}/{retry})")
            except Exception as e:
                logger.warning(f"发送贴纸异常: {type(e).__name__}: {e}")
            
            if attempt < retry - 1:
                await asyncio.sleep(1)
        
        logger.warning(f"⚠️ 发送贴纸最终失败: {chat_id}")
        return False
    
    async def delete_message(self, chat_id: int, message_id: int, retry: int = 2) -> bool:
        """删除消息 - 带重试"""
        for attempt in range(retry):
            try:
                await self.ensure_session()
                url = f"{self.api_base}/deleteMessage"
                data = {"chat_id": chat_id, "message_id": message_id}
                
                timeout = aiohttp.ClientTimeout(total=15)
                async with self.session.post(url, json=data, timeout=timeout) as response:
                    result = await response.json()
                    if result.get("ok"):
                        return True
                    else:
                        error = result.get("description", "")
                        # 消息不存在或已删除，不需要重试
                        if "message to delete not found" in error.lower() or "message can't be deleted" in error.lower():
                            return False
                        logger.warning(f"删除消息失败: {error}")
                        
            except asyncio.TimeoutError:
                logger.warning(f"删除消息超时 (尝试 {attempt + 1}/{retry})")
            except Exception as e:
                logger.warning(f"删除消息异常: {e}")
            
            if attempt < retry - 1:
                await asyncio.sleep(1)
        
        return False
    
    async def send_message_with_keyboard(self, chat_id: int, text: str, keyboard: dict, retry: int = 3) -> bool:
        """发送带键盘的消息 - 带重试"""
        for attempt in range(retry):
            try:
                await self.ensure_session()
                url = f"{self.api_base}/sendMessage"
                data = {
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "reply_markup": keyboard
                }
                
                logger.info(f"📤 发送带按钮消息到 {chat_id}... (尝试 {attempt + 1}/{retry})")
                
                timeout = aiohttp.ClientTimeout(total=60)
                async with self.session.post(url, json=data, timeout=timeout) as response:
                    result = await response.json()
                    
                    if result.get("ok"):
                        logger.info(f"✅ 带按钮消息发送成功: {chat_id}")
                        return True
                    else:
                        error = result.get("description", "未知错误")
                        logger.error(f"❌ Telegram API 错误: {error}")
                        if "bot was blocked" in error.lower():
                            return False
                        
            except asyncio.TimeoutError:
                logger.warning(f"⏱️ 发送消息超时 (尝试 {attempt + 1}/{retry})")
                if attempt < retry - 1:
                    await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"❌ 发送消息异常: {type(e).__name__}: {e}")
                if attempt < retry - 1:
                    await asyncio.sleep(2)
        
        return False
    
    async def notify_payment_received(self, order: PaymentOrder, tx_hash: str, tx_info: dict = None):
        """通知收款成功"""
        logger.info(f"🔔 开始发送支付成功通知: 用户 {order.user_id}, 订单 {order.order_id}")
        
        user_id = order.user_id
        plan = PaymentConfig.PAYMENT_PLANS.get(order.plan_id, {})
        days = plan.get("days", 0)
        
        # 获取套餐名称 - 使用 i18n
        plan_name_key_map = {
            'plan_7d': 'payment_plan_name_7d',
            'plan_30d': 'payment_plan_name_30d',
            'plan_120d': 'payment_plan_name_120d',
            'plan_365d': 'payment_plan_name_365d',
        }
        plan_name_key = plan_name_key_map.get(order.plan_id, 'payment_plan_name_7d')
        plan_name = t(user_id, plan_name_key)
        
        # 1. 删除原消息
        try:
            message_id = self.db.get_order_message_id(order.order_id)
            if message_id:
                deleted = await self.delete_message(user_id, message_id)
                if deleted:
                    logger.info(f"✅ 已删除订单消息: {message_id}")
                else:
                    logger.warning(f"⚠️ 删除订单消息失败: {message_id}")
            else:
                logger.warning(f"⚠️ 未找到订单消息ID: {order.order_id}")
        except Exception as e:
            logger.warning(f"⚠️ 删除消息异常: {type(e).__name__}: {e}")
        
        # 2. 发送庆祝贴纸
        logger.info(f"🎉 准备发送庆祝贴纸到 {user_id}...")
        sticker_id = "CAACAgIAAxkBAAFAr4hpZ4gcZrgcsdUcW-1DFfn8MqzMcgAC1hgAAt_skUmRnB_mBcJtujgE"
        sticker_sent = await self.send_sticker(user_id, sticker_id)
        if sticker_sent:
            logger.info(f"✅ 贴纸发送成功")
            await asyncio.sleep(0.5)  # 短暂等待
        else:
            logger.warning(f"⚠️ 贴纸发送失败，继续发送文字消息...")
        
        # 3. 获取会员到期时间
        expiry_time = "未知"
        try:
            conn = sqlite3.connect(PaymentConfig.MAIN_DB)
            c = conn.cursor()
            c.execute("SELECT expiry_time FROM memberships WHERE user_id = ?", (user_id,))
            row = c.fetchone()
            conn.close()
            
            if row and row[0]:
                try:
                    # 数据库中存储的是字符串格式: "YYYY-MM-DD HH:MM:SS"
                    expiry = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                    expiry_time = expiry.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    expiry_time = row[0]
        except Exception as e:
            logger.warning(f"获取会员到期时间失败: {e}")
        
        # 4. 发送用户成功消息 - 使用 i18n
        success_title = t(user_id, 'payment_success_title')
        success_confirmed = t(user_id, 'payment_success_confirmed')
        order_info_title = t(user_id, 'payment_order_info_title')
        order_id_label = t(user_id, 'payment_order_id')
        plan_label = t(user_id, 'payment_plan')
        amount_label = t(user_id, 'payment_amount')
        days_label = t(user_id, 'payment_member_days')
        expiry_label = t(user_id, 'payment_member_expiry')
        thanks_msg = t(user_id, 'payment_thanks')
        
        user_msg = f"""
{success_title}

{success_confirmed}

<b>{order_info_title}</b>
• {order_id_label}: <code>{order.order_id}</code>
• {plan_label}: {plan_name}
• {amount_label}: {order.amount:.4f} USDT
• {days_label}: +{days} 天
• {expiry_label}: {expiry_time}

{thanks_msg}
        """
        
        logger.info(f"📝 准备发送成功消息到 {user_id}...")
        msg_sent = await self.send_message(user_id, user_msg)
        if msg_sent:
            logger.info(f"✅ 用户成功消息发送完成: {user_id}")
        else:
            logger.error(f"❌ 用户成功消息发送失败: {user_id}")
        
        # 5. 发送管理员通知 - 使用 i18n
        if self.notify_chat_id:
            logger.info(f"📢 准备发送管理员通知...")
            # 获取地址信息（如果有）
            from_address = "未知"
            to_address = PaymentConfig.WALLET_ADDRESS
            
            if tx_info:
                from_address = tx_info.get("from_address", "未知")
                to_address = tx_info.get("to_address", to_address)
            
            # 地址脱敏显示
            def mask_address(addr):
                if len(addr) > 15:
                    return f"{addr[:8]}*****{addr[-8:]}"
                return addr
            
            # 管理员通知使用中文（因为管理员通常是中文用户）
            admin_new_order = t(user_id, 'payment_admin_new_order')
            admin_order_info = t(user_id, 'payment_order_info_title')
            admin_user_id = t(user_id, 'payment_user_id')
            admin_address_info = t(user_id, 'payment_address_info')
            admin_receive_addr = t(user_id, 'payment_receive_address')
            admin_send_addr = t(user_id, 'payment_send_address')
            view_tx_btn = t(user_id, 'btn_view_transaction')
            
            admin_msg = f"""
{admin_new_order}

<b>{admin_order_info}</b>
• {order_id_label}: <code>{order.order_id}</code>
• {admin_user_id}: {user_id}
• {plan_label}: {plan_name}
• {amount_label}: {order.amount:.4f} USDT
• {days_label}: {days} 天
• {expiry_label}: {expiry_time}

<b>{admin_address_info}</b>
{admin_receive_addr}: <code>{mask_address(to_address)}</code>
{admin_send_addr}: <code>{mask_address(from_address)}</code>
            """
            
            # 发送带按钮的消息
            try:
                # 导入 InlineKeyboardMarkup 和 InlineKeyboardButton（需要在函数内导入）
                from telegram import InlineKeyboardMarkup, InlineKeyboardButton
                
                keyboard = InlineKeyboardMarkup([
                    [InlineKeyboardButton(view_tx_btn, url=f"https://tronscan.org/#/transaction/{tx_hash}")]
                ])
                
                # 转换为 dict 格式
                keyboard_dict = keyboard.to_dict()
                
                await self.send_message_with_keyboard(int(self.notify_chat_id), admin_msg, keyboard_dict)
            except Exception as e:
                logger.error(f"发送管理员通知失败: {e}")
                # 如果带按钮的消息失败，至少发送纯文本消息
                await self.send_message(int(self.notify_chat_id), admin_msg)

# ================================
# 主服务类
# ================================

class TronPaymentService:
    """TRON支付服务"""
    
    def __init__(self):
        self.db = PaymentDatabase()
        self.order_manager = OrderManager(self.db)
        self.monitor = TronUSDTMonitor(
            PaymentConfig.WALLET_ADDRESS,
            PaymentConfig.TRONGRID_API_KEYS  # 传入 Key 列表
        )
        self.notifier = TelegramNotifier(self.db)  # 传入数据库引用
        self.running = False
    
    async def start(self):
        """启动服务"""
        logger.info("🚀 TRON支付服务启动中...")
        
        # 验证配置
        valid, msg = PaymentConfig.validate()
        if not valid:
            logger.error(f"❌ 配置验证失败: {msg}")
            return
        
        logger.info(f"✅ {msg}")
        logger.info(f"📡 监听钱包: {PaymentConfig.WALLET_ADDRESS}")
        logger.info(f"🔑 API Keys: {PaymentConfig.get_api_keys_info()}")
        logger.info(f"⏱️ 轮询间隔:  {PaymentConfig. POLL_INTERVAL_SECONDS}秒")
        logger.info(f"🔐 最少确认数: {PaymentConfig.MIN_CONFIRMATIONS}")
        
        self.running = True
        
        try:
            while self.running:
                try:
                    # 1. 检查并处理过期订单（删除消息+发送通知）
                    await self.check_expired_orders()
                    
                    # 2. 过期超时订单（标记状态）
                    self.order_manager.expire_old_orders()
                    
                    # 3. 获取待支付订单
                    pending_orders = self.db.get_pending_orders()
                    if not pending_orders:
                        await asyncio.sleep(PaymentConfig.POLL_INTERVAL_SECONDS)
                        continue
                    
                    logger.info(f"📊 当前待支付订单: {len(pending_orders)} 个")
                    
                    # 4. 获取最新交易
                    transactions = await self.monitor.get_trc20_transactions(limit=50)
                    logger.info(f"🔍 获取到 {len(transactions)} 笔交易")
                    
                    # 5. 匹配订单和交易
                    for tx in transactions:
                        # 检查是否已处理
                        if self.db.is_transaction_processed(tx.tx_hash):
                            continue
                        
                        # 检查确认数
                        if tx.confirmations < PaymentConfig.MIN_CONFIRMATIONS:
                            logger.info(f"⏳ 交易 {tx.tx_hash[:16]}... 确认数不足: {tx.confirmations}/{PaymentConfig.MIN_CONFIRMATIONS}")
                            continue
                        
                        # 验证合约地址
                        if tx.contract_address != PaymentConfig.USDT_CONTRACT:
                            logger.warning(f"⚠️ 非官方USDT合约: {tx.contract_address}")
                            tx.processed = True
                            self.db.save_transaction(tx)
                            continue
                        
                        # 获取交易时间
                        tx_time = datetime.fromtimestamp(tx.timestamp, tz=BEIJING_TZ)
                        now = datetime.now(BEIJING_TZ)
                        
                        # 安全检查1: 交易不能太旧（15分钟内）
                        if (now - tx_time).total_seconds() > 900:
                            logger.info(f"⏱️ 交易太旧（超过15分钟），标记已处理: {tx.tx_hash[:16]}...")
                            tx.processed = True
                            self.db.save_transaction(tx)
                            continue
                        
                        # 匹配订单
                        matched_order = None
                        for order in pending_orders:
                            # 安全检查2: 订单必须未过期
                            order_expires = order.expires_at
                            if order_expires.tzinfo is None:
                                order_expires = order_expires.replace(tzinfo=BEIJING_TZ)
                            
                            if now > order_expires:
                                self.db.update_order_status(order.order_id, OrderStatus.EXPIRED)
                                continue
                            
                            # 安全检查3: 金额精确匹配
                            if abs(tx.amount - order.amount) >= 0.0001:
                                continue
                            
                            # 安全检查4: 交易时间必须在订单创建之后
                            order_created = order.created_at
                            if order_created.tzinfo is None:
                                order_created = order_created.replace(tzinfo=BEIJING_TZ)
                            
                            if tx_time < order_created - timedelta(minutes=1):
                                continue
                            
                            # 安全检查5: 交易时间必须在订单有效期内
                            if tx_time > order_expires:
                                continue
                            
                            matched_order = order
                            break
                        
                        if matched_order:
                            logger.info(f"✅ 交易匹配成功: {tx.tx_hash[:16]}... -> 订单 {matched_order.order_id}")
                            
                            # 更新订单状态
                            self.db.update_order_status(
                                matched_order.order_id,
                                OrderStatus.PAID,
                                tx.tx_hash
                            )
                            
                            # 授予会员
                            success = await self.grant_membership(matched_order)
                            
                            if success:
                                # 更新为完成状态
                                self.db.update_order_status(
                                    matched_order.order_id,
                                    OrderStatus.COMPLETED
                                )
                                
                                # 发送通知 - 传递交易信息
                                tx_info_dict = {
                                    "from_address": tx.from_address,
                                    "to_address": tx.to_address
                                }
                                await self.notifier.notify_payment_received(
                                    matched_order,
                                    tx.tx_hash,
                                    tx_info_dict
                                )
                            
                            # 标记交易已处理
                            tx.processed = True
                            self.db.save_transaction(tx)
                        else:
                            # 未匹配的交易也标记已处理
                            logger.info(f"ℹ️ 交易未匹配订单: {tx.amount:.4f} USDT")
                            tx.processed = True
                            self.db.save_transaction(tx)
                    
                except Exception as e:
                    logger.error(f"❌ 监听循环异常: {e}")
                
                # 等待下一次轮询
                await asyncio.sleep(PaymentConfig.POLL_INTERVAL_SECONDS)
                
        finally:
            await self.stop()
    
    async def stop(self):
        """停止服务"""
        logger.info("🛑 正在停止服务...")
        self.running = False
        await self.monitor.close_session()
        await self.notifier.close()
        logger.info("✅ 服务已停止")
    
    async def check_expired_orders(self):
        """检查并处理过期订单"""
        try:
            expired_orders = self.db.get_expired_pending_orders()
            
            for order in expired_orders:
                logger.info(f"⏱️ 订单超时: {order.order_id}")
                
                # 1. 更新订单状态为过期
                self.db.update_order_status(order.order_id, OrderStatus.EXPIRED)
                
                # 2. 删除原订单消息
                try:
                    message_id = self.db.get_order_message_id(order.order_id)
                    if message_id:
                        deleted = await self.notifier.delete_message(order.user_id, message_id)
                        if deleted:
                            logger.info(f"✅ 已删除超时订单消息: {message_id}")
                        else:
                            logger.warning(f"⚠️ 删除超时订单消息失败: {message_id}")
                except Exception as e:
                    logger.warning(f"⚠️ 删除超时订单消息异常: {e}")
                
                # 3. 发送超时通知给用户
                timeout_msg = f"""
⏱️ <b>订单已超时</b>

• 订单号: <code>{order.order_id}</code>
• 状态: 已超时

订单已超过有效期，如需购买会员请重新下单。
                """
                
                # 使用 Telegram API 发送带按钮的消息
                keyboard = {
                    "inline_keyboard": [
                        [{"text": "💎 重新购买", "callback_data": "usdt_payment"}],
                        [{"text": "🔙 返回主菜单", "callback_data": "back_to_main"}]
                    ]
                }
                
                await self.notifier.send_message_with_keyboard(
                    order.user_id,
                    timeout_msg,
                    keyboard
                )
                logger.info(f"✅ 已发送超时通知: 用户 {order.user_id}")
                
        except Exception as e:
            logger.error(f"❌ 检查过期订单失败: {e}")
            import traceback
            traceback.print_exc()
    
    async def grant_membership(self, order: PaymentOrder) -> bool:
        """授予会员 - 使用与 tdata.py 相同的数据库和格式
        
        Args:
            order: 订单对象
            
        Returns:
            是否成功
        """
        try:
            # 获取套餐信息
            plan = PaymentConfig.PAYMENT_PLANS.get(order.plan_id)
            if not plan:
                logger.error(f"❌ 无效的套餐ID: {order.plan_id}")
                return False
            
            days = plan["days"]
            
            # 连接主数据库授予会员
            conn = sqlite3.connect(PaymentConfig.MAIN_DB)
            c = conn.cursor()
            
            # 自动建表：确保 memberships 表存在（与 tdata.py 相同的结构）
            c.execute("""
                CREATE TABLE IF NOT EXISTS memberships (
                    user_id INTEGER PRIMARY KEY,
                    level TEXT,
                    trial_expiry_time TEXT,
                    created_at TEXT
                )
            """)
            
            # 添加 expiry_time 列（如果不存在）
            try:
                c.execute("ALTER TABLE memberships ADD COLUMN expiry_time TEXT")
            except sqlite3.OperationalError:
                # 列已存在，忽略
                pass
            
            # 检查用户是否已有会员记录
            c.execute("SELECT expiry_time FROM memberships WHERE user_id = ?", (order.user_id,))
            row = c.fetchone()
            
            now = datetime.now(BEIJING_TZ)
            
            if row and row[0]:
                # 已有到期时间，从到期时间继续累加
                try:
                    # Database stores naive datetime strings, parse with strptime
                    current_expiry = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                    # 如果到期时间在未来，从到期时间累加
                    if current_expiry > now.replace(tzinfo=None):
                        new_expiry = current_expiry + timedelta(days=days)
                    else:
                        # 已过期，从当前时间累加
                        new_expiry = now.replace(tzinfo=None) + timedelta(days=days)
                except Exception as e:
                    logger.warning(f"解析到期时间失败: {e}，从当前时间计算")
                    new_expiry = now.replace(tzinfo=None) + timedelta(days=days)
            else:
                # 新会员，从当前时间累加
                new_expiry = now.replace(tzinfo=None) + timedelta(days=days)
            
            # 使用 INSERT OR REPLACE 和与 tdata.py 相同的格式
            c.execute("""
                INSERT OR REPLACE INTO memberships 
                (user_id, level, expiry_time, created_at)
                VALUES (?, ?, ?, ?)
            """, (order.user_id, '会员', new_expiry.strftime("%Y-%m-%d %H:%M:%S"), 
                  now.strftime("%Y-%m-%d %H:%M:%S")))
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ 会员授予成功: 用户 {order.user_id}, 天数 {days}, 到期 {new_expiry.strftime('%Y-%m-%d %H:%M:%S')}")
            return True
            
        except Exception as e:
            logger.error(f"❌ 授予会员失败: {e}")
            import traceback
            traceback.print_exc()
            return False

# ================================
# 主函数
# ================================

async def main():
    """主函数"""
    print("=" * 50)
    print("🚀 TRON USDT-TRC20 支付监听服务")
    print("=" * 50)
    
    service = TronPaymentService()
    
    try:
        await service.start()
    except KeyboardInterrupt:
        print("\n👋 服务已停止")
    except Exception as e:
        logger.error(f"❌ 服务异常: {e}")
    finally:
        await service.stop()

if __name__ == "__main__":
    asyncio.run(main())