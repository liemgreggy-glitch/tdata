"""
Passkey（通行密钥）批量检测与删除管理器

通过 MTProto API 实现，无需浏览器。
依据 Telegram Desktop 官方源码（passkeys.cpp）确认以下 API：
- account.GetPasskeys  — 获取账号绑定的所有 Passkey 列表
- account.DeletePasskey(id) — 删除指定 Passkey
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import struct
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# 超时配置（秒）
CONNECT_TIMEOUT = 30       # 建立连接超时
AUTH_TIMEOUT = 20          # is_user_authorized 超时
GET_ME_TIMEOUT = 20        # get_me 超时
GET_PASSKEYS_TIMEOUT = 30  # GetPasskeys API 超时
DELETE_PASSKEY_TIMEOUT = 20  # DeletePasskey API 超时
DISCONNECT_TIMEOUT = 10    # 断开连接超时
ACCOUNT_TOTAL_TIMEOUT = 120  # 单账号整体超时

# ---------------------------------------------------------------------------
# 尝试导入 Telethon
# ---------------------------------------------------------------------------
try:
    from telethon import TelegramClient
    from telethon.tl.tlobject import TLObject
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False

# 尝试导入 opentele（TData 转换）
try:
    from opentele.api import UseCurrentSession
    from opentele.td import TDesktop
    OPENTELE_AVAILABLE = True
except ImportError:
    OPENTELE_AVAILABLE = False

# 尝试导入 PySocks（代理支持）
try:
    import socks
    PROXY_SUPPORT = True
except ImportError:
    PROXY_SUPPORT = False


# ---------------------------------------------------------------------------
# 尝试导入官方 Passkey 请求类（Telethon 较新版本）
# ---------------------------------------------------------------------------
try:
    from telethon.tl.functions.account import GetPasskeysRequest
    _HAS_GET_PASSKEYS = True
except ImportError:
    _HAS_GET_PASSKEYS = False

try:
    from telethon.tl.functions.account import DeletePasskeyRequest
    _HAS_DELETE_PASSKEY = True
except ImportError:
    _HAS_DELETE_PASSKEY = False


# ---------------------------------------------------------------------------
# 原始 TL 构造器（兼容旧版 Telethon，当官方 Request 类不存在时使用）
# ---------------------------------------------------------------------------
def _make_get_passkeys_request():
    """构造 account.GetPasskeys 原始请求（CONSTRUCTOR_ID = 0xea1f0c52）"""
    if _HAS_GET_PASSKEYS:
        return GetPasskeysRequest()

    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLRequest as _TLObject

    from telethon.tl import TLObject as _TLBase
    import telethon.tl.core as _core

    class _Passkey(_TLObject):
        CONSTRUCTOR_ID = 0x98613ebf
        SUBCLASS_OF_ID = 0x98613ebf

        def __init__(self, id='', name='', date=0, flags=0,
                     software_emoji_id=None, last_usage_date=None):
            self.id = id
            self.name = name
            self.date = date
            self.flags = flags
            self.software_emoji_id = software_emoji_id
            self.last_usage_date = last_usage_date

        @classmethod
        def from_reader(cls, reader):
            flags = reader.read_int()
            id_ = reader.tgread_string()
            name = reader.tgread_string()
            date = reader.read_int()
            software_emoji_id = reader.read_long() if flags & 1 else None
            last_usage_date = reader.read_int() if flags & 2 else None
            return cls(id=id_, name=name, date=date, flags=flags,
                       software_emoji_id=software_emoji_id,
                       last_usage_date=last_usage_date)

    class _AccountPasskeys(_TLObject):
        CONSTRUCTOR_ID = 0xf8e0aa1c
        SUBCLASS_OF_ID = 0xf8e0aa1c

        def __init__(self, passkeys=None):
            self.passkeys = passkeys or []

        @classmethod
        def from_reader(cls, reader):
            passkeys = reader.tgread_vector()
            return cls(passkeys=passkeys)

    # 注册到 Telethon
    from telethon.tl.alltlobjects import tlobjects
    tlobjects[_Passkey.CONSTRUCTOR_ID] = _Passkey
    tlobjects[_AccountPasskeys.CONSTRUCTOR_ID] = _AccountPasskeys

    class _GetPasskeysRequest(_TLObject):
        CONSTRUCTOR_ID = 0xea1f0c52
        SUBCLASS_OF_ID = 0x5c4a9289

        def __init__(self):
            pass

        def to_dict(self):
            return {'_': 'account.GetPasskeys'}

        def _bytes(self):
            import struct
            return struct.pack('<I', self.CONSTRUCTOR_ID)

    return _GetPasskeysRequest()


def _make_delete_passkey_request(passkey_id: str):
    """构造 account.DeletePasskey 原始请求（CONSTRUCTOR_ID = 0xf5b5563f）"""
    if _HAS_DELETE_PASSKEY:
        return DeletePasskeyRequest(id=passkey_id)

    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLRequest as _TLObject

    class _DeletePasskeyRequest(_TLObject):
        CONSTRUCTOR_ID = 0xf5b5563f
        SUBCLASS_OF_ID = 0xf5b399ac

        def __init__(self, id: str):
            self.id = id

        def to_dict(self):
            return {'_': 'account.DeletePasskey', 'id': self.id}

        def _bytes(self):
            import struct
            id_bytes = self.id.encode('utf-8')
            n = len(id_bytes)
            if n < 254:
                header = bytes([n])
                padding = b'\x00' * ((-(n + 1)) % 4)
            else:
                header = bytes([254]) + struct.pack('<I', n)[:3]
                padding = b'\x00' * ((-n) % 4)
            return struct.pack('<I', self.CONSTRUCTOR_ID) + header + id_bytes + padding

    return _DeletePasskeyRequest(id=passkey_id)


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------
@dataclass
class PasskeyInfo:
    id: str
    name: str = ""
    date: int = 0        # 注册时间 unix timestamp
    last_usage: int = 0  # 最后使用时间


@dataclass
class PasskeyResult:
    account_name: str
    phone: str = ""
    file_type: str = "session"
    has_passkey: bool = False
    passkeys: List[PasskeyInfo] = field(default_factory=list)
    deleted_count: int = 0
    delete_failed: List[str] = field(default_factory=list)
    status: str = "pending"   # pending / no_passkey / deleted / failed
    error: Optional[str] = None
    elapsed: float = 0.0


# ---------------------------------------------------------------------------
# PasskeyManager 主类
# ---------------------------------------------------------------------------
class PasskeyManager:
    DEFAULT_CONCURRENT = 20

    def __init__(self, proxy_manager, db):
        self.proxy_manager = proxy_manager
        self.db = db

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------
    async def batch_process(
        self,
        files: List[Tuple[str, str]],   # [(path, display_name)]
        file_type: str,                  # 'session' | 'tdata'
        progress_callback=None,
        concurrent: int = DEFAULT_CONCURRENT,
    ) -> Dict[str, List[PasskeyResult]]:
        """批量处理账号 Passkey，返回分类结果字典"""
        total = len(files)
        logger.info(f"[Passkey] 批量处理开始: 共 {total} 个账号, 类型={file_type}, 并发={concurrent}")
        print(f"[Passkey] ▶ 批量处理开始: 共 {total} 个账号 | 类型={file_type} | 并发={concurrent}")

        semaphore = asyncio.Semaphore(concurrent)
        results: List[PasskeyResult] = []
        done_count = 0

        async def _process_with_sem(file_path, file_name):
            nonlocal done_count
            async with semaphore:
                result = await self._process_one(file_path, file_name, file_type)
                results.append(result)
                done_count += 1
                status_icon = {'no_passkey': '🔓', 'deleted': '✅', 'failed': '❌'}.get(result.status, '?')
                print(f"[Passkey] {status_icon} [{done_count}/{total}] {file_name} => {result.status}"
                      + (f" | 错误: {result.error}" if result.error else "")
                      + (f" | 已删除 {result.deleted_count} 个Passkey" if result.deleted_count else ""))
                if progress_callback:
                    try:
                        await progress_callback(done_count, total, result)
                    except Exception as cb_err:
                        logger.warning(f"[Passkey] 进度回调异常: {cb_err}")

        tasks = [
            asyncio.create_task(_process_with_sem(fp, fn))
            for fp, fn in files
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        categorized: Dict[str, List[PasskeyResult]] = {
            'no_passkey': [],
            'deleted': [],
            'failed': [],
        }
        for r in results:
            if r.status == 'no_passkey':
                categorized['no_passkey'].append(r)
            elif r.status == 'deleted':
                categorized['deleted'].append(r)
            else:
                categorized['failed'].append(r)

        no_pk = len(categorized['no_passkey'])
        deleted = len(categorized['deleted'])
        failed = len(categorized['failed'])
        total_keys = sum(r.deleted_count for r in categorized['deleted'])
        logger.info(f"[Passkey] 批量处理完成: 无Passkey={no_pk}, 已删除={deleted}(共{total_keys}个key), 失败={failed}")
        print(f"[Passkey] ■ 批量处理完成: 🔓无Passkey={no_pk} | ✅已删除={deleted}(共{total_keys}个key) | ❌失败={failed}")
        return categorized

    # ------------------------------------------------------------------
    # 内部：处理单个账号
    # ------------------------------------------------------------------
    async def _process_one(
        self, file_path: str, file_name: str, file_type: str
    ) -> PasskeyResult:
        result = PasskeyResult(account_name=file_name, file_type=file_type)
        start = time.time()
        client = None
        temp_session = None

        logger.info(f"[Passkey] 开始处理账号: {file_name} (类型={file_type})")
        print(f"[Passkey] → 处理账号: {file_name}")

        try:
            # 整体超时保护
            result = await asyncio.wait_for(
                self._process_one_inner(file_path, file_name, file_type),
                timeout=ACCOUNT_TOTAL_TIMEOUT
            )
        except asyncio.TimeoutError:
            elapsed = round(time.time() - start, 1)
            logger.error(f"[Passkey] 账号 {file_name} 整体超时 ({ACCOUNT_TOTAL_TIMEOUT}s), 已用时 {elapsed}s")
            print(f"[Passkey] ⏱ 账号 {file_name} 整体超时 ({ACCOUNT_TOTAL_TIMEOUT}s)")
            result = PasskeyResult(account_name=file_name, file_type=file_type,
                                   status='failed', error=f'处理超时({ACCOUNT_TOTAL_TIMEOUT}s)')
        except Exception as e:
            elapsed = round(time.time() - start, 1)
            logger.error(f"[Passkey] 账号 {file_name} 处理异常 ({elapsed}s): {e}", exc_info=True)
            print(f"[Passkey] ✗ 账号 {file_name} 处理异常: {e}")
            result = PasskeyResult(account_name=file_name, file_type=file_type,
                                   status='failed', error=str(e))

        result.elapsed = time.time() - start
        return result

    async def _process_one_inner(
        self, file_path: str, file_name: str, file_type: str
    ) -> PasskeyResult:
        """实际处理逻辑（由 _process_one 包裹整体超时）"""
        result = PasskeyResult(account_name=file_name, file_type=file_type)
        start = time.time()
        client = None
        temp_session = None

        try:
            # 1. 连接
            logger.info(f"[Passkey] {file_name}: 建立连接...")
            print(f"[Passkey]   {file_name}: 建立连接...")
            client, temp_session = await self._connect(file_path, file_name, file_type)
            if client is None:
                result.status = 'failed'
                result.error = '无法创建客户端连接'
                logger.error(f"[Passkey] {file_name}: 连接失败 - 客户端为None")
                print(f"[Passkey]   {file_name}: ✗ 连接失败")
                return result
            logger.info(f"[Passkey] {file_name}: 连接成功")
            print(f"[Passkey]   {file_name}: ✓ 连接成功")

            # 2. 检查授权
            logger.info(f"[Passkey] {file_name}: 检查账号授权状态...")
            print(f"[Passkey]   {file_name}: 检查授权...")
            try:
                is_authorized = await asyncio.wait_for(
                    client.is_user_authorized(), timeout=AUTH_TIMEOUT
                )
            except asyncio.TimeoutError:
                result.status = 'failed'
                result.error = f'授权检查超时({AUTH_TIMEOUT}s)'
                logger.error(f"[Passkey] {file_name}: 授权检查超时")
                print(f"[Passkey]   {file_name}: ✗ 授权检查超时")
                return result

            if not is_authorized:
                result.status = 'failed'
                result.error = '账号未授权'
                logger.warning(f"[Passkey] {file_name}: 账号未授权")
                print(f"[Passkey]   {file_name}: ✗ 账号未授权")
                return result
            logger.info(f"[Passkey] {file_name}: 账号已授权")
            print(f"[Passkey]   {file_name}: ✓ 账号已授权")

            # 3. 获取手机号（可选）
            try:
                me = await asyncio.wait_for(client.get_me(), timeout=GET_ME_TIMEOUT)
                if me and hasattr(me, 'phone') and me.phone:
                    result.phone = me.phone
                    logger.info(f"[Passkey] {file_name}: 手机号={result.phone}")
                    print(f"[Passkey]   {file_name}: 手机号={result.phone}")
            except asyncio.TimeoutError:
                logger.warning(f"[Passkey] {file_name}: get_me 超时，跳过")
                print(f"[Passkey]   {file_name}: ⚠ get_me 超时，跳过")
            except Exception as e:
                logger.warning(f"[Passkey] {file_name}: get_me 失败: {e}")

            # 4. 获取 Passkey 列表
            logger.info(f"[Passkey] {file_name}: 调用 account.GetPasskeys...")
            print(f"[Passkey]   {file_name}: 调用 GetPasskeys API...")
            passkeys = await self._get_passkeys(client)
            result.passkeys = passkeys
            result.has_passkey = len(passkeys) > 0
            logger.info(f"[Passkey] {file_name}: 找到 {len(passkeys)} 个Passkey")
            print(f"[Passkey]   {file_name}: 找到 {len(passkeys)} 个Passkey")

            if not passkeys:
                result.status = 'no_passkey'
                return result

            # 5. 逐个删除
            for pk in passkeys:
                pk_label = pk.name or pk.id
                logger.info(f"[Passkey] {file_name}: 删除Passkey [{pk_label}]...")
                print(f"[Passkey]   {file_name}: 删除Passkey [{pk_label}]...")
                success, err = await self._delete_passkey(client, pk.id)
                if success:
                    result.deleted_count += 1
                    logger.info(f"[Passkey] {file_name}: Passkey [{pk_label}] 删除成功")
                    print(f"[Passkey]   {file_name}: ✓ Passkey [{pk_label}] 删除成功")
                else:
                    result.delete_failed.append(f"{pk_label}: {err}")
                    logger.warning(f"[Passkey] {file_name}: Passkey [{pk_label}] 删除失败: {err}")
                    print(f"[Passkey]   {file_name}: ✗ Passkey [{pk_label}] 删除失败: {err}")

            if result.delete_failed and result.deleted_count == 0:
                result.status = 'failed'
                result.error = '所有Passkey删除失败: ' + '; '.join(result.delete_failed)
            else:
                result.status = 'deleted'

        except Exception as e:
            result.status = 'failed'
            result.error = str(e)
            logger.error(f"[Passkey] {file_name}: 处理异常: {e}", exc_info=True)
            print(f"[Passkey]   {file_name}: ✗ 异常: {e}")

        finally:
            if client:
                try:
                    logger.info(f"[Passkey] {file_name}: 断开连接...")
                    await asyncio.wait_for(client.disconnect(), timeout=DISCONNECT_TIMEOUT)
                    print(f"[Passkey]   {file_name}: 已断开连接")
                except Exception:
                    pass
            if temp_session and os.path.exists(temp_session):
                try:
                    os.remove(temp_session)
                except Exception:
                    pass

        result.elapsed = time.time() - start
        return result

    # ------------------------------------------------------------------
    # 内部：获取 Passkey 列表
    # ------------------------------------------------------------------
    async def _get_passkeys(self, client) -> List[PasskeyInfo]:
        try:
            request = _make_get_passkeys_request()
            logger.debug(f"[Passkey] GetPasskeys 请求对象: {type(request).__name__}")
            response = await asyncio.wait_for(client(request), timeout=GET_PASSKEYS_TIMEOUT)
            logger.debug(f"[Passkey] GetPasskeys 响应类型: {type(response).__name__}")
            passkeys = []
            items = []
            if hasattr(response, 'passkeys'):
                items = response.passkeys
            elif hasattr(response, 'results'):
                items = response.results
            elif isinstance(response, (list, tuple)):
                items = list(response)

            for item in items:
                pk_id = str(getattr(item, 'id', '') or '')
                pk_name = str(getattr(item, 'name', '') or '')
                pk_date = int(getattr(item, 'date', 0) or 0)
                pk_last = int(getattr(item, 'last_usage_date', 0) or 0)
                passkeys.append(PasskeyInfo(
                    id=pk_id,
                    name=pk_name,
                    date=pk_date,
                    last_usage=pk_last,
                ))
            return passkeys
        except asyncio.TimeoutError:
            logger.error(f"[Passkey] GetPasskeys 调用超时 ({GET_PASSKEYS_TIMEOUT}s) — API可能不支持此版本Telethon")
            print(f"[Passkey]   ⏱ GetPasskeys 超时({GET_PASSKEYS_TIMEOUT}s)，视为无Passkey")
            return []
        except Exception as e:
            err_str = str(e).lower()
            logger.warning(f"[Passkey] GetPasskeys 异常: {e}")
            # 账号未绑定 Passkey 时服务端可能返回空列表或特定错误
            if 'no passkey' in err_str or 'not found' in err_str or 'empty' in err_str:
                logger.info("[Passkey] GetPasskeys: 服务端返回无Passkey")
                return []
            # 功能不支持（旧版 API 层）或方法未知
            if ('method' in err_str and ('invalid' in err_str or 'unknown' in err_str)) \
                    or 'not supported' in err_str or 'constructor' in err_str:
                logger.warning(f"[Passkey] GetPasskeys API 不支持，视为无Passkey: {e}")
                print(f"[Passkey]   ⚠ GetPasskeys API不支持，视为无Passkey")
                return []
            raise

    # ------------------------------------------------------------------
    # 内部：删除单个 Passkey
    # ------------------------------------------------------------------
    async def _delete_passkey(self, client, passkey_id: str) -> Tuple[bool, str]:
        try:
            request = _make_delete_passkey_request(passkey_id)
            await asyncio.wait_for(client(request), timeout=DELETE_PASSKEY_TIMEOUT)
            return True, ""
        except asyncio.TimeoutError:
            msg = f"DeletePasskey 超时({DELETE_PASSKEY_TIMEOUT}s)"
            logger.error(f"[Passkey] {msg} id={passkey_id}")
            print(f"[Passkey]   ⏱ {msg}")
            return False, msg
        except Exception as e:
            logger.warning(f"[Passkey] DeletePasskey 失败 id={passkey_id}: {e}")
            return False, str(e)

    # ------------------------------------------------------------------
    # 内部：创建客户端连接
    # ------------------------------------------------------------------
    async def _connect(
        self, file_path: str, file_name: str, file_type: str
    ):
        """返回 (client, temp_session_path_or_None)"""
        api_id, api_hash = self._get_api_credentials()
        proxy_dict = self._get_proxy()
        temp_session = None

        proxy_info_str = f"代理={proxy_dict.get('addr', '')}:{proxy_dict.get('port', '')}" if proxy_dict else "无代理"
        logger.info(f"[Passkey] {file_name}: 创建连接 ({proxy_info_str})")
        print(f"[Passkey]   {file_name}: 建立连接 ({proxy_info_str})")

        try:
            if file_type == 'tdata':
                if not OPENTELE_AVAILABLE:
                    raise RuntimeError("opentele 未安装，无法处理 TData 格式")
                logger.info(f"[Passkey] {file_name}: TData -> 转换为临时Session...")
                print(f"[Passkey]   {file_name}: TData转换中...")
                tdesk = TDesktop(file_path)
                fd, temp_session = tempfile.mkstemp(suffix='.session', prefix='passkey_tmp_')
                os.close(fd)
                os.remove(temp_session)
                client = await asyncio.wait_for(
                    tdesk.ToTelethon(temp_session, flag=UseCurrentSession),
                    timeout=CONNECT_TIMEOUT
                )
                if not client.is_connected():
                    await asyncio.wait_for(client.connect(), timeout=CONNECT_TIMEOUT)
                logger.info(f"[Passkey] {file_name}: TData转换并连接成功")
                print(f"[Passkey]   {file_name}: TData转换成功")
            else:
                # session 或 session-json
                session_path = file_path
                if session_path.endswith('.session'):
                    session_path = session_path[:-len('.session')]
                kwargs = {'proxy': proxy_dict} if proxy_dict else {}
                logger.info(f"[Passkey] {file_name}: Session连接 path={session_path}")
                print(f"[Passkey]   {file_name}: Session连接中...")
                client = TelegramClient(session_path, api_id, api_hash, **kwargs)
                await asyncio.wait_for(client.connect(), timeout=CONNECT_TIMEOUT)
                logger.info(f"[Passkey] {file_name}: Session连接完成")

            return client, temp_session

        except asyncio.TimeoutError:
            logger.error(f"[Passkey] {file_name}: 连接超时 ({CONNECT_TIMEOUT}s)")
            print(f"[Passkey]   {file_name}: ✗ 连接超时({CONNECT_TIMEOUT}s)")
            if temp_session and os.path.exists(temp_session):
                try:
                    os.remove(temp_session)
                except Exception:
                    pass
            raise RuntimeError(f"连接超时({CONNECT_TIMEOUT}s)")
        except Exception as e:
            logger.error(f"[Passkey] {file_name}: 连接异常: {e}")
            print(f"[Passkey]   {file_name}: ✗ 连接异常: {e}")
            if temp_session and os.path.exists(temp_session):
                try:
                    os.remove(temp_session)
                except Exception:
                    pass
            raise

    # ------------------------------------------------------------------
    # 内部：获取 API 凭证
    # ------------------------------------------------------------------
    def _get_api_credentials(self) -> Tuple[int, str]:
        api_id = int(os.getenv('API_ID', '2040'))
        api_hash = os.getenv('API_HASH', 'b18441a1ff607e10a989891a5462e627')
        logger.debug(f"[Passkey] API凭证: api_id={api_id}")
        return api_id, api_hash

    # ------------------------------------------------------------------
    # 内部：获取代理
    # ------------------------------------------------------------------
    def _get_proxy(self) -> Optional[dict]:
        if not self.proxy_manager:
            return None
        try:
            proxy_info = self.proxy_manager.get_next_proxy()
            if not proxy_info:
                logger.debug("[Passkey] 无可用代理，直连")
                return None
            if not PROXY_SUPPORT:
                logger.warning("[Passkey] PySocks 未安装，无法使用代理")
                return None

            proxy_type_map = {
                'socks5': socks.SOCKS5,
                'socks4': socks.SOCKS4,
                'http': socks.HTTP,
            }
            proxy_type = proxy_type_map.get(
                proxy_info.get('type', 'socks5').lower(), socks.SOCKS5
            )
            proxy_dict = {
                'proxy_type': proxy_type,
                'addr': proxy_info['host'],
                'port': proxy_info['port'],
            }
            if proxy_info.get('username') and proxy_info.get('password'):
                proxy_dict['username'] = proxy_info['username']
                proxy_dict['password'] = proxy_info['password']
            logger.debug(f"[Passkey] 使用代理: {proxy_info['host']}:{proxy_info['port']}")
            return proxy_dict
        except Exception as e:
            logger.warning(f"[Passkey] 获取代理失败: {e}")
            return None

    # ------------------------------------------------------------------
    # 结果文件打包
    # ------------------------------------------------------------------
    def create_result_files(
        self,
        results: Dict[str, List[PasskeyResult]],
        files: List[Tuple[str, str]],
        task_id: str,
        file_type: str,
        user_id: int = None,
    ) -> List[Tuple[str, str, str, int]]:
        """
        将三类结果打包为 ZIP 文件。

        返回: [(zip_path, filename, caption, size_bytes), ...]
        """
        logger.info(f"[Passkey] 开始打包结果文件 task_id={task_id}")
        print(f"[Passkey] 📦 打包结果文件...")
        output = []
        base_dir = tempfile.mkdtemp(prefix=f"passkey_result_{task_id}_")

        categories = [
            ('no_passkey', results.get('no_passkey', [])),
            ('deleted',    results.get('deleted', [])),
            ('failed',     results.get('failed', [])),
        ]

        label_map = {
            'no_passkey': '无Passkey_干净账号',
            'deleted':    '已删除Passkey',
            'failed':     '失败',
        }

        for cat_key, cat_results in categories:
            if not cat_results:
                continue

            label = label_map[cat_key]
            count = len(cat_results)
            zip_name = f"{label}_{count}个.zip"
            zip_path = os.path.join(base_dir, zip_name)

            # 构建报告文本
            report_lines = [
                f"Passkey 处理报告",
                f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"账号数量: {count}",
                "",
            ]
            for r in cat_results:
                report_lines.append(f"账号: {r.account_name}")
                if r.phone:
                    report_lines.append(f"  手机号: {r.phone}")
                if cat_key == 'no_passkey':
                    report_lines.append("  无 Passkey")
                elif cat_key == 'deleted':
                    report_lines.append(f"  原有Passkey数量: {len(r.passkeys)}")
                    report_lines.append(f"  已删除: {r.deleted_count} 个")
                    if r.delete_failed:
                        for fail in r.delete_failed:
                            report_lines.append(f"  删除失败: {fail}")
                else:
                    report_lines.append(f"  错误: {r.error or '未知错误'}")
                report_lines.append("")

            report_text = "\n".join(report_lines)

            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                # 写入报告文件
                zf.writestr("passkey_report.txt", report_text.encode('utf-8'))

                # 写入账号原始文件
                for r in cat_results:
                    # 在 files 中查找对应路径
                    orig_path = None
                    for fp, fn in files:
                        if fn == r.account_name or os.path.basename(fp) == r.account_name:
                            orig_path = fp
                            break
                        # 也尝试不带扩展名匹配
                        base_fn = os.path.splitext(fn)[0]
                        base_acc = os.path.splitext(r.account_name)[0]
                        if base_fn == base_acc:
                            orig_path = fp
                            break

                    if orig_path and os.path.exists(orig_path):
                        arc_name = os.path.basename(orig_path)
                        if os.path.isdir(orig_path):
                            # tdata 目录
                            for root, dirs, fnames in os.walk(orig_path):
                                for fname in fnames:
                                    full = os.path.join(root, fname)
                                    rel = os.path.relpath(full, os.path.dirname(orig_path))
                                    zf.write(full, rel)
                        else:
                            zf.write(orig_path, arc_name)
                            # 同名 JSON 文件
                            json_path = orig_path.replace('.session', '.json')
                            if os.path.exists(json_path):
                                zf.write(json_path, os.path.basename(json_path))

            size = os.path.getsize(zip_path)
            caption_map = {
                'no_passkey': f"🔓 无Passkey：{count} 个",
                'deleted':    f"✅ 已删除Passkey：{count} 个",
                'failed':     f"❌ 处理失败：{count} 个",
            }
            logger.info(f"[Passkey] 已生成ZIP: {zip_name} ({size} bytes)")
            print(f"[Passkey]   生成ZIP: {zip_name} ({size} bytes)")
            output.append((zip_path, zip_name, caption_map[cat_key], size))

        logger.info(f"[Passkey] 打包完成，共 {len(output)} 个ZIP文件")
        print(f"[Passkey] 📦 打包完成，共 {len(output)} 个ZIP文件")
        return output


# ---------------------------------------------------------------------------
# Passkey 登录结果
# ---------------------------------------------------------------------------
@dataclass
class PasskeyLoginResult:
    passkey_file: str           # .passkey 文件名
    phone: str = ""
    success: bool = False
    session_path: Optional[str] = None   # 登录成功后导出的 session 文件路径
    error: Optional[str] = None
    elapsed: float = 0.0


# ---------------------------------------------------------------------------
# Passkey 登录管理器（基于 Playwright WebAuthn Hook）
# ---------------------------------------------------------------------------
class PasskeyLoginManager:
    """
    使用 .passkey 文件（含 passkey_id / private_key_pem / user_handle）
    通过 Playwright 模拟 WebAuthn，完成 Telegram Web 登录，导出 localStorage session。

    .passkey 文件 JSON 格式：
    {
        "passkey_id": "...",
        "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\\n...",
        "user_handle": "...",      # base64url 编码
        "phone": "+86...",         # 可选，用于命名输出文件
        "password": "..."          # 可选，2FA 密码
    }
    """

    LOGIN_TIMEOUT = 120          # 单账号整体超时（秒）
    DEFAULT_CONCURRENT = 3       # 默认并发数（每个登录开一个 Chrome 实例）
    CHROME_PATH = '/usr/bin/google-chrome-stable'

    # JS hook 脚本，注入到浏览器页面，劫持 navigator.credentials.get
    _WEBAUTHN_HOOK_SCRIPT = """
        (function() {
            window.__ch = null;
            window.__res = null;

            const b64d = (s) => {
                s += ('==').slice(0, (4 - s.length % 4) % 4);
                return Uint8Array.from(
                    atob(s.replace(/-/g, '+').replace(/_/g, '/')),
                    c => c.charCodeAt(0)
                );
            };

            Object.defineProperty(navigator, 'credentials', {
                value: {
                    get: async function(o) {
                        window.__ch = Array.from(new Uint8Array(o?.publicKey?.challenge));
                        return new Promise(r => window.__res = r);
                    },
                    create: async function(o) { return null; }
                },
                writable: false,
                configurable: false
            });

            window.inject = function(c, uh) {
                if (!window.__res) return false;
                const uhBytes = b64d(uh);
                const resp = {
                    clientDataJSON: b64d(c.cdj).buffer,
                    authenticatorData: b64d(c.ad).buffer,
                    signature: b64d(c.sig).buffer,
                    userHandle: uhBytes.buffer,
                    toJSON: function() {
                        return {
                            clientDataJSON: c.cdj,
                            authenticatorData: c.ad,
                            signature: c.sig,
                            userHandle: uh
                        };
                    }
                };
                const cred = {
                    id: c.id,
                    rawId: b64d(c.id).buffer,
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    response: resp,
                    getClientExtensionResults: function() { return {}; },
                    toJSON: function() {
                        return {
                            id: c.id, rawId: c.id, type: 'public-key',
                            authenticatorAttachment: 'platform',
                            response: resp.toJSON(),
                            clientExtensionResults: {}
                        };
                    }
                };
                window.__res(cred);
                return true;
            };
        })();
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or tempfile.mkdtemp(prefix='passkey_login_out_')

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    # ------------------------------------------------------------------
    # 公共接口：批量登录
    # ------------------------------------------------------------------
    async def batch_login(
        self,
        passkey_files: List[str],
        progress_callback=None,
        concurrent: int = DEFAULT_CONCURRENT,
    ) -> Dict[str, List['PasskeyLoginResult']]:
        """批量登录，返回 {'success': [...], 'failed': [...]}"""
        total = len(passkey_files)
        logger.info(f"[PasskeyLogin] 批量登录开始: 共 {total} 个文件, 并发={concurrent}")
        print(f"[PasskeyLogin] ▶ 批量登录: {total} 个 | 并发={concurrent}")

        semaphore = asyncio.Semaphore(concurrent)
        results: List[PasskeyLoginResult] = []
        done_count = 0

        async def _process_with_sem(pk_path: str):
            nonlocal done_count
            async with semaphore:
                result = await self._login_one(pk_path)
                results.append(result)
                done_count += 1
                icon = '✅' if result.success else '❌'
                msg = f"[PasskeyLogin] {icon} [{done_count}/{total}] {result.passkey_file}"
                if result.phone:
                    msg += f" phone={result.phone}"
                if result.error:
                    msg += f" | 错误: {result.error}"
                print(msg)
                if progress_callback:
                    try:
                        await progress_callback(done_count, total, result)
                    except Exception as e:
                        logger.warning(f"[PasskeyLogin] 进度回调异常: {e}")

        tasks = [asyncio.create_task(_process_with_sem(p)) for p in passkey_files]
        await asyncio.gather(*tasks, return_exceptions=True)

        categorized: Dict[str, List[PasskeyLoginResult]] = {'success': [], 'failed': []}
        for r in results:
            categorized['success' if r.success else 'failed'].append(r)

        ok = len(categorized['success'])
        fail = len(categorized['failed'])
        logger.info(f"[PasskeyLogin] 完成: 成功={ok}, 失败={fail}")
        print(f"[PasskeyLogin] ■ 完成: ✅成功={ok} | ❌失败={fail}")
        return categorized

    # ------------------------------------------------------------------
    # 内部：单账号登录（带整体超时）
    # ------------------------------------------------------------------
    async def _login_one(self, passkey_file_path: str) -> 'PasskeyLoginResult':
        file_name = os.path.basename(passkey_file_path)
        result = PasskeyLoginResult(passkey_file=file_name)
        start = time.time()
        try:
            result = await asyncio.wait_for(
                self._login_one_inner(passkey_file_path),
                timeout=self.LOGIN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            result.error = f'登录超时({self.LOGIN_TIMEOUT}s)'
            result.passkey_file = file_name
            logger.error(f"[PasskeyLogin] {file_name} 整体超时")
        except Exception as e:
            result.error = str(e)
            result.passkey_file = file_name
            logger.error(f"[PasskeyLogin] {file_name} 异常: {e}", exc_info=True)
        result.elapsed = time.time() - start
        return result

    async def _login_one_inner(self, passkey_file_path: str) -> 'PasskeyLoginResult':
        file_name = os.path.basename(passkey_file_path)
        result = PasskeyLoginResult(passkey_file=file_name)

        # 读取 .passkey 文件
        with open(passkey_file_path, 'r', encoding='utf-8') as f:
            pk = json.load(f)

        passkey_id = pk['passkey_id']
        private_key_pem = pk['private_key_pem']
        user_handle = pk.get('user_handle', '')
        phone = pk.get('phone', '')
        password_2fa = pk.get('password', pk.get('two_fa_password', None))

        result.phone = phone

        if not user_handle:
            result.error = '缺少 user_handle 字段'
            return result

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            result.error = 'playwright 未安装，请运行: pip install playwright && playwright install chromium'
            return result

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                executable_path=self.CHROME_PATH,
                args=['--no-sandbox', '--disable-dev-shm-usage'],
            )
            context = await browser.new_context()
            await context.add_init_script(self._WEBAUTHN_HOOK_SCRIPT)
            page = await context.new_page()

            try:
                # 1. 访问 Telegram Web
                logger.info(f"[PasskeyLogin] {file_name}: 访问 Telegram Web...")
                await page.goto('https://web.telegram.org/a/', timeout=60000)
                await asyncio.sleep(6)

                # 2. 点击 PASSKEY 按钮
                btn = page.locator("button:has-text('PASSKEY'), button:has-text('Passkey')")
                if await btn.count() == 0:
                    result.error = '找不到 PASSKEY 按钮，页面可能未显示登录界面'
                    return result
                await btn.first.click()
                logger.info(f"[PasskeyLogin] {file_name}: 已点击 PASSKEY 按钮")
                await asyncio.sleep(3)

                # 3. 等待 challenge
                ch = None
                for _ in range(20):
                    ch = await page.evaluate("window.__ch")
                    if ch:
                        break
                    await asyncio.sleep(0.5)

                if not ch:
                    result.error = '未收到 WebAuthn challenge'
                    return result

                logger.info(f"[PasskeyLogin] {file_name}: 收到 challenge ({len(ch)} bytes)")

                # 4. 签名（与 pass.py 完全一致）
                pkey = serialization.load_pem_private_key(
                    private_key_pem.encode(), None, default_backend()
                )
                cd = json.dumps(
                    {
                        "type": "webauthn.get",
                        "challenge": self._b64url_encode(bytes(ch)),
                        "origin": "https://web.telegram.org",
                        "crossOrigin": False,
                    },
                    separators=(',', ':')
                ).encode()
                ad = hashlib.sha256(b"telegram.org").digest() + b'\x05' + struct.pack('>I', 1)
                sig = pkey.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))

                # 5. 注入凭证
                inject_ok = await page.evaluate(
                    f"window.inject({{id:'{passkey_id}',"
                    f"cdj:'{self._b64url_encode(cd)}',"
                    f"ad:'{self._b64url_encode(ad)}',"
                    f"sig:'{self._b64url_encode(sig)}'}},"
                    f"'{user_handle}')"
                )
                if not inject_ok:
                    result.error = '凭证注入失败（inject 返回 false）'
                    return result

                logger.info(f"[PasskeyLogin] {file_name}: 凭证注入成功，等待响应...")

                # 6. 等待响应
                await asyncio.sleep(5)
                text = await page.inner_text('body')
                content = await page.content()

                # 7. 处理 2FA（与 pass.py 完全一致）
                if 'password' in text.lower() or 'two-step' in text.lower():
                    logger.info(f"[PasskeyLogin] {file_name}: Passkey 验证成功，需要 2FA")
                    if password_2fa:
                        pwd_input = page.locator('input[type="password"]')
                        if await pwd_input.count() > 0:
                            await pwd_input.fill(password_2fa)
                            await page.keyboard.press('Enter')
                            await asyncio.sleep(5)
                            content = await page.content()
                        else:
                            result.error = '2FA 输入框未找到'
                            return result
                    else:
                        result.error = 'Passkey 验证成功但需要 2FA，.passkey 文件中缺少 password 字段'
                        return result

                # 8. 判断登录成功
                if 'ChatList' in content or 'LeftColumn' in content or 'chat-list' in content:
                    logger.info(f"[PasskeyLogin] {file_name}: 登录成功，导出 session...")
                    result.success = True

                    # 9. 导出 localStorage 为 session 文件
                    safe_name = (phone.replace('+', '') if phone else passkey_id[:20]).replace('/', '_')
                    session_out = os.path.join(self.output_dir, f"{safe_name}_passkey.json")
                    try:
                        ls_data = await page.evaluate("""
                            () => {
                                const d = {};
                                for (let i = 0; i < localStorage.length; i++) {
                                    const k = localStorage.key(i);
                                    d[k] = localStorage.getItem(k);
                                }
                                return d;
                            }
                        """)
                        session_info = {
                            'phone': phone,
                            'passkey_id': passkey_id,
                            'login_method': 'passkey',
                            'local_storage': ls_data,
                        }
                        with open(session_out, 'w', encoding='utf-8') as sf:
                            json.dump(session_info, sf, ensure_ascii=False, indent=2)
                        result.session_path = session_out
                        logger.info(f"[PasskeyLogin] {file_name}: session 已导出 => {session_out}")
                    except Exception as export_err:
                        logger.warning(f"[PasskeyLogin] {file_name}: session 导出异常: {export_err}")
                        # 降级：截图
                        screenshot_path = os.path.join(self.output_dir, f"{safe_name}_success.png")
                        await page.screenshot(path=screenshot_path)
                        result.session_path = screenshot_path
                else:
                    result.error = f'登录后页面未识别到聊天界面，页面片段: {text[:150]}'
                    logger.warning(f"[PasskeyLogin] {file_name}: 登录结果未识别")

            finally:
                await browser.close()

        return result

    # ------------------------------------------------------------------
    # 结果文件打包
    # ------------------------------------------------------------------
    def create_result_zip(
        self,
        results: Dict[str, List['PasskeyLoginResult']],
        task_id: str,
    ) -> List[Tuple[str, str, str, int]]:
        """打包登录结果为 ZIP，返回 [(zip_path, filename, caption, size_bytes)]"""
        output = []
        base_dir = tempfile.mkdtemp(prefix=f"passkey_login_result_{task_id}_")

        success_list = results.get('success', [])
        failed_list = results.get('failed', [])

        if success_list:
            count = len(success_list)
            zip_name = f"PasskeyLogin_Session_{count}个.zip"
            zip_path = os.path.join(base_dir, zip_name)
            report_lines = [
                "Passkey 登录报告",
                f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"成功登录: {count}", "",
            ]
            for r in success_list:
                report_lines += [f"文件: {r.passkey_file}"]
                if r.phone:
                    report_lines.append(f"  手机号: {r.phone}")
                report_lines += [f"  用时: {r.elapsed:.1f}s", ""]

            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("passkey_login_report.txt", "\n".join(report_lines).encode('utf-8'))
                for r in success_list:
                    if r.session_path and os.path.exists(r.session_path):
                        zf.write(r.session_path, os.path.basename(r.session_path))

            size = os.path.getsize(zip_path)
            output.append((zip_path, zip_name, f"✅ Passkey 登录成功：{count} 个", size))
            logger.info(f"[PasskeyLogin] 生成成功ZIP: {zip_name} ({size} bytes)")

        if failed_list:
            count = len(failed_list)
            zip_name = f"PasskeyLogin_失败_{count}个.zip"
            zip_path = os.path.join(base_dir, zip_name)
            report_lines = [
                "Passkey 登录失败报告",
                f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"失败数量: {count}", "",
            ]
            for r in failed_list:
                report_lines += [f"文件: {r.passkey_file}"]
                if r.phone:
                    report_lines.append(f"  手机号: {r.phone}")
                report_lines += [f"  错误: {r.error or '未知错误'}", ""]

            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("passkey_login_failed_report.txt", "\n".join(report_lines).encode('utf-8'))

            size = os.path.getsize(zip_path)
            output.append((zip_path, zip_name, f"❌ 登录失败：{count} 个", size))
            logger.info(f"[PasskeyLogin] 生成失败ZIP: {zip_name} ({size} bytes)")

        return output
