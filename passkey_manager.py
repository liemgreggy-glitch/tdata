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

logger = logging.getLogger(__name__)

# 超时配置（秒）
CONNECT_TIMEOUT = 30       # 建立连接超时
AUTH_TIMEOUT = 20          # is_user_authorized 超时
GET_ME_TIMEOUT = 20        # get_me 超时
GET_PASSKEYS_TIMEOUT = 30  # GetPasskeys API 超时
DELETE_PASSKEY_TIMEOUT = 20  # DeletePasskey API 超时
INIT_PASSKEY_TIMEOUT = 30   # initPasskeyRegistration 超时
REGISTER_PASSKEY_TIMEOUT = 30  # registerPasskey 超时
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
            return struct.pack('<I', self.CONSTRUCTOR_ID) + \
                   struct.pack('<I', len(id_bytes)) + id_bytes

    return _DeletePasskeyRequest(id=passkey_id)


# ---------------------------------------------------------------------------
# TL bytes helper
# ---------------------------------------------------------------------------
def _tl_bytes(data: bytes) -> bytes:
    """Serialize bytes using TL (Telegram) wire format."""
    from telethon.tl.tlobject import TLObject
    return TLObject.serialize_bytes(data)


def _tl_str(s: str) -> bytes:
    """Serialize string using TL wire format."""
    from telethon.tl.tlobject import TLObject
    return TLObject.serialize_bytes(s.encode('utf-8'))


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode a string, tolerating missing padding."""
    padded = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _make_init_passkey_registration_request():
    """构造 account.initPasskeyRegistration 请求（CONSTRUCTOR_ID = 0x429547e8）"""
    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLRequest as _TLRequest
    from telethon.tl.alltlobjects import tlobjects

    class _InitPasskeyRegistrationRequest(_TLRequest):
        CONSTRUCTOR_ID = 0x429547e8
        SUBCLASS_OF_ID = 0x429547e8

        def __init__(self):
            pass

        def to_dict(self):
            return {'_': 'account.initPasskeyRegistration'}

        def _bytes(self):
            return struct.pack('<I', self.CONSTRUCTOR_ID)

        @staticmethod
        def read_result(reader):
            # account.PasskeyRegistrationOptions has unknown constructor id;
            # read it manually: skip constructor id, then read json:DataJSON field
            reader.read_int(signed=False)  # skip response constructor id
            json_obj = reader.tgread_object()  # reads DataJSON#7d748d04
            return json_obj

    tlobjects[_InitPasskeyRegistrationRequest.CONSTRUCTOR_ID] = _InitPasskeyRegistrationRequest
    return _InitPasskeyRegistrationRequest()


def _make_input_passkey_credential_response(client_data_json: bytes,
                                            attestation_object: bytes):
    """构造 InputPasskeyCredentialResponse（CONSTRUCTOR_ID = 0xe3b72634）"""
    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLObject as _TLObject
    from telethon.tl.alltlobjects import tlobjects

    class _InputPasskeyCredentialResponse(_TLObject):
        CONSTRUCTOR_ID = 0xe3b72634
        SUBCLASS_OF_ID = 0xe3b72634

        def __init__(self, client_data_json: bytes, attestation_object: bytes):
            self.client_data_json = client_data_json
            self.attestation_object = attestation_object

        def to_dict(self):
            return {
                '_': 'inputPasskeyCredentialResponse',
                'client_data_json': self.client_data_json,
                'attestation_object': self.attestation_object,
            }

        def _bytes(self):
            return (
                struct.pack('<I', self.CONSTRUCTOR_ID)
                + _tl_bytes(self.client_data_json)
                + _tl_bytes(self.attestation_object)
            )

    tlobjects[_InputPasskeyCredentialResponse.CONSTRUCTOR_ID] = \
        _InputPasskeyCredentialResponse
    return _InputPasskeyCredentialResponse(
        client_data_json=client_data_json,
        attestation_object=attestation_object,
    )


def _make_input_passkey_credential(credential_id: str, credential_type: str,
                                   raw_id: bytes, response):
    """构造 InputPasskeyCredential（CONSTRUCTOR_ID = 0x1250a88a）"""
    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLObject as _TLObject
    from telethon.tl.alltlobjects import tlobjects

    class _InputPasskeyCredential(_TLObject):
        CONSTRUCTOR_ID = 0x1250a88a
        SUBCLASS_OF_ID = 0x1250a88a

        def __init__(self, id: str, type: str, raw_id: bytes, response):
            self.id = id
            self.type = type
            self.raw_id = raw_id
            self.response = response

        def to_dict(self):
            return {
                '_': 'inputPasskeyCredential',
                'id': self.id,
                'type': self.type,
                'raw_id': self.raw_id,
                'response': self.response.to_dict(),
            }

        def _bytes(self):
            return (
                struct.pack('<I', self.CONSTRUCTOR_ID)
                + _tl_str(self.id)
                + _tl_str(self.type)
                + _tl_bytes(self.raw_id)
                + bytes(self.response)
            )

    tlobjects[_InputPasskeyCredential.CONSTRUCTOR_ID] = _InputPasskeyCredential
    return _InputPasskeyCredential(id=credential_id, type=credential_type,
                                   raw_id=raw_id, response=response)


def _make_register_passkey_request(credential):
    """构造 account.registerPasskey 请求（CONSTRUCTOR_ID = 0x55b41fd6）"""
    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLRequest as _TLRequest
    from telethon.tl.alltlobjects import tlobjects

    class _RegisterPasskeyRequest(_TLRequest):
        CONSTRUCTOR_ID = 0x55b41fd6
        SUBCLASS_OF_ID = 0x55b41fd6

        def __init__(self, credential):
            self.credential = credential

        def to_dict(self):
            return {
                '_': 'account.registerPasskey',
                'credential': self.credential.to_dict(),
            }

        def _bytes(self):
            return (
                struct.pack('<I', self.CONSTRUCTOR_ID)
                + bytes(self.credential)
            )

        @staticmethod
        def read_result(reader):
            # Response is Passkey type; try generic read, fall back gracefully
            try:
                return reader.tgread_object()
            except Exception:
                return None

    tlobjects[_RegisterPasskeyRequest.CONSTRUCTOR_ID] = _RegisterPasskeyRequest
    return _RegisterPasskeyRequest(credential=credential)


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


@dataclass
class PasskeyCreateResult:
    account_name: str
    phone: str = ""
    file_type: str = "session"
    status: str = "pending"   # pending / created / failed
    passkey_id: str = ""
    passkey_name: str = ""
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
    # 内部：初始化 Passkey 注册（获取 WebAuthn 注册选项）
    # ------------------------------------------------------------------
    async def _init_passkey_registration(self, client) -> dict:
        """调用 account.initPasskeyRegistration，返回 WebAuthn 创建选项 dict"""
        request = _make_init_passkey_registration_request()
        logger.debug("[Passkey] initPasskeyRegistration 请求对象: %s",
                     type(request).__name__)
        response = await asyncio.wait_for(
            client(request), timeout=INIT_PASSKEY_TIMEOUT
        )
        logger.debug("[Passkey] initPasskeyRegistration 响应类型: %s",
                     type(response).__name__)
        # response should be DataJSON with .data containing JSON string
        if hasattr(response, 'data'):
            raw = response.data
        elif isinstance(response, str):
            raw = response
        else:
            raw = str(response)
        options = json.loads(raw)
        logger.info("[Passkey] initPasskeyRegistration 成功，获得注册选项")
        return options

    # ------------------------------------------------------------------
    # 内部：软件模拟 FIDO2 生成注册凭证
    # ------------------------------------------------------------------
    def _build_fido2_credential(self, options: dict,
                                passkey_name: str = "Telegram") -> dict:
        """
        使用 cryptography 库软件模拟 FIDO2 设备，生成符合 WebAuthn 规范的注册凭证。

        返回 dict 包含:
            id            - base64url 编码的凭证 ID
            rawId         - 原始凭证 ID bytes
            clientDataJSON  - bytes
            attestationObject - bytes
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            from fido2 import cbor
        except ImportError as e:
            raise RuntimeError(f"缺少依赖库: {e}")

        # 解析 options 中的必要字段
        challenge_raw = options.get('challenge', '')
        # challenge 可能是 base64url 编码的字节串
        if isinstance(challenge_raw, str):
            challenge_bytes = _b64url_decode(challenge_raw)
        else:
            challenge_bytes = bytes(challenge_raw)

        rp_info = options.get('rp', {})
        rp_id = rp_info.get('id', 'telegram.org')
        origin = f"https://{rp_id}"

        # 1. 生成 EC P-256 密钥对
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        pub_numbers = public_key.public_numbers()
        x_bytes = pub_numbers.x.to_bytes(32, 'big')
        y_bytes = pub_numbers.y.to_bytes(32, 'big')

        # 2. 生成随机凭证 ID（32 字节）
        credential_id = os.urandom(32)
        cred_id_b64 = _b64url_encode(credential_id)

        # 3. 构造 COSE EC2 公钥（ES256 = -7）
        cose_key = {1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes}
        cose_key_bytes = cbor.encode(cose_key)

        # 4. 构造 authData
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        flags = 0x45  # UP(bit0) | UV(bit2) | AT(bit6)
        sign_count = struct.pack('>I', 0)
        aaguid = bytes(16)
        cred_id_len = struct.pack('>H', len(credential_id))
        auth_data = (rp_id_hash + bytes([flags]) + sign_count
                     + aaguid + cred_id_len + credential_id + cose_key_bytes)

        # 5. 构造 clientDataJSON
        client_data = {
            "type": "webauthn.create",
            "challenge": _b64url_encode(challenge_bytes),
            "origin": origin,
            "crossOrigin": False,
        }
        client_data_json = json.dumps(client_data, separators=(',', ':')).encode()

        # 6. 构造 attestationObject（格式 "none"）
        att_obj = {"fmt": "none", "authData": auth_data, "attStmt": {}}
        attestation_object = cbor.encode(att_obj)

        logger.info("[Passkey] FIDO2 凭证生成成功 id=%s", cred_id_b64[:16])
        return {
            'id': cred_id_b64,
            'rawId': credential_id,
            'clientDataJSON': client_data_json,
            'attestationObject': attestation_object,
        }

    # ------------------------------------------------------------------
    # 内部：提交 Passkey 注册凭证
    # ------------------------------------------------------------------
    async def _register_passkey(self, client,
                                credential: dict) -> Tuple[bool, str, str]:
        """
        调用 account.registerPasskey，返回 (success, passkey_id, error)
        """
        try:
            resp_obj = _make_input_passkey_credential_response(
                client_data_json=credential['clientDataJSON'],
                attestation_object=credential['attestationObject'],
            )
            cred_obj = _make_input_passkey_credential(
                credential_id=credential['id'],
                credential_type='public-key',
                raw_id=credential['rawId'],
                response=resp_obj,
            )
            request = _make_register_passkey_request(cred_obj)
            response = await asyncio.wait_for(
                client(request), timeout=REGISTER_PASSKEY_TIMEOUT
            )
            # Extract passkey ID from response
            if response is not None:
                pk_id = str(getattr(response, 'id', '') or credential['id'])
            else:
                pk_id = credential['id']
            logger.info("[Passkey] registerPasskey 成功 id=%s", pk_id[:16])
            return True, pk_id, ""
        except asyncio.TimeoutError:
            msg = f"registerPasskey 超时({REGISTER_PASSKEY_TIMEOUT}s)"
            logger.error("[Passkey] %s", msg)
            return False, "", msg
        except Exception as e:
            logger.warning("[Passkey] registerPasskey 失败: %s", e)
            return False, "", str(e)

    # ------------------------------------------------------------------
    # 内部：为单账号创建 Passkey（init → build → register）
    # ------------------------------------------------------------------
    async def _create_passkey_for_account(
        self, client, passkey_name: str = "Telegram"
    ) -> Tuple[bool, str, str]:
        """
        组合三步完成 Passkey 创建，返回 (success, passkey_id, error)
        """
        # Step 1: 获取注册选项
        try:
            options = await self._init_passkey_registration(client)
        except asyncio.TimeoutError:
            msg = f"initPasskeyRegistration 超时({INIT_PASSKEY_TIMEOUT}s)"
            logger.error("[Passkey] %s", msg)
            return False, "", msg
        except Exception as e:
            logger.warning("[Passkey] initPasskeyRegistration 失败: %s", e)
            return False, "", str(e)

        # Step 2: 软件模拟生成 FIDO2 凭证
        try:
            credential = self._build_fido2_credential(options, passkey_name)
        except Exception as e:
            logger.error("[Passkey] 生成FIDO2凭证失败: %s", e, exc_info=True)
            return False, "", f"生成凭证失败: {e}"

        # Step 3: 提交注册
        return await self._register_passkey(client, credential)

    # ------------------------------------------------------------------
    # 公共接口：批量创建 Passkey
    # ------------------------------------------------------------------
    async def batch_create_passkey(
        self,
        files: List[Tuple[str, str]],
        file_type: str,
        passkey_name: str = "Telegram",
        progress_callback=None,
        concurrent: int = DEFAULT_CONCURRENT,
    ) -> Dict[str, List[PasskeyCreateResult]]:
        """批量为多个账号创建 Passkey，返回分类结果字典"""
        total = len(files)
        logger.info("[Passkey] 批量创建开始: 共 %d 个账号, 类型=%s, 并发=%d",
                    total, file_type, concurrent)
        print(f"[Passkey] ▶ 批量创建开始: 共 {total} 个账号 | 类型={file_type} | 并发={concurrent}")

        semaphore = asyncio.Semaphore(concurrent)
        results: List[PasskeyCreateResult] = []
        done_count = 0

        async def _create_with_sem(file_path, file_name):
            nonlocal done_count
            async with semaphore:
                result = await self._create_one(file_path, file_name,
                                                file_type, passkey_name)
                results.append(result)
                done_count += 1
                status_icon = {'created': '✅', 'failed': '❌'}.get(
                    result.status, '?')
                print(
                    f"[Passkey] {status_icon} [{done_count}/{total}] "
                    f"{file_name} => {result.status}"
                    + (f" | 错误: {result.error}" if result.error else "")
                    + (f" | PasskeyID: {result.passkey_id[:16]}"
                       if result.passkey_id else "")
                )
                if progress_callback:
                    try:
                        await progress_callback(done_count, total, result)
                    except Exception as cb_err:
                        logger.warning("[Passkey] 进度回调异常: %s", cb_err)

        tasks = [
            asyncio.create_task(_create_with_sem(fp, fn))
            for fp, fn in files
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        categorized: Dict[str, List[PasskeyCreateResult]] = {
            'created': [],
            'failed': [],
        }
        for r in results:
            if r.status == 'created':
                categorized['created'].append(r)
            else:
                categorized['failed'].append(r)

        created = len(categorized['created'])
        failed = len(categorized['failed'])
        logger.info("[Passkey] 批量创建完成: 已创建=%d, 失败=%d", created, failed)
        print(f"[Passkey] ■ 批量创建完成: ✅已创建={created} | ❌失败={failed}")
        return categorized

    async def _create_one(
        self, file_path: str, file_name: str, file_type: str,
        passkey_name: str
    ) -> PasskeyCreateResult:
        """处理单个账号的 Passkey 创建，带整体超时保护"""
        start = time.time()
        logger.info("[Passkey] 开始创建Passkey: %s (类型=%s)", file_name, file_type)
        print(f"[Passkey] → 创建Passkey: {file_name}")

        try:
            result = await asyncio.wait_for(
                self._create_one_inner(file_path, file_name, file_type,
                                       passkey_name),
                timeout=ACCOUNT_TOTAL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            elapsed = round(time.time() - start, 1)
            logger.error("[Passkey] 账号 %s 整体超时 (%ds), 已用时 %ss",
                         file_name, ACCOUNT_TOTAL_TIMEOUT, elapsed)
            print(f"[Passkey] ⏱ 账号 {file_name} 整体超时 ({ACCOUNT_TOTAL_TIMEOUT}s)")
            result = PasskeyCreateResult(
                account_name=file_name, file_type=file_type,
                passkey_name=passkey_name, status='failed',
                error=f'处理超时({ACCOUNT_TOTAL_TIMEOUT}s)',
            )
        except Exception as e:
            elapsed = round(time.time() - start, 1)
            logger.error("[Passkey] 账号 %s 处理异常 (%ss): %s",
                         file_name, elapsed, e, exc_info=True)
            print(f"[Passkey] ✗ 账号 {file_name} 处理异常: {e}")
            result = PasskeyCreateResult(
                account_name=file_name, file_type=file_type,
                passkey_name=passkey_name, status='failed', error=str(e),
            )

        result.elapsed = time.time() - start
        return result

    async def _create_one_inner(
        self, file_path: str, file_name: str, file_type: str,
        passkey_name: str
    ) -> PasskeyCreateResult:
        """实际创建逻辑（由 _create_one 包裹整体超时）"""
        result = PasskeyCreateResult(account_name=file_name, file_type=file_type,
                                     passkey_name=passkey_name)
        start = time.time()
        client = None
        temp_session = None

        try:
            # 1. 连接
            logger.info("[Passkey] %s: 建立连接...", file_name)
            print(f"[Passkey]   {file_name}: 建立连接...")
            client, temp_session = await self._connect(file_path, file_name,
                                                       file_type)
            if client is None:
                result.status = 'failed'
                result.error = '无法创建客户端连接'
                return result
            print(f"[Passkey]   {file_name}: ✓ 连接成功")

            # 2. 检查授权
            print(f"[Passkey]   {file_name}: 检查授权...")
            try:
                is_authorized = await asyncio.wait_for(
                    client.is_user_authorized(), timeout=AUTH_TIMEOUT
                )
            except asyncio.TimeoutError:
                result.status = 'failed'
                result.error = f'授权检查超时({AUTH_TIMEOUT}s)'
                return result

            if not is_authorized:
                result.status = 'failed'
                result.error = '账号未授权'
                return result
            print(f"[Passkey]   {file_name}: ✓ 账号已授权")

            # 3. 获取手机号（可选）
            try:
                me = await asyncio.wait_for(client.get_me(), timeout=GET_ME_TIMEOUT)
                if me and hasattr(me, 'phone') and me.phone:
                    result.phone = me.phone
                    print(f"[Passkey]   {file_name}: 手机号={result.phone}")
            except Exception:
                pass

            # 4. 创建 Passkey
            logger.info("[Passkey] %s: 开始创建Passkey...", file_name)
            print(f"[Passkey]   {file_name}: 创建Passkey...")
            success, pk_id, error = await self._create_passkey_for_account(
                client, passkey_name
            )
            if success:
                result.status = 'created'
                result.passkey_id = pk_id
                logger.info("[Passkey] %s: Passkey 创建成功 id=%s",
                            file_name, pk_id[:16] if pk_id else '')
                print(f"[Passkey]   {file_name}: ✓ Passkey 创建成功")
            else:
                result.status = 'failed'
                result.error = error
                logger.warning("[Passkey] %s: Passkey 创建失败: %s",
                               file_name, error)
                print(f"[Passkey]   {file_name}: ✗ Passkey 创建失败: {error}")

        except Exception as e:
            result.status = 'failed'
            result.error = str(e)
            logger.error("[Passkey] %s: 处理异常: %s", file_name, e, exc_info=True)
            print(f"[Passkey]   {file_name}: ✗ 异常: {e}")

        finally:
            if client:
                try:
                    await asyncio.wait_for(client.disconnect(),
                                           timeout=DISCONNECT_TIMEOUT)
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
    # 结果文件打包（创建 Passkey 专用）
    # ------------------------------------------------------------------
    def create_result_files_for_create(
        self,
        results: Dict[str, List[PasskeyCreateResult]],
        files: List[Tuple[str, str]],
        task_id: str,
        file_type: str,
        user_id: int = None,
    ) -> List[Tuple[str, str, str, int]]:
        """
        将创建 Passkey 的结果打包为 ZIP 文件。

        返回: [(zip_path, filename, caption, size_bytes), ...]
        """
        logger.info("[Passkey] 开始打包创建结果文件 task_id=%s", task_id)
        print("[Passkey] 📦 打包创建结果文件...")
        output = []
        base_dir = tempfile.mkdtemp(prefix=f"passkey_create_{task_id}_")

        categories = [
            ('created', results.get('created', [])),
            ('failed',  results.get('failed', [])),
        ]

        label_map = {
            'created': '已创建Passkey',
            'failed':  '失败',
        }
        caption_map = {
            'created': lambda n: f"✅ 已创建Passkey：{n} 个",
            'failed':  lambda n: f"❌ 处理失败：{n} 个",
        }

        for cat_key, cat_results in categories:
            if not cat_results:
                continue

            label = label_map[cat_key]
            count = len(cat_results)
            zip_name = f"{label}_{count}个_{task_id}.zip"
            zip_path = os.path.join(base_dir, zip_name)

            # 构建报告文本
            report_lines = [
                "Passkey 创建报告",
                f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"账号数量: {count}",
                "",
            ]
            for r in cat_results:
                report_lines.append(f"账号: {r.account_name}")
                if r.phone:
                    report_lines.append(f"  手机号: {r.phone}")
                if cat_key == 'created':
                    report_lines.append(f"  Passkey名称: {r.passkey_name}")
                    report_lines.append(f"  Passkey ID: {r.passkey_id}")
                else:
                    report_lines.append(f"  错误: {r.error or '未知错误'}")
                report_lines.append("")

            report_text = "\n".join(report_lines)

            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("passkey_create_report.txt",
                            report_text.encode('utf-8'))
                # 写入账号原始文件
                for r in cat_results:
                    orig_path = None
                    for fp, fn in files:
                        base_fn = os.path.splitext(fn)[0]
                        base_acc = os.path.splitext(r.account_name)[0]
                        if (fn == r.account_name
                                or os.path.basename(fp) == r.account_name
                                or base_fn == base_acc):
                            orig_path = fp
                            break

                    if orig_path and os.path.exists(orig_path):
                        arc_name = os.path.basename(orig_path)
                        if os.path.isdir(orig_path):
                            for root, dirs, fnames in os.walk(orig_path):
                                for fname in fnames:
                                    full = os.path.join(root, fname)
                                    rel = os.path.relpath(
                                        full, os.path.dirname(orig_path))
                                    zf.write(full, rel)
                        else:
                            zf.write(orig_path, arc_name)
                            json_path = orig_path.replace('.session', '.json')
                            if os.path.exists(json_path):
                                zf.write(json_path,
                                         os.path.basename(json_path))

            size = os.path.getsize(zip_path)
            logger.info("[Passkey] 已生成ZIP: %s (%d bytes)", zip_name, size)
            print(f"[Passkey]   生成ZIP: {zip_name} ({size} bytes)")
            output.append((zip_path, zip_name, caption_map[cat_key](count),
                           size))

        logger.info("[Passkey] 打包完成，共 %d 个ZIP文件", len(output))
        print(f"[Passkey] 📦 打包完成，共 {len(output)} 个ZIP文件")
        return output

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
