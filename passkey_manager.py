"""
Passkey（通行密钥）批量检测与删除管理器

通过 MTProto API 实现，无需浏览器。
依据 Telegram Desktop 官方源码（passkeys.cpp）确认以下 API：
- account.GetPasskeys  — 获取账号绑定的所有 Passkey 列表
- account.DeletePasskey(id) — 删除指定 Passkey
"""

import asyncio
import os
import shutil
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 尝试导入 Telethon
# ---------------------------------------------------------------------------
try:
    from telethon import TelegramClient
    from telethon.tl.core import TLObject
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
    """构造 account.GetPasskeys 原始请求（CONSTRUCTOR_ID = 0x1e16e712）"""
    if _HAS_GET_PASSKEYS:
        return GetPasskeysRequest()

    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLObject as _TLObject

    class _GetPasskeysRequest(_TLObject):
        CONSTRUCTOR_ID = 0x1e16e712
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
    """构造 account.DeletePasskey 原始请求（CONSTRUCTOR_ID = 0xd54f424a）"""
    if _HAS_DELETE_PASSKEY:
        return DeletePasskeyRequest(id=passkey_id)

    if not TELETHON_AVAILABLE:
        raise RuntimeError("Telethon 未安装")

    from telethon.tl.tlobject import TLObject as _TLObject

    class _DeletePasskeyRequest(_TLObject):
        CONSTRUCTOR_ID = 0xd54f424a
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
        semaphore = asyncio.Semaphore(concurrent)
        results: List[PasskeyResult] = []
        done_count = 0
        total = len(files)

        async def _process_with_sem(file_path, file_name):
            nonlocal done_count
            async with semaphore:
                result = await self._process_one(file_path, file_name, file_type)
                results.append(result)
                done_count += 1
                if progress_callback:
                    try:
                        await progress_callback(done_count, total, result)
                    except Exception:
                        pass

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

        try:
            client, temp_session = await self._connect(file_path, file_name, file_type)
            if client is None:
                result.status = 'failed'
                result.error = '无法创建客户端连接'
                return result

            if not await client.is_user_authorized():
                result.status = 'failed'
                result.error = '账号未授权'
                return result

            # 获取账号手机号（可选，失败不影响主流程）
            try:
                me = await client.get_me()
                if me and hasattr(me, 'phone') and me.phone:
                    result.phone = me.phone
            except Exception:
                pass

            # 获取 Passkey 列表
            passkeys = await self._get_passkeys(client)
            result.passkeys = passkeys
            result.has_passkey = len(passkeys) > 0

            if not passkeys:
                result.status = 'no_passkey'
                return result

            # 逐个删除
            for pk in passkeys:
                success, err = await self._delete_passkey(client, pk.id)
                if success:
                    result.deleted_count += 1
                else:
                    result.delete_failed.append(f"{pk.name or pk.id}: {err}")

            result.status = 'deleted'

        except Exception as e:
            result.status = 'failed'
            result.error = str(e)

        finally:
            if client:
                try:
                    await client.disconnect()
                except Exception:
                    pass
            # 清理 tdata 转换生成的临时 session
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
            response = await client(request)
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
        except Exception as e:
            err_str = str(e).lower()
            # 账号未绑定 Passkey 时服务端可能返回空列表或特定错误
            if 'no passkey' in err_str or 'not found' in err_str or 'empty' in err_str:
                return []
            # 功能不支持（旧版 API 层）
            if 'method' in err_str and ('invalid' in err_str or 'unknown' in err_str):
                return []
            raise

    # ------------------------------------------------------------------
    # 内部：删除单个 Passkey
    # ------------------------------------------------------------------
    async def _delete_passkey(self, client, passkey_id: str) -> Tuple[bool, str]:
        try:
            request = _make_delete_passkey_request(passkey_id)
            await client(request)
            return True, ""
        except Exception as e:
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

        try:
            if file_type == 'tdata':
                if not OPENTELE_AVAILABLE:
                    raise RuntimeError("opentele 未安装，无法处理 TData 格式")
                tdesk = TDesktop(file_path)
                # 使用 mkstemp 创建唯一临时 session 文件，避免路径冲突
                fd, temp_session = tempfile.mkstemp(suffix='.session', prefix='passkey_tmp_')
                os.close(fd)
                os.remove(temp_session)  # ToTelethon 需要路径不存在或会自动创建
                client = await tdesk.ToTelethon(temp_session, flag=UseCurrentSession)
                if not client.is_connected():
                    await client.connect()
            else:
                # session 或 session-json
                session_path = file_path
                if session_path.endswith('.session'):
                    session_path = session_path[:-len('.session')]
                kwargs = {'proxy': proxy_dict} if proxy_dict else {}
                client = TelegramClient(session_path, api_id, api_hash, **kwargs)
                await client.connect()

            return client, temp_session

        except Exception as e:
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
                return None
            if not PROXY_SUPPORT:
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
            return proxy_dict
        except Exception:
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
            zip_name = f"{label}_{count}个_{task_id}.zip"
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
                'no_passkey': f"🔓 无Passkey（干净账号）：{count} 个",
                'deleted':    f"✅ 已删除Passkey：{count} 个",
                'failed':     f"❌ 处理失败：{count} 个",
            }
            output.append((zip_path, zip_name, caption_map[cat_key], size))

        return output
