# -*- coding: utf-8 -*-
import os
import re
import json
import zipfile
from dataclasses import dataclass
from typing import List, Tuple, Optional, Iterable, Dict
import phonenumbers
from phonenumbers import geocoder

PHONE_REGEX = re.compile(r"(?:\+?\d{6,16})")

# Country code to translation key mapping
COUNTRY_CODE_TO_KEY = {
    # Major countries
    420: 'country_czech_republic',
    86: 'country_china',
    1: 'country_united_states',  # Also Canada
    44: 'country_united_kingdom',
    7: 'country_russia',  # Also Kazakhstan
    49: 'country_germany',
    33: 'country_france',
    81: 'country_japan',
    82: 'country_south_korea',
    91: 'country_india',
    55: 'country_brazil',
    61: 'country_australia',
    65: 'country_singapore',
    60: 'country_malaysia',
    62: 'country_indonesia',
    66: 'country_thailand',
    84: 'country_vietnam',
    63: 'country_philippines',
    213: 'country_algeria',
    234: 'country_nigeria',
    20: 'country_egypt',
    27: 'country_south_africa',
    52: 'country_mexico',
    54: 'country_argentina',
    90: 'country_turkey',
    966: 'country_saudi_arabia',
    971: 'country_uae',
    972: 'country_israel',
    48: 'country_poland',
    380: 'country_ukraine',
    31: 'country_netherlands',
    32: 'country_belgium',
    41: 'country_switzerland',
    43: 'country_austria',
    46: 'country_sweden',
    47: 'country_norway',
    45: 'country_denmark',
    358: 'country_finland',
    39: 'country_italy',
    34: 'country_spain',
    351: 'country_portugal',
    30: 'country_greece',
    36: 'country_hungary',
    40: 'country_romania',
    359: 'country_bulgaria',
    381: 'country_serbia',
    385: 'country_croatia',
    421: 'country_slovakia',
    386: 'country_slovenia',
    353: 'country_ireland',
    64: 'country_new_zealand',
    92: 'country_pakistan',
    880: 'country_bangladesh',
    94: 'country_sri_lanka',
    977: 'country_nepal',
    95: 'country_myanmar',
    855: 'country_cambodia',
    856: 'country_laos',
    976: 'country_mongolia',
    998: 'country_uzbekistan',
    375: 'country_belarus',
    995: 'country_georgia',
    374: 'country_armenia',
    994: 'country_azerbaijan',
    98: 'country_iran',
    964: 'country_iraq',
    965: 'country_kuwait',
    974: 'country_qatar',
    973: 'country_bahrain',
    968: 'country_oman',
    962: 'country_jordan',
    961: 'country_lebanon',
    963: 'country_syria',
    967: 'country_yemen',
    212: 'country_morocco',
    216: 'country_tunisia',
    218: 'country_libya',
    249: 'country_sudan',
    251: 'country_ethiopia',
    254: 'country_kenya',
    255: 'country_tanzania',
    256: 'country_uganda',
    233: 'country_ghana',
    237: 'country_cameroon',
    225: 'country_ivory_coast',
    221: 'country_senegal',
    243: 'country_congo',
    244: 'country_angola',
    258: 'country_mozambique',
    263: 'country_zimbabwe',
    260: 'country_zambia',
    267: 'country_botswana',
    264: 'country_namibia',
    56: 'country_chile',
    57: 'country_colombia',
    51: 'country_peru',
    58: 'country_venezuela',
    593: 'country_ecuador',
    591: 'country_bolivia',
    595: 'country_paraguay',
    598: 'country_uruguay',
    53: 'country_cuba',
    1809: 'country_dominican_republic',
    1787: 'country_puerto_rico',
    1876: 'country_jamaica',
    1868: 'country_trinidad_and_tobago',
    502: 'country_guatemala',
    504: 'country_honduras',
    503: 'country_el_salvador',
    505: 'country_nicaragua',
    506: 'country_costa_rica',
    507: 'country_panama',
    886: 'country_taiwan',
    852: 'country_hong_kong',
    853: 'country_macau',
    
    # Additional countries
    93: 'country_afghanistan',
    355: 'country_albania',
    376: 'country_andorra',
    1268: 'country_antigua_and_barbuda',
    1242: 'country_bahamas',
    1246: 'country_barbados',
    501: 'country_belize',
    229: 'country_benin',
    975: 'country_bhutan',
    387: 'country_bosnia_and_herzegovina',
    673: 'country_brunei',
    226: 'country_burkina_faso',
    257: 'country_burundi',
    238: 'country_cape_verde',
    236: 'country_central_african_republic',
    235: 'country_chad',
    269: 'country_comoros',
    357: 'country_cyprus',
    253: 'country_djibouti',
    1767: 'country_dominica',
    240: 'country_equatorial_guinea',
    291: 'country_eritrea',
    372: 'country_estonia',
    268: 'country_eswatini',
    679: 'country_fiji',
    241: 'country_gabon',
    220: 'country_gambia',
    1473: 'country_grenada',
    224: 'country_guinea',
    245: 'country_guinea_bissau',
    592: 'country_guyana',
    509: 'country_haiti',
    354: 'country_iceland',
    686: 'country_kiribati',
    996: 'country_kyrgyzstan',
    371: 'country_latvia',
    266: 'country_lesotho',
    231: 'country_liberia',
    423: 'country_liechtenstein',
    370: 'country_lithuania',
    352: 'country_luxembourg',
    261: 'country_madagascar',
    265: 'country_malawi',
    960: 'country_maldives',
    223: 'country_mali',
    356: 'country_malta',
    692: 'country_marshall_islands',
    222: 'country_mauritania',
    230: 'country_mauritius',
    691: 'country_micronesia',
    373: 'country_moldova',
    377: 'country_monaco',
    382: 'country_montenegro',
    674: 'country_nauru',
    227: 'country_niger',
    850: 'country_north_korea',
    389: 'country_north_macedonia',
    680: 'country_palau',
    970: 'country_palestine',
    675: 'country_papua_new_guinea',
    250: 'country_rwanda',
    1869: 'country_saint_kitts_and_nevis',
    1758: 'country_saint_lucia',
    1784: 'country_saint_vincent_and_the_grenadines',
    685: 'country_samoa',
    378: 'country_san_marino',
    239: 'country_sao_tome_and_principe',
    248: 'country_seychelles',
    232: 'country_sierra_leone',
    677: 'country_solomon_islands',
    252: 'country_somalia',
    211: 'country_south_sudan',
    597: 'country_suriname',
    992: 'country_tajikistan',
    670: 'country_timor_leste',
    228: 'country_togo',
    676: 'country_tonga',
    993: 'country_turkmenistan',
    688: 'country_tuvalu',
    678: 'country_vanuatu',
    379: 'country_vatican_city',
    
    # Territories and dependencies
    590: 'country_guadeloupe',
    596: 'country_martinique',
    262: 'country_reunion',
    594: 'country_french_guiana',
    689: 'country_french_polynesia',
    687: 'country_new_caledonia',
    299: 'country_greenland',
    298: 'country_faroe_islands',
    297: 'country_aruba',
    599: 'country_curacao',
    1721: 'country_sint_maarten',
    1441: 'country_bermuda',
    1345: 'country_cayman_islands',
    1649: 'country_turks_and_caicos',
    1284: 'country_british_virgin_islands',
    1264: 'country_anguilla',
    1664: 'country_montserrat',
    1671: 'country_guam',
    1670: 'country_northern_mariana_islands',
    1684: 'country_american_samoa',
    682: 'country_cook_islands',
    683: 'country_niue',
    350: 'country_gibraltar',
    383: 'country_kosovo',
    
    # Additional codes for more coverage
    # Note: Some territories share codes with their parent countries
    # Code 1 countries (North America)
    # 1: 'country_united_states',  # Already defined above
    # 1: 'country_canada',  # Shares code 1
    1340: 'country_us_virgin_islands',
    500: 'country_falkland_islands',
    290: 'country_saint_helena',  # Also Ascension and Tristan da Cunha
    # 290: 'country_ascension_island',  # Shares 290
    # 290: 'country_tristan_da_cunha',  # Shares 290
    508: 'country_saint_pierre_and_miquelon',
    681: 'country_wallis_and_futuna',
    # 590: 'country_guadeloupe',  # Already defined
    # 590: 'country_saint_barthelemy',  # Shares 590
    # 590: 'country_saint_martin',  # Shares 590
    # 596: 'country_martinique',  # Already defined
    # 262: 'country_reunion',  # Already defined
    # 262: 'country_mayotte',  # Shares 262
    # 594: 'country_french_guiana',  # Already defined
    672: 'country_norfolk_island',  # Also Antarctica
    # 672: 'country_antarctica',  # Shares 672
    61891: 'country_christmas_island',  # Uses Australia +61
    61891: 'country_cocos_islands',  # Uses Australia +61
    690: 'country_tokelau',
    64: 'country_pitcairn_islands',  # Uses satellite phone
    # 7: 'country_kazakhstan',  # Shares code 7 with Russia
    # Code 599 Caribbean Netherlands
    # 599: 'country_bonaire',  # Shares 599
    # 599: 'country_saba',  # Shares 599
    # 599: 'country_sint_eustatius',  # Shares 599
    246: 'country_diego_garcia',  # British Indian Ocean Territory
    500: 'country_south_georgia',  # Shares with Falklands
}

@dataclass
class AccountMeta:
    path: str            # 文件或目录绝对路径
    display_name: str    # 显示/打包用名称（保留原名）
    phone: Optional[str] # 形如 +8613xxxxxx（E.164）
    country_code: Optional[int]
    country_name_zh: Optional[str]

class AccountClassifier:
    """账号分类/打包工具：支持 tdata 和 session+json 两种来源"""

    def __init__(self) -> None:
        pass

    # -------------- 基础提取 --------------
    def _normalize_phone(self, raw: str) -> Optional[str]:
        """从字符串中提取并标准化为 E.164；失败返回 None"""
        if not raw:
            return None
        m = PHONE_REGEX.search(raw)
        if not m:
            return None
        cand = m.group(0)
        if not cand.startswith("+"):
            cand = "+" + cand
        try:
            num = phonenumbers.parse(cand, None)
            if phonenumbers.is_possible_number(num):
                return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            return None
        return None

    def _infer_phone_from_json(self, json_path: str) -> Optional[str]:
        """尝试在 JSON 文件中寻找手机号字段"""
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            # 常见字段
            for k in ("phone", "phone_number", "tel", "user_phone"):
                if isinstance(data.get(k), str):
                    p = self._normalize_phone(data[k])
                    if p:
                        return p
            # 常见嵌套
            user = data.get("user")
            if isinstance(user, dict):
                for k in ("phone", "phone_number"):
                    if isinstance(user.get(k), str):
                        p = self._normalize_phone(user[k])
                        if p:
                            return p
        except Exception:
            pass
        return None

    def _detect_country(self, phone: Optional[str]) -> Tuple[Optional[int], Optional[str]]:
        """通过 phonenumbers 解析国家信息；失败返回 (None, None)"""
        if not phone:
            return None, None
        try:
            num = phonenumbers.parse(phone, None)
            code = num.country_code
            name = geocoder.country_name_for_number(num, "zh") or geocoder.country_name_for_number(num, "en")
            return code, (name or "未知")
        except Exception:
            return None, None

    # -------------- 元数据构造 --------------
    def build_meta_from_pairs(self, files: List[Tuple[str, str]], file_type: str) -> List[AccountMeta]:
        """
        将 FileProcessor.scan_zip_file 返回的列表 [(path, name)] 转为 AccountMeta 列表
        file_type: 'tdata' 或 'session'
        """
        metas: List[AccountMeta] = []
        for path, display_name in files:
            phone: Optional[str] = None

            # 1) 从名称里推断
            phone = self._normalize_phone(display_name)

            # 2) 目录/文件内查找 json 兜底
            if not phone:
                if os.path.isdir(path):
                    # tdata 目录下同级或下层可能会有描述 json
                    for root, _, fns in os.walk(path):
                        for fn in fns:
                            if fn.lower().endswith(".json"):
                                p = self._infer_phone_from_json(os.path.join(root, fn))
                                if p:
                                    phone = p
                                    break
                        if phone:
                            break
                else:
                    # session 同目录下可能有 .json
                    if path.lower().endswith(".json"):
                        phone = self._infer_phone_from_json(path)
                    else:
                        alt = path.replace(".session", ".json")
                        if os.path.exists(alt):
                            phone = self._infer_phone_from_json(alt)

            code, name = self._detect_country(phone)
            metas.append(AccountMeta(
                path=path,
                display_name=display_name,
                phone=phone,
                country_code=code,
                country_name_zh=name if name else None
            ))
        return metas

    # -------------- 命名与分组 --------------
    def country_key(self, m: AccountMeta, t_func=None) -> Tuple[str, str]:
        """Get country name and code for account, with optional translation support"""
        if m.country_code:
            # Try to get translation key from country code mapping
            if t_func and m.country_code in COUNTRY_CODE_TO_KEY:
                country_key = COUNTRY_CODE_TO_KEY[m.country_code]
                country_name = t_func(country_key)
            else:
                # Fallback to Chinese name from phonenumbers library
                country_name = m.country_name_zh or (t_func('split_unknown') if t_func else "未知")
            return country_name, str(m.country_code)
        return (t_func('split_unknown') if t_func else "未知"), "000"

    def detect_bundle_country_label(self, metas: List[AccountMeta], t_func=None) -> Tuple[str, str]:
        """Detect unified country label for quantity-based splitting. 
        Returns ('Mixed','000') for mixed countries or ('Unknown','000') for all unidentified accounts.
        Labels are translatable when t_func is provided."""
        if not metas:
            return (t_func('split_unknown') if t_func else "未知"), "000"
        codes: Dict[str, str] = {}  # code -> name
        code_list: List[str] = []
        for m in metas:
            name, code = self.country_key(m, t_func)
            codes[code] = name
            code_list.append(code)
        uniq = set(code_list)
        if len(uniq) == 1:
            code = next(iter(uniq))
            return codes.get(code, (t_func('split_unknown') if t_func else "未知")), code
        if uniq == {"000"}:
            return (t_func('split_unknown') if t_func else "未知"), "000"
        return (t_func('split_mixed') if t_func else "混合"), "000"

    # -------------- 打包 --------------
    def _zip_bundle(self, items: List[AccountMeta], out_dir: str, display_zip: str) -> str:
        """
        将传入的账号条目打成一个 zip 包
        修复点：
        - 保留 tdata 完整目录结构：手机号/tdata/Dxxxxxx/...
        - Session 格式：直接放在 ZIP 根目录（扁平结构）
        - 对于 .session 同时打入同名 .json（同目录优先，找不到回退 sessions/）
        """
        os.makedirs(out_dir, exist_ok=True)
        dst = os.path.join(out_dir, display_zip)

        written: set = set()  # 去重，避免重复写同一路径
        with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for it in items:
                # 账号根目录：优先用 E.164 手机号；没有则用显示名
                account_root = (it.phone or it.display_name or "").strip() or "account"

                if os.path.isdir(it.path):
                    # TData 格式：保留文件夹结构
                    base = it.path
                    base_is_tdata = os.path.basename(base).lower() == "tdata"

                    for rp, _, fns in os.walk(base):
                        for fn in fns:
                            full = os.path.join(rp, fn)
                            rel_from_base = os.path.relpath(full, base)
                            # 若源就是 tdata 目录，把 tdata 作为一级目录保留
                            if base_is_tdata:
                                arc_rel = os.path.join("tdata", rel_from_base)
                            else:
                                arc_rel = rel_from_base
                            arcname = os.path.join(account_root, arc_rel)
                            if arcname not in written:
                                zf.write(full, arcname=arcname)
                                written.add(arcname)
                else:
                    # Session 格式：直接放在 ZIP 根目录（扁平结构），不创建手机号文件夹
                    # 这样避免了多余的嵌套层级，session文件和json文件都在ZIP根目录
                    base_name = os.path.basename(it.path)
                    name_lower = base_name.lower()

                    # Session 文件直接放在根目录
                    arc_file = base_name
                    if arc_file not in written:
                        zf.write(it.path, arcname=arc_file)
                        written.add(arc_file)

                    # 若是 .session，尝试附带同名 .json
                    if name_lower.endswith(".session"):
                        json_name = os.path.splitext(base_name)[0] + ".json"
                        json_candidates = [
                            os.path.join(os.path.dirname(it.path), json_name),
                            os.path.join(os.getcwd(), "sessions", json_name),
                        ]
                        for cand in json_candidates:
                            if os.path.exists(cand):
                                arc_json = json_name
                                if arc_json not in written:
                                    zf.write(cand, arcname=arc_json)
                                    written.add(arc_json)
                                break
                    # 若是 .json，也尽量附带同名 .session（健壮性，防止只传了一个）
                    elif name_lower.endswith(".json"):
                        ses_name = os.path.splitext(base_name)[0] + ".session"
                        ses_candidates = [
                            os.path.join(os.path.dirname(it.path), ses_name),
                            os.path.join(os.getcwd(), "sessions", ses_name),
                        ]
                        for cand in ses_candidates:
                            if os.path.exists(cand):
                                arc_ses = ses_name
                                if arc_ses not in written:
                                    zf.write(cand, arcname=arc_ses)
                                    written.add(arc_ses)
                                break
        return dst

    # -------------- 对外：按国家拆分 --------------
    def split_by_country(self, metas: List[AccountMeta], out_dir: str, t_func=None) -> List[Tuple[str, str, int]]:
        from collections import defaultdict
        groups: Dict[Tuple[str, str], List[AccountMeta]] = defaultdict(list)
        for m in metas:
            groups[self.country_key(m, t_func)].append(m)

        results: List[Tuple[str, str, int]] = []
        for (name, code), items in groups.items():
            qty = len(items)
            zip_name = f"{name}+{code}_{qty}.zip"
            path = self._zip_bundle(items, out_dir, zip_name)
            results.append((path, zip_name, qty))
        return results

    # -------------- 对外：按数量拆分 --------------
    def split_by_quantities(
        self,
        metas: List[AccountMeta],
        sizes: Iterable[int],
        out_dir: str,
        country_label: Optional[Tuple[str, str]] = None,
        t_func=None
    ) -> List[Tuple[str, str, int]]:
        """Split accounts by specified sizes in order. 
        Naming pattern: {country}+{code}_{quantity}.zip with serial suffix to avoid duplicates.
        Country names are translatable when t_func is provided."""
        if country_label is None:
            country_label = self.detect_bundle_country_label(metas, t_func)
        name, code = country_label

        os.makedirs(out_dir, exist_ok=True)

        res: List[Tuple[str, str, int]] = []
        idx = 0
        metas_sorted = list(metas)
        total = len(metas_sorted)

        # 判断是否可能发生重名（同一国家/区号，数量重复）
        sizes_list = list(sizes)
        need_serial = sizes_list.count(1) > 1 or len(set(sizes_list)) != len(sizes_list)

        batch_no = 0
        for s in sizes_list:
            if idx >= total:
                break
            batch = metas_sorted[idx: idx + s]
            real = len(batch)
            if real == 0:
                break

            batch_no += 1
            base_name = f"{name}+{code}_{real}.zip"
            zip_name = base_name

            # 若需要保证唯一性，则追加批次序号
            if need_serial:
                zip_name = f"{name}+{code}_{real}--{batch_no}.zip"

            # 若仍存在重名（目录已有同名），继续自增后缀
            dedup_no = 1
            final_zip_name = zip_name
            while os.path.exists(os.path.join(out_dir, final_zip_name)):
                dedup_no += 1
                final_zip_name = f"{os.path.splitext(zip_name)[0]}--{dedup_no}.zip"

            path = self._zip_bundle(batch, out_dir, final_zip_name)
            res.append((path, final_zip_name, real))
            idx += s

        return res