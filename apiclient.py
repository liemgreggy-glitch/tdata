import requests

BASE_URL = "http://45.147.196.113"  # 你的外网地址（80端口，已反代）

def push_code(phone: str, code: str, code_type: str = "sms"):
    """
    把验证码上报到网页后端。调用后，网页会立刻显示这条验证码。
    - phone: 该号码的完整国际格式（和生成链接时一致），例：5592985255528 或 +5592985255528
    - code: 你拿到的验证码字符串
    - code_type: 'sms' / 'call' / 'app'（可选）
    """
    url = f"{BASE_URL}/api/submit_code"
    payload = {"phone": str(phone), "code": str(code), "type": code_type}
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()