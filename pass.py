"""
Passkey 登录
"""

import asyncio
import base64
import hashlib
import json
import struct
import sys

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    padded = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


async def passkey_login(passkey_file: str, password_2fa: str = None):
    with open(passkey_file, 'r') as f:
        pk = json.load(f)
    
    passkey_id = pk['passkey_id']
    private_key_pem = pk['private_key_pem']
    user_handle = pk.get('user_handle', '')
    phone = pk.get('phone', '')
    
    print(f"手机号: {phone}")
    print(f"passkey_id: {passkey_id[:20]}...")
    print(f"user_handle: {user_handle}")
    
    if not user_handle:
        print("❌ 缺少 user_handle")
        return False
    
    from playwright.async_api import async_playwright
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True, 
            executable_path='/usr/bin/google-chrome-stable', 
            args=['--no-sandbox']
        )
        context = await browser.new_context()
        
        await context.add_init_script("""
            (function() {
                console.log('[Hook] Init');
                window.__ch = null;
                window.__res = null;
                
                const b64e = (b) => { let s=''; new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x)); return btoa(s).replace(/\+/g,'-').replace(/\\//g,'_').replace(/=/g,''); };
                const b64d = (s) => { s+=('==').slice(0,(4-s.length%4)%4); return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)); };
                
                Object.defineProperty(navigator, 'credentials', {
                    value: {
                        get: async function(o) {
                            console.log('[Hook] credentials.get called');
                            window.__ch = Array.from(new Uint8Array(o?.publicKey?.challenge));
                            return new Promise(r => window.__res = r);
                        },
                        create: async function(o) {
                            console.log('[Hook] credentials.create called');
                            return null;
                        }
                    },
                    writable: false,
                    configurable: false
                });
                
                window.inject = function(c, uh) {
                    if (!window.__res) { console.log('[Hook] No resolve'); return false; }
                    const uhBytes = b64d(uh);
                    console.log('[Hook] userHandle:', uh, uhBytes.length, 'bytes');
                    
                    const resp = {
                        clientDataJSON: b64d(c.cdj).buffer,
                        authenticatorData: b64d(c.ad).buffer,
                        signature: b64d(c.sig).buffer,
                        userHandle: uhBytes.buffer,
                        toJSON: function() { return { clientDataJSON:c.cdj, authenticatorData:c.ad, signature:c.sig, userHandle:uh }; }
                    };
                    const cred = {
                        id: c.id, 
                        rawId: b64d(c.id).buffer, 
                        type: "public-key", 
                        authenticatorAttachment: "platform",
                        response: resp, 
                        getClientExtensionResults: function() { return {}; },
                        toJSON: function() { return { id:c.id, rawId:c.id, type:"public-key", authenticatorAttachment:"platform", response:resp.toJSON(), clientExtensionResults:{} }; }
                    };
                    window.__res(cred);
                    console.log('[Hook] Injected OK');
                    return true;
                };
                
                console.log('[Hook] Ready');
            })();
        """)
        
        page = await context.new_page()
        page.on('console', lambda m: print(f"  [Browser] {m.text}"))
        
        print("\n[1] 访问 Telegram...")
        await page.goto('https://web.telegram.org/a/', timeout=60000)
        await asyncio.sleep(6)
        
        # 检查 hook
        hook_ok = await page.evaluate("typeof window.inject === 'function'")
        print(f"  Hook: {'✅' if hook_ok else '❌'}")
        
        print("[2] 点击 PASSKEY...")
        btn = page.locator("button:has-text('PASSKEY')")
        if await btn.count() > 0:
            await btn.click()
            print("  ✅ 已点击")
        else:
            print("  ❌ 找不到按钮")
            await page.screenshot(path="no_btn.png")
            await browser.close()
            return False
        
        await asyncio.sleep(3)
        
        print("[3] 等待 challenge...")
        ch = None
        for i in range(20):
            ch = await page.evaluate("window.__ch")
            if ch: break
            await asyncio.sleep(0.5)
        
        if not ch:
            print("❌ 无 challenge")
            await page.screenshot(path="no_ch.png")
            await browser.close()
            return False
        
        print(f"  ✅ challenge: {len(ch)} bytes")
        
        print("[4] 签名...")
        pkey = serialization.load_pem_private_key(private_key_pem.encode(), None, default_backend())
        cd = json.dumps({"type":"webauthn.get","challenge":b64url_encode(bytes(ch)),"origin":"https://web.telegram.org","crossOrigin":False}, separators=(',',':')).encode()
        ad = hashlib.sha256(b"telegram.org").digest() + b'\x05' + struct.pack('>I', 1)
        sig = pkey.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        
        print("[5] 注入...")
        result = await page.evaluate(f"window.inject({{id:'{passkey_id}',cdj:'{b64url_encode(cd)}',ad:'{b64url_encode(ad)}',sig:'{b64url_encode(sig)}'}}, '{user_handle}')")
        print(f"  注入: {'✅' if result else '❌'}")
        
        print("[6] 等待响应...")
        await asyncio.sleep(5)
        
        text = await page.inner_text('body')
        content = await page.content()
        
        if 'password' in text.lower() or 'two-step' in text.lower():
            print("\n✅ Passkey 验证成功，需要 2FA!")
            
            if password_2fa:
                print(f"[7] 输入 2FA: {password_2fa}")
                pwd_input = page.locator('input[type="password"]')
                if await pwd_input.count() > 0:
                    await pwd_input.fill(password_2fa)
                    await page.keyboard.press('Enter')
                    await asyncio.sleep(5)
                    
                    content = await page.content()
                    if 'ChatList' in content or 'LeftColumn' in content:
                        print("\n🎉 登录成功!")
                        await page.screenshot(path="success.png")
                        await browser.close()
                        return True
        
        elif 'ChatList' in content or 'LeftColumn' in content:
            print("\n🎉 登录成功!")
            await browser.close()
            return True
        
        else:
            print(f"  页面: {text[:200]}")
            await page.screenshot(path="result.png")
        
        await browser.close()
        return False


if __name__ == '__main__':
    pf = sys.argv[1]
    pwd = sys.argv[sys.argv.index('--password') + 1] if '--password' in sys.argv else None
    
    print("=" * 50)
    print("🔑 Passkey 登录")
    print("=" * 50)
    
    asyncio.run(passkey_login(pf, pwd))
