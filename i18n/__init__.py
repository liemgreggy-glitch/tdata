import json
import os

DEFAULT_LANGUAGE = 'zh'
SUPPORTED_LANGUAGES = ['zh', 'en', 'ru']

# 用户语言设置文件
USER_LANGUAGE_FILE = 'user_language.json'

# Import translation dictionaries at module level for better performance
from i18n.zh import TEXTS as ZH_TEXTS
from i18n.en import TEXTS as EN_TEXTS
from i18n.ru import TEXTS as RU_TEXTS

# Translation dictionary lookup
TRANSLATIONS = {
    'zh': ZH_TEXTS,
    'en': EN_TEXTS,
    'ru': RU_TEXTS,
}

def load_user_languages():
    """加载用户语言设置"""
    if os.path.exists(USER_LANGUAGE_FILE):
        try:
            with open(USER_LANGUAGE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"⚠️ Failed to load user_language.json: {e}")
            return {}
    return {}

def save_user_languages(data):
    """保存用户语言设置"""
    try:
        with open(USER_LANGUAGE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"⚠️ Failed to save user_language.json: {e}")

def get_user_language(user_id):
    """获取用户语言设置"""
    languages = load_user_languages()
    return languages.get(str(user_id), DEFAULT_LANGUAGE)

def set_user_language(user_id, lang):
    """设置用户语言"""
    # Validate language is supported
    if lang not in SUPPORTED_LANGUAGES:
        print(f"⚠️ Unsupported language '{lang}', defaulting to '{DEFAULT_LANGUAGE}'")
        lang = DEFAULT_LANGUAGE
    
    languages = load_user_languages()
    languages[str(user_id)] = lang
    save_user_languages(languages)

def get_text(user_id, key):
    """获取翻译文本"""
    lang = get_user_language(user_id)
    texts = TRANSLATIONS.get(lang, ZH_TEXTS)
    return texts.get(key, key)

def t(user_id, key):
    """get_text 的简写"""
    return get_text(user_id, key)
