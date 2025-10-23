import streamlit as st
import re
import json
from datetime import datetime
from urllib.parse import urlparse
import random

# Gemini APIのインポート（オプション）
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    
# ページ設定
st.set_page_config(
    page_title="統合セキュリティチェッカー",
    page_icon="🔒",
    layout="wide"
)

# カスタムCSS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .risk-high {
        background-color: #fee2e2;
        border-left: 5px solid #dc2626;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .risk-medium {
        background-color: #fef3c7;
        border-left: 5px solid #f59e0b;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .risk-low {
        background-color: #d1fae5;
        border-left: 5px solid #10b981;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .threat-item {
        background-color: #f9fafb;
        padding: 0.5rem;
        margin: 0.3rem 0;
        border-radius: 3px;
        border-left: 3px solid #6366f1;
    }
</style>
""", unsafe_allow_html=True)

# セッション状態の初期化
if 'threat_database' not in st.session_state:
    st.session_state.threat_database = {
        "dangerous_domains": [
            "paypal-secure-login.com",
            "amazon-verify.net",
            "apple-support-id.com",
            "microsoft-security.net",
            "google-verify-account.com"
        ],
        "suspicious_keywords": [
            "verify account", "urgent action", "suspended",
            "confirm identity", "アカウント確認", "緊急",
            "本人確認", "パスワード更新", "セキュリティ警告",
            "一時停止", "24時間以内", "今すぐ"
        ],
        "dangerous_patterns": [
            r"http://[^/]*\.(tk|ml|ga|cf|gq)",
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
            r"https?://[^/]*-[^/]*(login|signin|verify)",
        ]
    }

if 'scam_database' not in st.session_state:
    st.session_state.scam_database = {
        "known_scam_numbers": [
            "03-1234-5678",
            "0120-999-999",
            "050-1111-2222",
            "090-1234-5678"
        ],
        "suspicious_prefixes": [
            "050", "070", "+675", "+234", "+1-876"
        ],
        "warning_patterns": [
            r"^0120", r"^0570", r"^0990", r"^\+.*"
        ],
        "safe_prefixes": ["110", "119", "118"],
        "reported_cases": []
    }

if 'reported_sites' not in st.session_state:
    st.session_state.reported_sites = []

if 'check_history' not in st.session_state:
    st.session_state.check_history = []

if 'phone_check_history' not in st.session_state:
    st.session_state.phone_check_history = []

if 'quiz_index' not in st.session_state:
    st.session_state.quiz_index = 0
    
if 'score' not in st.session_state:
    st.session_state.score = 0
    
if 'answered' not in st.session_state:
    st.session_state.answered = False

if 'last_check' not in st.session_state:
    st.session_state.last_check = None

if 'gemini_key' not in st.session_state:
    st.session_state.gemini_key = ""
    
if 'use_gemini' not in st.session_state:
    st.session_state.use_gemini = False

# クイズサンプルデータ
quiz_samples = [
    {
        "subject": "【重要】あなたのアカウントが一時停止されました",
        "content": "お客様のアカウントに不審なアクセスが検出されました。以下のリンクから確認してください。\n→ http://security-update-login.com",
        "is_phishing": True,
        "explanation": "正規のドメインではなく、不審なURLを使用しています。また、緊急性を煽るタイトルです。"
    },
    {
        "subject": "【Amazon】ご注文ありがとうございます",
        "content": "ご注文いただいた商品は10月12日に発送されます。ご利用ありがとうございます。",
        "is_phishing": False,
        "explanation": "内容は自然で、URLも含まれていません。正規の連絡の可能性が高いです。"
    },
    {
        "subject": "【Apple ID】アカウント情報の確認が必要です",
        "content": "セキュリティのため、以下のURLから24時間以内に情報を更新してください。\n→ http://apple.login-check.xyz",
        "is_phishing": True,
        "explanation": "URLが公式のAppleドメイン（apple.comなど）ではありません。『24時間以内』という緊急性もフィッシングの特徴です。"
    },
    {
        "subject": "【楽天】ポイント還元のお知らせ",
        "content": "キャンペーンにより、300ポイントを付与しました。楽天市場をご利用いただきありがとうございます。",
        "is_phishing": False,
        "explanation": "不自然なURLや情報要求がなく、自然な表現です。"
    },
]
random.shuffle(quiz_samples) # クイズをランダム化

# 関数定義
def setup_gemini(api_key):
    """Gemini API設定"""
    if api_key and GEMINI_AVAILABLE:
        try:
            genai.configure(api_key=api_key)
            return True
        except Exception as e:
            st.error(f"Gemini API設定エラー: {str(e)}")
            return False
    return False

def analyze_url_local(url):
    """ローカルデータベースでURL解析"""
    results = {
        "url": url,
        "risk_level": "安全",
        "risk_score": 10,
        "warnings": [],
        "details": []
    }
    
    try:
        # URLの整形を試みる（schemeがない場合の補完）
        if not re.match(r'https?://', url):
            url_with_scheme = 'http://' + url
        else:
            url_with_scheme = url
            
        parsed = urlparse(url_with_scheme)
        domain = parsed.netloc.lower()
        
        if not domain:
            results["risk_level"] = "エラー"
            results["risk_score"] = 0
            results["warnings"].append("❌ 有効なURLではありません")
            return results
        
        # 危険ドメインチェック
        if any(d in domain for d in st.session_state.threat_database["dangerous_domains"]):
            results["risk_level"] = "危険"
            results["risk_score"] = 95
            results["warnings"].append("⚠️ 既知の詐欺サイトです！直ちにアクセスを中止してください")
        
        # ユーザー通報ドメインチェック
        if any(d == domain for d in st.session_state.reported_sites):
             if results["risk_level"] != "危険":
                 results["risk_level"] = "注意"
                 results["risk_score"] = max(results["risk_score"], 70)
             results["warnings"].append("🚨 ユーザーから通報されたドメインと一致します")
        
        # パターンマッチング
        for pattern in st.session_state.threat_database["dangerous_patterns"]:
            if re.search(pattern, url_with_scheme):
                if results["risk_level"] == "安全":
                    results["risk_level"] = "注意"
                    results["risk_score"] = 60
                results["warnings"].append("⚠️ 疑わしいURLパターンを検出")
                break
        
        # HTTPSチェック
        if parsed.scheme == "http":
            results["warnings"].append("⚠️ HTTPSではありません（通信が暗号化されていません）")
            if results["risk_level"] == "安全":
                results["risk_level"] = "注意"
                results["risk_score"] = 40
        
        # 短縮URLチェック
        short_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
        if any(d in domain for d in short_domains):
            results["warnings"].append("ℹ️ 短縮URLです。実際のリンク先を確認してください")
        
        # 詳細情報
        results["details"].append(f"ドメイン: {domain}")
        results["details"].append(f"プロトコル: {parsed.scheme}")
        results["details"].append(f"パス: {parsed.path or '/'}")
        
    except Exception as e:
        results["risk_level"] = "エラー"
        results["risk_score"] = 0
        results["warnings"].append(f"❌ URL解析エラー: {str(e)}")
    
    return results

def analyze_email_local(content):
    """ローカルデータベースでメール解析"""
    results = {
        "risk_level": "安全",
        "risk_score": 10,
        "warnings": [],
        "details": [],
        "ai_analysis": None
    }
    
    # キーワードチェック
    found_keywords = []
    for keyword in st.session_state.threat_database["suspicious_keywords"]:
        if keyword.lower() in content.lower():
            found_keywords.append(keyword)
    
    if found_keywords:
        results["risk_level"] = "注意"
        results["risk_score"] = 50
        results["warnings"].append(f"⚠️ 疑わしいキーワード検出: {', '.join(found_keywords[:5])}など")
    
    # URLチェック
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
    if urls:
        results["details"].append(f"検出されたURL数: {len(urls)}")
        dangerous_urls = []
        for url in urls[:5]:
            url_result = analyze_url_local(url)
            if url_result["risk_level"] == "危険":
                results["risk_level"] = "危険"
                results["risk_score"] = 90
                dangerous_urls.append(url)
            elif url_result["risk_level"] == "注意" and results["risk_level"] != "危険":
                results["risk_level"] = "注意"
                results["risk_score"] = max(results["risk_score"], 60)
            
        if dangerous_urls:
            results["warnings"].append(f"🚨 危険なURL発見: {len(dangerous_urls)}件")
    
    # 緊急性チェック
    urgent_words = ["今すぐ", "直ちに", "24時間以内", "immediately", "urgent"]
    if any(word in content.lower() for word in urgent_words):
        results["warnings"].append("⚠️ 緊急性を煽る表現が含まれています")
        results["risk_score"] = min(results["risk_score"] + 20, 100)
    
    return results

def analyze_email_with_gemini(content):
    """Gemini AIによるメール内容分析"""
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""
あなたはフィッシング詐欺の専門家です。以下のメール内容を分析し、フィッシングの可能性を評価してください。
特に、送信者、緊急性、不審なリンク（ダミーURL）に注目してください。

メール内容:
---
{content}
---

以下を分析してJSON形式で回答:
{{
    "ai_risk_assessment": "高リスク/中リスク/低リスク",
    "risk_score": 0-100,
    "reasons": ["具体的な疑わしい点"],
    "summary": "総合分析（100文字程度）"
}}
"""
        
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.2,
                max_output_tokens=1000,
            )
        )
        
        json_match = re.search(r'\{[\s\S]*\}', response.text)
        if json_match:
            return json.loads(json_match.group())
        return {"summary": "AI分析結果を解析できませんでした。", "ai_risk_assessment": "不明", "risk_score": 0}
    except Exception as e:
        return {"summary": f"AI分析エラー: {str(e)}", "ai_risk_assessment": "エラー", "risk_score": 0}


def identify_area(number):
    """地域識別"""
    area_codes = {
        "03": "東京", "06": "大阪", "052": "名古屋",
        "011": "札幌", "092": "福岡", "075": "京都", "045": "横浜"
    }
    for code, area in area_codes.items():
        if number.startswith(code):
            return area
    return "不明"

def identify_number_type(normalized):
    """番号タイプ識別"""
    if normalized in st.session_state.scam_database["safe_prefixes"]:
        return "緊急通報"
    elif normalized.startswith('0120') or normalized.startswith('0800'):
        return "フリーダイヤル"
    elif normalized.startswith('050'):
        return "IP電話"
    elif normalized.startswith('090') or normalized.startswith('080') or normalized.startswith('070'):
        return "携帯電話"
    elif normalized.startswith('0570'):
        return "ナビダイヤル"
    elif normalized.startswith('0'):
        return "固定電話"
    elif normalized.startswith('+'):
        return "国際電話"
    else:
        return "不明"

def identify_caller_type(number, normalized):
    """発信者タイプの詳細識別"""
    caller_info = {
        "type": "不明",
        "confidence": "低",
        "details": [],
        "category": "その他"
    }
    
    # 緊急番号
    if normalized in ["110", "119", "118"]:
        caller_info["type"] = "緊急通報番号"
        caller_info["confidence"] = "確実"
        caller_info["category"] = "公的機関"
        caller_info["details"].append("警察・消防・海上保安庁")
        return caller_info
    
    # 公的機関の代表番号パターン
    government_patterns = {
        "03-3581": "官公庁（霞が関周辺）",
        "03-5253": "厚生労働省・文部科学省エリア",
        "03-3580": "警察庁周辺",
        "03-5321": "都庁・都の機関",
        "06-6941": "大阪府庁周辺",
    }
    
    for prefix, org in government_patterns.items():
        # numberの最初の6-7桁とprefixを比較
        if number.startswith(prefix):
            caller_info["type"] = "公的機関"
            caller_info["confidence"] = "高"
            caller_info["category"] = "公的機関"
            caller_info["details"].append(org)
            return caller_info
    
    # 銀行・金融機関
    bank_patterns = {
        "0120-86": "三菱UFJ銀行系",
        "0120-77": "三井住友銀行系",
        "0120-65": "みずほ銀行系",
        "0120-39": "ゆうちょ銀行系",
    }
    
    for prefix, bank in bank_patterns.items():
        if number.startswith(prefix):
            caller_info["type"] = "金融機関"
            caller_info["confidence"] = "中"
            caller_info["category"] = "一般企業"
            caller_info["details"].append(bank)
            caller_info["details"].append("⚠️ 本物か必ず確認してください")
            return caller_info
    
    # 番号タイプによる判定
    number_type = identify_number_type(normalized)
    
    if number_type == "フリーダイヤル":
        caller_info["type"] = "企業カスタマーサポート"
        caller_info["confidence"] = "中"
        caller_info["category"] = "一般企業"
        caller_info["details"].append("フリーダイヤル（通話無料）")
        caller_info["details"].append("企業からの連絡が多い")
    elif number_type == "ナビダイヤル":
        caller_info["type"] = "企業ナビダイヤル"
        caller_info["confidence"] = "中"
        caller_info["category"] = "一般企業"
        caller_info["details"].append("通話料有料（高額になることも）")
        caller_info["details"].append("企業のサポートセンター等")
    elif number_type == "IP電話":
        caller_info["type"] = "IP電話利用者"
        caller_info["confidence"] = "低"
        caller_info["category"] = "不明"
        caller_info["details"].append("個人/企業どちらも可能性あり")
        caller_info["details"].append("IP電話は匿名性が高い")
        caller_info["details"].append("⚠️ 詐欺に悪用されやすい")
    elif number_type == "携帯電話":
        caller_info["type"] = "個人携帯電話"
        caller_info["confidence"] = "高"
        caller_info["category"] = "個人"
        caller_info["details"].append("個人契約の携帯電話")
        caller_info["details"].append("まれに法人契約もあり")
    elif number_type == "固定電話":
        area = identify_area(number)
        if area != "不明":
            caller_info["type"] = f"固定電話（{area}）"
            caller_info["confidence"] = "中"
            caller_info["category"] = "企業または個人"
            caller_info["details"].append(f"地域: {area}")
            caller_info["details"].append("企業のオフィスまたは個人宅")
        else:
            caller_info["type"] = "固定電話"
            caller_info["confidence"] = "低"
            caller_info["category"] = "不明"
    elif number_type == "国際電話":
        caller_info["type"] = "国際電話"
        caller_info["confidence"] = "確実"
        caller_info["category"] = "国際"
        caller_info["details"].append("海外からの着信")
        caller_info["details"].append("⚠️ 国際詐欺に注意")
    
    return caller_info

def analyze_phone_number(number, use_ai=False, api_key=None):
    """電話番号解析"""
    # エラーチェック
    if not number:
        return {
            "original": "", "normalized": "", "risk_level": "エラー",
            "warnings": ["番号が入力されていません"], "details": [], "recommendations": [],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ai_analysis": None, "caller_type": None
        }

    normalized = re.sub(r'[-\s()]+', '', number)
    
    result = {
        "original": number,
        "normalized": normalized,
        "risk_level": "安全",
        "warnings": [],
        "details": [],
        "recommendations": [],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ai_analysis": None,
        "caller_type": None,
        "risk_score": 10
    }
    
    # 発信者タイプ識別
    caller_type = identify_caller_type(number, normalized)
    result["caller_type"] = caller_type
    
    # 緊急番号チェック
    if normalized in ["110", "119", "118"]:
        result["risk_level"] = "緊急"
        result["risk_score"] = 0
        result["details"].append("✅ 緊急通報番号です")
        st.session_state.phone_check_history.append(result)
        return result
    
    # 既知の詐欺番号チェック
    if normalized in [re.sub(r'[-\s()]+', '', d) for d in st.session_state.scam_database["known_scam_numbers"]]:
        result["risk_level"] = "危険"
        result["risk_score"] = 95
        result["warnings"].append("🚨 既知の詐欺電話番号と一致します！")
        result["recommendations"].append("❌ 絶対に応答しないでください")
        result["recommendations"].append("📞 着信拒否設定を推奨")
    
    # ユーザー通報データチェック
    report_count = sum(1 for case in st.session_state.scam_database["reported_cases"] if re.sub(r'[-\s()]+', '', case["number"]) == normalized)
    if report_count > 0:
        if result["risk_level"] == "安全":
            result["risk_level"] = "注意"
            result["risk_score"] = max(result["risk_score"], 70)
        result["warnings"].append(f"⚠️ {report_count}件の通報あり")
        result["details"].append(f"最新の通報内容: {st.session_state.scam_database['reported_cases'][-1]['description'][:50]}...")
    
    # プレフィックスチェック
    for prefix in st.session_state.scam_database["suspicious_prefixes"]:
        if normalized.startswith(prefix):
            if result["risk_level"] == "安全":
                result["risk_level"] = "注意"
                result["risk_score"] = max(result["risk_score"], 40)
            result["warnings"].append(f"⚠️ 疑わしいプレフィックス: {prefix} (詐欺に悪用されやすい)")
            result["recommendations"].append("慎重に対応してください")
    
    # パターンチェック
    for pattern in st.session_state.scam_database["warning_patterns"]:
        if re.match(pattern, normalized):
            if result["risk_level"] == "安全":
                result["risk_level"] = "注意"
                result["risk_score"] = max(result["risk_score"], 30)
            result["warnings"].append("⚠️ 警戒が必要なパターンです (例: 国際電話、フリーダイヤル)")
    
    # 国際電話チェック
    if normalized.startswith('+') or normalized.startswith('010'):
        result["warnings"].append("🌍 国際電話です")
        result["recommendations"].append("身に覚えがない場合は応答しない")
        if result["risk_level"] == "安全":
            result["risk_level"] = "注意"
            result["risk_score"] = max(result["risk_score"], 50)
    
    # 詳細情報（発信者タイプから取得）
    result["details"].append(f"📱 番号タイプ: {caller_type['type']}")
    result["details"].append(f"📍 地域: {identify_area(number)}")
    
    # 安全な場合の推奨事項
    if result["risk_level"] == "安全":
        result["recommendations"].append("✅ 特に問題は検出されませんでした")
        result["recommendations"].append("💡 不審な要求には注意してください")
    
    # AI分析
    if use_ai and api_key and GEMINI_AVAILABLE and setup_gemini(api_key):
        with st.spinner("🤖 AIが高度な分析を実行中..."):
            ai_result = analyze_phone_with_gemini(number, result, api_key)
            if ai_result:
                result["ai_analysis"] = ai_result
                # AIの結果をリスクに反映
                if ai_result.get('ai_risk_assessment') == "危険" and result["risk_level"] != "危険":
                    result["risk_level"] = "危険"
                    result["risk_score"] = max(result["risk_score"], 90)
                elif ai_result.get('ai_risk_assessment') == "注意" and result["risk_level"] == "安全":
                    result["risk_level"] = "注意"
                    result["risk_score"] = max(result["risk_score"], 70)
                elif ai_result.get('risk_score') is not None:
                    result["risk_score"] = max(result["risk_score"], ai_result.get('risk_score'))


    # 履歴に追加
    st.session_state.phone_check_history.append(result)
    return result

def analyze_phone_with_gemini(number, basic_result, api_key):
    """Gemini AIによる電話番号分析"""
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        caller_type_info = basic_result.get('caller_type', {})
        
        prompt = f"""
あなたは電話番号の専門家です。以下の情報から、この電話番号の詳細を分析してください。この分析は、詐欺の可能性を評価するためのものです。

電話番号: {number}
正規化: {basic_result['normalized']}
発信者タイプ: {caller_type_info.get('type', '不明')}
カテゴリ: {caller_type_info.get('category', '不明')}
基本リスクレベル: {basic_result['risk_level']}

以下を分析して、JSON形式で回答してください。JSON以外は含めないでください。
{{
    "ai_risk_assessment": "安全/注意/危険",
    "risk_score": 0-100,
    "business_type": "具体的な業種 (例: カスタマーサポート、セールス、個人)",
    "fraud_patterns": ["考えられる詐欺パターン (例: 還付金詐欺、架空請求、ワン切り)"],
    "recommendations": ["推奨行動 (例: 無視、折り返し確認、通報)"],
    "summary": "総合分析（100文字程度）"
}}
"""
        
        response = model.generate_content(
            prompt,
            config=genai.types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema={
                    "type": "object",
                    "properties": {
                        "ai_risk_assessment": {"type": "string"},
                        "risk_score": {"type": "number"},
                        "business_type": {"type": "string"},
                        "fraud_patterns": {"type": "array", "items": {"type": "string"}},
                        "recommendations": {"type": "array", "items": {"type": "string"}},
                        "summary": {"type": "string"}
                    }
                }
            )
        )
        
        # response.textがJSON文字列として返されるはず
        return json.loads(response.text)
    except Exception as e:
        st.warning(f"AI分析エラー: {str(e)}")
        return None

def analyze_with_gemini(prompt, api_key):
    """Gemini AIで分析 (汎用)"""
    if not GEMINI_AVAILABLE:
        return None
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.2,
                max_output_tokens=1000,
            )
        )
        
        json_match = re.search(r'\{[\s\S]*\}', response.text)
        if json_match:
            return json.loads(json_match.group())
        return {"summary": response.text} # JSON形式でなくても、テキストを返す
    except Exception as e:
        st.error(f"❌ AI分析エラー: {str(e)}")
        return None

def display_result(result, title_override=None):
    """結果表示（Web/メール用）"""
    risk_level = result['risk_level']
    risk_score = result['risk_score']
    
    # AI分析結果を統合
    ai_summary = None
    if result.get('ai_analysis'):
        ai = result['ai_analysis']
        ai_summary = ai.get('summary')
        ai_risk_level = ai.get('ai_risk_assessment')
        ai_score = ai.get('risk_score', 0)
        
        # リスクレベルをAIとローカルのMAXで更新
        if ai_risk_level == '高リスク':
            risk_level = '危険'
        elif ai_risk_level == '中リスク' and risk_level == '安全':
            risk_level = '注意'
        risk_score = max(risk_score, ai_score)
        result['risk_level'] = risk_level # セッション内結果も更新
        result['risk_score'] = risk_score
    
    # UI表示
    if risk_level == '危険':
        st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({risk_score}/100)</h3></div>', unsafe_allow_html=True)
    elif risk_level == '注意':
        st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({risk_score}/100)</h3></div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({risk_score}/100)</h3></div>', unsafe_allow_html=True)
    
    st.progress(risk_score / 100)
    
    if ai_summary:
        st.info(f"**🤖 AI総合分析**: {ai_summary}")

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("⚠️ 警告・懸念点")
        if result['warnings']:
            for warning in result['warnings']:
                st.warning(warning)
        else:
            st.success("特に問題は検出されませんでした")
            
    with col_b:
        st.subheader("📋 詳細情報")
        if title_override == "メール":
             st.text(f"処理された文字数: {len(result.get('content', ''))}")
        for detail in result['details']:
            st.text(detail)

def display_phone_result(result):
    """結果表示（電話番号用）"""
    risk_colors = {
        "安全": "green", "注意": "orange",
        "危険": "red", "緊急": "blue"
    }
    risk_emoji = {
        "安全": "✅", "注意": "⚠️",
        "危険": "🚨", "緊急": "🚑", "エラー": "❌"
    }
    
    color = risk_colors.get(result['risk_level'], "gray")
    emoji = risk_emoji.get(result['risk_level'], "❓")
    
    st.markdown(f"## {emoji} リスク判定: :{color}[{result['risk_level']}]")
    
    # 発信者タイプ情報
    if result.get('caller_type'):
        caller = result['caller_type']
        category_icons = {
            "個人": "👤", "一般企業": "🏢", "公的機関": "🏛️",
            "金融機関": "🏦", "国際": "🌍", "特殊": "⚙️",
            "不明": "❓", "その他": "📞"
        }
        icon = category_icons.get(caller['category'], "📞")
        
        st.info(f"""
        ### {icon} 発信者タイプ: **{caller['type']}**
        **カテゴリ**: {caller['category']}  
        **信頼度**: {caller['confidence']}
        """)
        
        if caller['details']:
            with st.expander("🔍 発信者詳細情報"):
                for detail in caller['details']:
                    st.markdown(f"- {detail}")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("📞 電話番号", result['original'])
    with col2:
        st.metric("🔢 正規化", result['normalized'])
    with col3:
        st.metric("🕐 チェック時刻", result['timestamp'])
    
    st.markdown("---")
    
    # AI分析結果
    if result.get('ai_analysis'):
        ai = result['ai_analysis']
        st.success("### 🤖 Gemini AI 高度分析")
        
        if ai.get('summary'):
            st.info(f"**📝 AI総合分析**: {ai['summary']}")
        
        col_ai_1, col_ai_2 = st.columns(2)
        with col_ai_1:
            st.text(f"AI推定リスク: {ai.get('ai_risk_assessment', '不明')}")
        with col_ai_2:
            st.text(f"業種推定: {ai.get('business_type', '不明')}")
        
        if ai.get('fraud_patterns'):
            with st.expander("🎯 想定される詐欺パターン"):
                for pattern in ai['fraud_patterns']:
                    st.markdown(f"- {pattern}")
        
        st.markdown("---")
    
    # 警告
    if result['warnings']:
        st.error("### ⚠️ 警告")
        for warning in result['warnings']:
            st.markdown(f"- {warning}")
        st.markdown("")
    
    # 詳細情報
    if result['details']:
        st.info("### 📋 詳細情報 (ローカル分析)")
        for detail in result['details']:
            st.markdown(f"- {detail}")
        st.markdown("")
    
    # 推奨事項
    if result['recommendations'] or (result.get('ai_analysis') and result['ai_analysis'].get('recommendations')):
        if result['risk_level'] == "危険":
            st.error("### 💡 推奨事項")
        else:
            st.success("### 💡 推奨事項")
            
        for rec in result['recommendations']:
            st.markdown(f"- {rec}")
        
        if result.get('ai_analysis') and result['ai_analysis'].get('recommendations'):
            st.markdown("**🤖 AIからの追加推奨:**")
            for rec in result['ai_analysis']['recommendations']:
                st.markdown(f"- {rec}")

def next_quiz():
    """次のクイズへ"""
    st.session_state.quiz_index = (st.session_state.quiz_index + 1) % len(quiz_samples)
    st.session_state.answered = False

def check_quiz(user_answer, correct_answer):
    """クイズの回答チェック"""
    if user_answer == correct_answer:
        st.session_state.score += 1
        return True
    return False

# ヘッダー
st.markdown("""
<div class="main-header">
    <h1>🔒 統合セキュリティチェッカー</h1>
    <p>詐欺・フィッシング対策のための包括的なセキュリティツール</p>
</div>
""", unsafe_allow_html=True)

# サイドバー
with st.sidebar:
    st.header("⚙️ 設定")
    st.markdown("### 🤖 Gemini AI 利用設定")
    
    if GEMINI_AVAILABLE:
        st.session_state.gemini_key = st.text_input(
            "Gemini API Key",
            type="password",
            value=st.session_state.gemini_key,
            help="電話番号チェックやメール分析の精度向上に使用します。"
        )
        st.session_state.use_gemini = st.checkbox(
            "AI分析を有効にする",
            value=st.session_state.use_gemini
        )
        if st.session_state.use_gemini and not st.session_state.gemini_key:
            st.warning("AI分析を有効にするにはAPIキーを入力してください。")
    else:
        st.info("Gemini APIはインストールされていません。ローカルチェックのみ実行されます。")
        st.session_state.use_gemini = False

    st.markdown("---")
    st.header("📋 履歴")
    if st.session_state.check_history:
        st.subheader("Web/メール履歴")
        for i, item in enumerate(st.session_state.check_history[::-1]):
            st.caption(f"{item['timestamp']} - {item.get('type', '不明')}: :{item['risk_level'] == '危険' and 'red' or item['risk_level'] == '注意' and 'orange' or 'green'}[{item['risk_level']}]")
    if st.session_state.phone_check_history:
        st.subheader("電話番号履歴")
        for i, item in enumerate(st.session_state.phone_check_history[::-1]):
             st.caption(f"{item['timestamp']} - {item['original']}: :{item['risk_level'] == '危険' and 'red' or item['risk_level'] == '注意' and 'orange' or 'green'}[{item['risk_level']}]")
    
    st.markdown("---")
    st.header("📞 脅威データベース")
    st.caption(f"詐欺電話通報件数: {len(st.session_state.scam_database['reported_cases'])}")
    st.caption(f"危険ドメイン数: {len(st.session_state.threat_database['dangerous_domains']) + len(st.session_state.reported_sites)}")

# メインコンテンツ
tab1, tab2, tab3, tab4 = st.tabs(["🌐 Web/メールチェック", "📞 電話番号チェック", "🧠 セキュリティクイズ", "🚨 脅威通報"])

# --- タブ1: Web/メールチェック ---
with tab1:
    st.header("🌐 WebサイトURL & メール本文 フィッシングチェック")
    
    check_type = st.radio("チェック対象を選択", ("URL", "メール本文"), horizontal=True)
    
    if check_type == "URL":
        url_input = st.text_input("チェックしたいURLを入力してください", placeholder="例: http://login-verify-account.com/update")
        
        if st.button("URLをチェック"):
            if url_input:
                result = analyze_url_local(url_input)
                
                # AI分析（URLの意図を分析）
                if st.session_state.use_gemini and st.session_state.gemini_key:
                    if setup_gemini(st.session_state.gemini_key):
                        prompt = f"""
あなたはWebセキュリティの専門家です。以下のURLの構造と内容を分析し、フィッシングまたはマルウェアサイトの可能性を評価してください。
URL: {url_input}
基本分析結果: {result['risk_level']}

以下を分析してJSON形式で回答:
{{
    "ai_risk_assessment": "高リスク/中リスク/低リスク",
    "risk_score": 0-100,
    "reasons": ["具体的な疑わしい点"],
    "summary": "総合分析（100文字程度）"
}}
"""
                        with st.spinner("🤖 AIが高度なURL意図分析を実行中..."):
                            ai_result = analyze_phone_with_gemini(url_input, result, st.session_state.gemini_key) # analyze_phone_with_geminiを流用
                            result["ai_analysis"] = ai_result
                
                st.session_state.check_history.append({"timestamp": datetime.now().strftime("%H:%M:%S"), "type": "URL", "url": url_input, **result})
                display_result(result, title_override="URL")
            else:
                st.warning("URLを入力してください。")
                
    elif check_type == "メール本文":
        email_subject = st.text_input("件名（オプション）", placeholder="例: 【重要】あなたのアカウントが一時停止されました")
        email_content = st.text_area("メール本文を貼り付けてください", height=300, placeholder="例: セキュリティ上の理由から、以下のリンクをクリックして本人確認を行ってください...")
        
        if st.button("メール本文をチェック"):
            if email_content:
                full_content = f"件名: {email_subject}\n\n本文: {email_content}"
                result = analyze_email_local(full_content)
                result['content'] = full_content # 履歴用に保存

                # AI分析
                if st.session_state.use_gemini and st.session_state.gemini_key:
                    if setup_gemini(st.session_state.gemini_key):
                        with st.spinner("🤖 AIがメール内容のフィッシング分析を実行中..."):
                            ai_result = analyze_email_with_gemini(full_content)
                            result["ai_analysis"] = ai_result
                
                st.session_state.check_history.append({"timestamp": datetime.now().strftime("%H:%M:%S"), "type": "メール", "subject": email_subject, **result})
                display_result(result, title_override="メール")
            else:
                st.warning("メール本文を入力してください。")

# --- タブ2: 電話番号詐欺チェック ---
with tab2:
    st.header("📞 電話番号 詐欺・迷惑電話チェック")
    
    phone_number_input = st.text_input("チェックしたい電話番号を入力してください", placeholder="例: 090-XXXX-XXXX または +81-3-XXXX-XXXX")
    
    if st.button("電話番号をチェック"):
        if phone_number_input:
            result = analyze_phone_number(
                phone_number_input,
                use_ai=st.session_state.use_gemini,
                api_key=st.session_state.gemini_key
            )
            display_phone_result(result)
        else:
            st.warning("電話番号を入力してください。")

# --- タブ3: セキュリティクイズ ---
with tab3:
    st.header("🧠 セキュリティ知識クイズ")
    st.subheader(f"現在のスコア: {st.session_state.score} / {len(quiz_samples)}問中")

    current_quiz = quiz_samples[st.session_state.quiz_index]
    
    st.markdown("---")
    st.markdown(f"### 第{st.session_state.quiz_index + 1}問: これはフィッシングメールですか？")
    
    st.info(f"**件名**: {current_quiz['subject']}")
    st.code(current_quiz['content'], language="text")
    
    col_q, col_n = st.columns([1, 1])
    
    with col_q:
        user_choice = st.radio("あなたの回答", ("フィッシングである", "フィッシングではない"), disabled=st.session_state.answered, key=f"quiz_{st.session_state.quiz_index}")
        
    if not st.session_state.answered:
        if st.button("回答する", key="submit_quiz"):
            st.session_state.answered = True
            
            is_correct = check_quiz(user_choice == "フィッシングである", current_quiz['is_phishing'])
            
            if is_correct:
                st.success("🎉 正解！セキュリティ意識が高いですね。")
            else:
                st.error("❌ 不正解... もう一度注意深く確認しましょう。")
            
            st.markdown("### 💡 解説")
            st.markdown(current_quiz['explanation'])
            st.button("次の問題へ", on_click=next_quiz)

    else:
        # 回答後の表示ロジック
        is_correct = (user_choice == "フィッシングである") == current_quiz['is_phishing']
        if is_correct:
            st.success("🎉 正解！セキュリティ意識が高いですね。")
        else:
            st.error("❌ 不正解... もう一度注意深く確認しましょう。")
            
        st.markdown("### 💡 解説")
        st.markdown(current_quiz['explanation'])
        st.button("次の問題へ", on_click=next_quiz)

# --- タブ4: 脅威通報 ---
with tab4:
    st.header("🚨 詐欺・不審情報の通報")
    st.info("🚨 通報された情報は、**このアプリのセッション内でのみ**他のユーザー（あなた自身）のチェックに役立てられます。外部の警察や公的機関には通報されません。")
    
    report_type = st.radio("通報の種類", ("不審なURL/ドメイン", "詐欺・迷惑電話番号"), horizontal=True)
    
    if report_type == "不審なURL/ドメイン":
        reported_url = st.text_input("不審なURLまたはドメイン", placeholder="例: scam-site.xyz/login")
        report_desc_url = st.text_area("通報理由・被害内容（簡単に）", placeholder="例: Amazonを装って個人情報を要求された")
        
        if st.button("URL/ドメインを通報"):
            if reported_url and report_desc_url:
                try:
                    domain = urlparse(reported_url).netloc.lower()
                    if not domain:
                        domain = reported_url # URLでなければ全体をドメインと見なす
                        
                    if domain not in st.session_state.reported_sites:
                        st.session_state.reported_sites.append(domain)
                        st.session_state.threat_database["dangerous_domains"].append(domain) # ドメインDBに追加
                        st.success(f"✅ ドメイン **{domain}** をデータベースに追加しました。")
                    else:
                        st.info("このドメインは既に通報されています。")
                        
                    st.caption(f"通報内容: {report_desc_url}")
                except Exception as e:
                    st.error(f"URL解析エラー: {e}")
            else:
                st.warning("URLと通報理由を入力してください。")
                
    elif report_type == "詐欺・迷惑電話番号":
        reported_number = st.text_input("不審な電話番号", placeholder="例: 090-XXXX-XXXX")
        report_desc_phone = st.text_area("通報理由・被害内容（簡単に）", placeholder="例: 突然、未払いの料金があると脅された")
        
        if st.button("電話番号を通報"):
            normalized_number = re.sub(r'[-\s()]+', '', reported_number)
            if normalized_number and report_desc_phone:
                # 既知の詐欺番号に追加（セッション内でのみ）
                if normalized_number not in [re.sub(r'[-\s()]+', '', d) for d in st.session_state.scam_database["known_scam_numbers"]]:
                    st.session_state.scam_database["known_scam_numbers"].append(normalized_number)
                
                # 通報ケースとして追加（詳細な通報情報）
                st.session_state.scam_database["reported_cases"].append({
                    "number": reported_number,
                    "description": report_desc_phone,
                    "reports": 1,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                
                st.success(f"✅ 電話番号 **{reported_number}** をデータベースに追加し、通報内容を記録しました。")
                st.caption(f"通報内容: {report_desc_phone}")
            else:
                st.warning("電話番号と通報理由を入力してください。")