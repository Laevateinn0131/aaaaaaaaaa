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

# クイズサンプルデータ
quiz_samples = [
    {
        "subject": "【重要】あなたのアカウントが一時停止されました",
        "content": "お客様のアカウントに不審なアクセスが検出されました。以下のリンクから確認してください。\n→ http://security-update-login.com",
        "is_phishing": True,
        "explanation": "正規のドメインではなく、不審なURLを使用しています。"
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
        "explanation": "URLが公式のAppleドメインではありません。典型的なフィッシングサイトの形式です。"
    },
    {
        "subject": "【楽天】ポイント還元のお知らせ",
        "content": "キャンペーンにより、300ポイントを付与しました。楽天市場をご利用いただきありがとうございます。",
        "is_phishing": False,
        "explanation": "不自然なURLや情報要求がなく、自然な表現です。"
    },
]

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
        parsed = urlparse(url)
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
        
        # パターンマッチング
        for pattern in st.session_state.threat_database["dangerous_patterns"]:
            if re.search(pattern, url):
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
        if any(s in domain for s in short_domains):
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
        "details": []
    }
    
    # キーワードチェック
    found_keywords = []
    for keyword in st.session_state.threat_database["suspicious_keywords"]:
        if keyword.lower() in content.lower():
            found_keywords.append(keyword)
    
    if found_keywords:
        results["risk_level"] = "注意"
        results["risk_score"] = 50
        results["warnings"].append(f"⚠️ 疑わしいキーワード検出: {', '.join(found_keywords[:3])}")
    
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

def identify_area(number):
    """地域識別"""
    area_codes = {
        "03": "東京", "06": "大阪", "052": "名古屋",
        "011": "札幌", "092": "福岡", "075": "京都"
    }
    for code, area in area_codes.items():
        if number.startswith(code):
            return area
    return "不明"

def identify_number_type(normalized):
    """番号タイプ識別"""
    if normalized.startswith('0120') or normalized.startswith('0800'):
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
    if normalized.startswith('0120') or normalized.startswith('0800'):
        caller_info["type"] = "企業カスタマーサポート"
        caller_info["confidence"] = "中"
        caller_info["category"] = "一般企業"
        caller_info["details"].append("フリーダイヤル（通話無料）")
        caller_info["details"].append("企業からの連絡が多い")
    elif normalized.startswith('0570'):
        caller_info["type"] = "企業ナビダイヤル"
        caller_info["confidence"] = "中"
        caller_info["category"] = "一般企業"
        caller_info["details"].append("通話料有料（高額になることも）")
        caller_info["details"].append("企業のサポートセンター等")
    elif normalized.startswith('050'):
        caller_info["type"] = "IP電話利用者"
        caller_info["confidence"] = "低"
        caller_info["category"] = "不明"
        caller_info["details"].append("個人/企業どちらも可能性あり")
        caller_info["details"].append("IP電話は匿名性が高い")
        caller_info["details"].append("⚠️ 詐欺に悪用されやすい")
    elif normalized.startswith('090') or normalized.startswith('080') or normalized.startswith('070'):
        caller_info["type"] = "個人携帯電話"
        caller_info["confidence"] = "高"
        caller_info["category"] = "個人"
        caller_info["details"].append("個人契約の携帯電話")
        caller_info["details"].append("まれに法人契約もあり")
    elif normalized.startswith('020'):
        caller_info["type"] = "ポケベル・M2M"
        caller_info["confidence"] = "高"
        caller_info["category"] = "特殊"
        caller_info["details"].append("IoT機器等の通信")
    elif normalized.startswith('0'):
        area = identify_area(number)
        if area != "不明":
            caller_info["type"] = "固定電話（企業または個人宅）"
            caller_info["confidence"] = "中"
            caller_info["category"] = "企業または個人"
            caller_info["details"].append(f"地域: {area}")
            caller_info["details"].append("企業のオフィスまたは個人宅")
        else:
            caller_info["type"] = "固定電話"
            caller_info["confidence"] = "低"
            caller_info["category"] = "不明"
    elif number.startswith('+') or normalized.startswith('010'):
        caller_info["type"] = "国際電話"
        caller_info["confidence"] = "確実"
        caller_info["category"] = "国際"
        caller_info["details"].append("海外からの着信")
        caller_info["details"].append("⚠️ 国際詐欺に注意")
    
    return caller_info

def analyze_phone_number(number, use_ai=False, api_key=None):
    """電話番号解析"""
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
        "caller_type": None
    }
    
    # 発信者タイプ識別
    caller_type = identify_caller_type(number, normalized)
    result["caller_type"] = caller_type
    
    # 緊急番号チェック
    if normalized in ["110", "119", "118"]:
        result["risk_level"] = "緊急"
        result["details"].append("✅ 緊急通報番号です")
        return result
    
    # 既知の詐欺番号チェック
    if number in st.session_state.scam_database["known_scam_numbers"]:
        result["risk_level"] = "危険"
        result["warnings"].append("🚨 既知の詐欺電話番号です！")
        result["recommendations"].append("❌ 絶対に応答しないでください")
        result["recommendations"].append("📞 着信拒否設定を推奨")
    
    # ユーザー通報データチェック
    for case in st.session_state.scam_database["reported_cases"]:
        if case["number"] == number:
            result["risk_level"] = "危険"
            result["warnings"].append(f"⚠️ {case['reports']}件の通報あり")
            result["details"].append(f"通報内容: {case['description'][:100]}...")
    
    # プレフィックスチェック
    for prefix in st.session_state.scam_database["suspicious_prefixes"]:
        if normalized.startswith(prefix):
            if result["risk_level"] == "安全":
                result["risk_level"] = "注意"
            result["warnings"].append(f"⚠️ 疑わしいプレフィックス: {prefix}")
            result["recommendations"].append("慎重に対応してください")
    
    # パターンチェック
    for pattern in st.session_state.scam_database["warning_patterns"]:
        if re.match(pattern, normalized):
            if result["risk_level"] == "安全":
                result["risk_level"] = "注意"
            result["warnings"].append("⚠️ 警戒が必要なパターンです")
    
    # 国際電話チェック
    if number.startswith('+') or normalized.startswith('010'):
        result["warnings"].append("🌍 国際電話です")
        result["recommendations"].append("身に覚えがない場合は応答しない")
        if result["risk_level"] == "安全":
            result["risk_level"] = "注意"
    
    # 詳細情報
    result["details"].append(f"📱 番号タイプ: {identify_number_type(normalized)}")
    result["details"].append(f"📍 地域: {identify_area(number)}")
    
    # 安全な場合の推奨事項
    if result["risk_level"] == "安全":
        result["recommendations"].append("✅ 特に問題は検出されませんでした")
        result["recommendations"].append("💡 不審な要求には注意してください")
    
    # AI分析
    if use_ai and api_key:
        if setup_gemini(api_key):
            with st.spinner("🤖 AIが高度な分析を実行中..."):
                ai_result = analyze_phone_with_gemini(number, result, api_key)
                if ai_result:
                    result["ai_analysis"] = ai_result
    
    # 履歴に追加
    st.session_state.phone_check_history.append(result)
    return result

def analyze_phone_with_gemini(number, basic_result, api_key):
    """Gemini AIによる電話番号分析"""
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        caller_type_info = basic_result.get('caller_type', {})
        
        prompt = f"""
あなたは電話番号の専門家です。以下の情報から、この電話番号の詳細を分析してください。

電話番号: {number}
正規化: {basic_result['normalized']}
発信者タイプ: {caller_type_info.get('type', '不明')}
カテゴリ: {caller_type_info.get('category', '不明')}
現在のリスクレベル: {basic_result['risk_level']}

以下を分析してJSON形式で回答:
{{
   "ai_risk_assessment": "安全/注意/危険",
   "confidence_score": 0-100,
   "business_type": "具体的な業種",
   "fraud_patterns": ["考えられる詐欺パターン"],
   "recommendations": ["推奨行動"],
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
        return None
    except Exception as e:
        return None

def analyze_with_gemini(prompt, api_key):
    """Gemini AIで分析"""
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
        return None
    except Exception as e:
        st.error(f"❌ AI分析エラー: {str(e)}")
        return None

def display_result(result):
    """結果表示（Web/メール用）"""
    if result['risk_level'] == '危険':
        st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3></div>', unsafe_allow_html=True)
    elif result['risk_level'] == '注意':
        st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3></div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3></div>', unsafe_allow_html=True)
    
    st.progress(result['risk_score'] / 100)
    
    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("⚠️ 警告")
        if result['warnings']:
            for warning in result['warnings']:
                st.warning(warning)
        else:
            st.success("特に問題は検出されませんでした")
    
    with col_b:
        st.subheader("📋 詳細情報")
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
        "危険": "🚨", "緊急": "🚑"
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
        
        if ai.get('business_type'):
            st.text(f"業種推定: {ai['business_type']}")
        
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
        st.info("### 📋 詳細情報")
        for detail in result['details']:
            st.markdown(f"- {detail}")
        st.markdown("")
    
    # 推奨事項
    if result['recommendations']:
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