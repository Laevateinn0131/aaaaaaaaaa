import streamlit as st
from urllib.parse import urlparse
import re

st.set_page_config(page_title="詐欺対策総合アプリ", page_icon="🛡️", layout="wide")

# ==== ページナビゲーション ====
st.sidebar.title("🛡️ 詐欺対策総合アプリ")
page = st.sidebar.radio("メニュー", [
    "🏠 ホーム",
    "📞 電話番号チェック",
    "🔗 URLチェック",
    "📧 メールチェック",
    "🧩 学習クイズ",
    "📚 ガイド",
    "🗂️ 脅威データベース"
])

# ==== 分析ロジック ====

def analyze_phone(number):
    normalized = re.sub(r"[-\s()]+", "", number)
    risk = "安全"
    score = 10
    warnings, details = [], []
    caller = {"種別": "不明", "カテゴリ": "その他", "信頼度": "低"}

    if normalized in ["110", "119", "118"]:
        risk, score = "緊急", 100
        caller = {"種別": "緊急通報番号", "カテゴリ": "公的機関", "信頼度": "確実"}
        details.append("✅ 緊急通報番号です")
    elif normalized.startswith(("0120", "0800")):
        caller = {"種別": "企業カスタマーサポート", "カテゴリ": "企業", "信頼度": "中"}
        details.append("📞 フリーダイヤル（通話無料）")
    elif normalized.startswith("050"):
        risk, score = "注意", 60
        caller = {"種別": "IP電話", "カテゴリ": "不明", "信頼度": "低"}
        warnings.append("⚠️ IP電話は匿名性が高く、詐欺に悪用されやすい")
    elif normalized.startswith(("090", "080", "070")):
        caller = {"種別": "携帯電話", "カテゴリ": "個人", "信頼度": "高"}
        details.append("📱 個人契約の携帯電話")
    elif normalized.startswith("03"):
        caller = {"種別": "固定電話", "カテゴリ": "企業または個人", "信頼度": "中"}
        details.append("🏢 固定電話（東京地域）")
    elif normalized.startswith(("+", "010")):
        risk, score = "注意", 70
        caller = {"種別": "国際電話", "カテゴリ": "国際", "信頼度": "中"}
        warnings.append("🌍 国際電話 - 身に覚えがない場合は応答しない")

    scam_numbers = ["0312345678", "0120999999", "05011112222"]
    if normalized in scam_numbers:
        risk, score = "危険", 95
        warnings.append("🚨 既知の詐欺電話番号です！")

    return risk, score, warnings, details, caller


def analyze_url(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        risk, score = "安全", 10
        warnings, details = [], []
        details.append(f"ドメイン: {host}")
        details.append(f"プロトコル: {parsed.scheme}")

        if parsed.scheme == "http":
            warnings.append("⚠️ HTTPSではありません（暗号化されていません）")
            risk, score = "注意", 40
        if any(x in host for x in ["paypal-secure-login", "amazon-verify", "apple-support-id"]):
            warnings.append("🚨 詐欺サイトパターン検出！")
            risk, score = "危険", 95
        if re.match(r"\d{1,3}(\.\d{1,3}){3}", host):
            warnings.append("⚠️ IPアドレス形式のURLです")
            risk, score = "注意", max(score, 60)
        if any(x in host for x in ["bit.ly", "t.co", "tinyurl.com"]):
            warnings.append("ℹ️ 短縮URLです。実際のリンク先を確認してください。")
        return risk, score, warnings, details
    except Exception:
        return "エラー", 0, ["❌ 無効なURLです"], []


def analyze_email(text):
    risk, score = "安全", 10
    warnings, details = [], []
    suspicious = ["verify account", "urgent action", "アカウント確認", "緊急", "本人確認", "パスワード更新"]
    found = [k for k in suspicious if k.lower() in text.lower()]
    if found:
        warnings.append("⚠️ 疑わしいキーワード: " + ", ".join(found))
        risk, score = "注意", 50
    urls = re.findall(r"https?://[^\s]+", text)
    if urls:
        details.append(f"検出URL数: {len(urls)}")
        for u in urls:
            urisk, uscore, _, _ = analyze_url(u)
            if urisk == "危険":
                risk, score = "危険", 90
                warnings.append("🚨 危険なURLが含まれています")
    if any(x in text for x in ["今すぐ", "24時間以内", "urgent", "immediately"]):
        warnings.append("⚠️ 緊急性を煽る表現が含まれています")
        score = min(score + 20, 100)
    return risk, score, warnings, details

# ==== ページ構成 ====

if page == "🏠 ホーム":
    st.title("🛡️ 詐欺対策総合アプリ")
    st.markdown("""
    電話番号・URL・メールの安全性を総合的にチェックできます。  
    また、詐欺パターンを学べるクイズや安全ガイドも搭載。
    """)
    st.image("https://img.icons8.com/color/480/shield.png", width=120)
    st.markdown("### 主な機能")
    st.markdown("""
    - 📞 電話番号のリスク分析  
    - 🔗 URLの安全性チェック  
    - 📧 メールの詐欺パターン検出  
    - 🧩 クイズ形式の学習  
    - 🗂️ リアルタイム脅威データベース  
    """)

elif page == "📞 電話番号チェック":
    st.header("📞 電話番号チェック")
    number = st.text_input("電話番号を入力してください", "050-1111-2222")
    if st.button("分析する"):
        risk, score, warns, details, caller = analyze_phone(number)
        st.subheader(f"リスク判定: {risk}（スコア {score}/100）")
        st.write("**発信者タイプ:**")
        st.json(caller)
        if warns: st.warning("\n".join(warns))
        if details: st.info("\n".join(details))

elif page == "🔗 URLチェック":
    st.header("🔗 URLチェック")
    url = st.text_input("URLを入力してください", "http://paypal-secure-login.com")
    if st.button("チェック"):
        risk, score, warns, details = analyze_url(url)
        st.subheader(f"リスク判定: {risk}（スコア {score}/100）")
        if warns: st.warning("\n".join(warns))
        if details: st.info("\n".join(details))

elif page == "📧 メールチェック":
    st.header("📧 メールチェック")
    mail = st.text_area("メール本文を貼り付けてください", height=200)
    if st.button("分析する"):
        risk, score, warns, details = analyze_email(mail)
        st.subheader(f"リスク判定: {risk}（スコア {score}/100）")
        if warns: st.warning("\n".join(warns))
        if details: st.info("\n".join(details))

elif page == "🧩 学習クイズ":
    st.header("🧩 フィッシング詐欺クイズ")
    quizzes = [
        {
            "subject": "【重要】あなたのアカウントが一時停止されました",
            "content": "不審なアクセスが検出されました。以下のリンクから確認してください。\nhttp://security-update-login.com",
            "is_phish": True,
            "explain": "正規のドメインではありません。"
        },
        {
            "subject": "【Amazon】ご注文ありがとうございます",
            "content": "ご注文いただいた商品は10月12日に発送されます。",
            "is_phish": False,
            "explain": "自然な内容で詐欺ではありません。"
        }
    ]
    if "q" not in st.session_state: st.session_state.q = 0
    if "score" not in st.session_state: st.session_state.score = 0
    q = quizzes[st.session_state.q]
    st.markdown(f"#### 件名: {q['subject']}")
    st.code(q["content"])
    ans = st.radio("これは詐欺メールですか？", ["🚨 フィッシングメール", "✅ 安全なメール"])
    if st.button("回答"):
        correct = (ans.startswith("🚨") and q["is_phish"]) or (ans.startswith("✅") and not q["is_phish"])
        if correct:
            st.success("✅ 正解！")
            st.session_state.score += 1
        else:
            st.error("❌ 不正解")
        st.info(f"💡 解説: {q['explain']}")
        if st.session_state.q < len(quizzes) - 1:
            st.button("次へ", on_click=lambda: st.session_state.update(q=st.session_state.q+1))
        else:
            st.balloons()
            st.success(f"🎉 終了！スコア: {st.session_state.score}/{len(quizzes)}")
            st.button("最初からやり直す", on_click=lambda: st.session_state.update(q=0, score=0))

elif page == "📚 ガイド":
    st.header("📚 詐欺対策ガイド")
    st.markdown("""
    ### 🚨 電話詐欺の特徴
    - 050や国際電話
    - 公的機関を名乗る
    - 緊急性を装う
    - 金銭要求

    ### ⚠️ フィッシングメールの特徴
    - 「アカウント停止」「24時間以内」などの表現
    - 不自然な日本語やURL

    ### ✅ 対策方法
    - 不審なリンクは開かない  
    - 公式サイトに直接アクセス  
    - 知らない番号には出ない  
    - 個人情報を電話やメールで教えない  
    """)

elif page == "🗂️ 脅威データベース":
    st.header("🗂️ 既知の脅威データベース")
    st.subheader("📞 詐欺電話番号")
    st.code("03-1234-5678\n0120-999-999\n050-1111-2222\n090-1234-5678")

    st.subheader("🌍 危険ドメイン例")
    st.code("paypal-secure-login.com\namazon-verify.net\napple-support-id.com")

    st.subheader("⚠️ 疑わしいキーワード")
    st.write(", ".join([
        "verify account", "urgent action", "アカウント確認",
        "本人確認", "24時間以内", "パスワード更新"
    ]))

st.sidebar.info("⚠️ このアプリは参考ツールです。最終判断は慎重に行ってください。")
