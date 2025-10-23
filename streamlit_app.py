import os
import re
from urllib.parse import urlparse
import streamlit as st
import google.generativeai as genai

# =====================================
# 🔑 Gemini APIの設定
# =====================================
# セキュリティのため、環境変数で設定することを推奨
# 例: Windowsなら PowerShell で以下を実行
# setx GEMINI_API_KEY "あなたのAPIキー"
#
# ここでは直接セット（デモ用）
os.environ["GEMINI_API_KEY"] = "AIzaSyDuxrHGEiBATrTUQ6iqiZqe_oyNbNL58Ww"
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

# 使用モデルを指定
model = genai.GenerativeModel("gemini-1.5-pro")

# =====================================
# Streamlit設定
# =====================================
st.set_page_config(page_title="🛡️ Gemini詐欺対策アプリ", page_icon="🧠", layout="wide")

st.sidebar.title("🧠 Gemini AI 詐欺対策ツール")
page = st.sidebar.radio("メニュー", ["🏠 ホーム", "📞 電話番号", "🔗 URL", "📧 メール", "🧩 クイズ", "📚 ガイド"])

# =====================================
# 🔍 Geminiに分析を依頼する関数
# =====================================
def gemini_analyze(prompt):
    """Gemini APIで自然言語によるリスク分析を行う"""
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"⚠️ Gemini分析中にエラーが発生しました: {e}"

# =====================================
# 🏠 ホーム
# =====================================
if page == "🏠 ホーム":
    st.title("🧠 Gemini AI 詐欺対策総合アプリ")
    st.markdown("""
    Google Gemini AI を活用して、  
    電話番号・URL・メール内容などを自動分析し、  
    フィッシングや詐欺の可能性を評価します。
    """)
    st.image("https://img.icons8.com/color/480/shield.png", width=120)
    st.info("Gemini AI モデル: gemini-1.5-pro")

# =====================================
# 📞 電話番号分析
# =====================================
elif page == "📞 電話番号":
    st.header("📞 電話番号リスク分析")
    phone = st.text_input("電話番号を入力してください", "050-1111-2222")

    if st.button("Geminiで分析"):
        prompt = f"""
        以下の電話番号に関して、詐欺や迷惑電話のリスクを日本語で評価してください。
        可能であれば番号の特徴（IP電話、携帯、公的機関など）を説明し、
        詐欺に使われやすいパターンとの一致を指摘してください。
        電話番号: {phone}
        """
        result = gemini_analyze(prompt)
        st.subheader("🔍 Gemini分析結果")
        st.write(result)

# =====================================
# 🔗 URL分析
# =====================================
elif page == "🔗 URL":
    st.header("🔗 URL安全性チェック")
    url = st.text_input("URLを入力してください", "http://paypal-secure-login.com")

    if st.button("Geminiで分析"):
        prompt = f"""
        次のURLが詐欺・フィッシング・マルウェアサイトの可能性があるかを日本語で分析してください。
        ドメイン構造や不審な単語、プロトコルの安全性も説明してください。
        URL: {url}
        """
        result = gemini_analyze(prompt)
        st.subheader("🔍 Gemini分析結果")
        st.write(result)

# =====================================
# 📧 メール本文分析
# =====================================
elif page == "📧 メール":
    st.header("📧 メール本文チェック")
    email_text = st.text_area("メール本文を貼り付けてください", height=200)

    if st.button("Geminiで分析"):
        prompt = f"""
        以下のメール本文を解析し、詐欺・フィッシング・スパムの可能性を評価してください。
        不審な点、怪しい文面、偽装URLがあれば説明してください。
        結果を日本語で簡潔に出力。
        ----
        {email_text}
        """
        result = gemini_analyze(prompt)
        st.subheader("🔍 Gemini分析結果")
        st.write(result)

# =====================================
# 🧩 クイズ
# =====================================
elif page == "🧩 クイズ":
    st.header("🧩 詐欺パターンクイズ（Gemini解説付き）")

    quiz = {
        "subject": "【重要】アカウントが停止されました",
        "body": "あなたのアカウントに不正アクセスがありました。以下のリンクから確認してください。\nhttp://security-update-login.com",
    }

    st.markdown(f"#### 件名: {quiz['subject']}")
    st.code(quiz['body'])

    ans = st.radio("このメールは安全ですか？", ["🚨 危険な可能性が高い", "✅ 安全そう"])

    if st.button("Geminiの解説を見る"):
        prompt = f"""
        以下のメールがフィッシング詐欺かどうかを日本語で判断し、理由を短く説明してください。
        ----
        件名: {quiz['subject']}
        本文: {quiz['body']}
        """
        explanation = gemini_analyze(prompt)
        st.info(explanation)

# =====================================
# 📚 ガイド
# =====================================
elif page == "📚 ガイド":
    st.header("📚 詐欺対策ガイド（Geminiヒント付き）")

    st.markdown("""
    ### 💡 電話詐欺の特徴
    - 「警察」「金融庁」などを名乗る
    - 急に金銭や個人情報を求める
    - 国際・050番号は要注意

    ### 🌐 フィッシング詐欺の特徴
    - 「アカウント停止」「緊急確認」など不安を煽る言葉
    - 不自然な日本語や偽ドメイン

    ### ✅ 安全対策
    - 不審なリンクは開かない  
    - 公式サイトで直接ログイン  
    - 電話・メールで個人情報を答えない
    """)

    if st.button("Geminiに最新傾向を聞く"):
        prompt = "2025年現在、日本国内で増えている詐欺やフィッシング手口の傾向を簡潔に説明してください。"
        trend = gemini_analyze(prompt)
        st.subheader("🧠 Geminiの最新知見")
        st.write(trend)

st.sidebar.info("⚠️ Gemini AIの出力は参考情報です。最終的な判断はご自身で行ってください。")
