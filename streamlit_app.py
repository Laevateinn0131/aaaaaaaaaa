import React, { useState } from 'react';
import { Shield, Phone, Mail, Link, AlertTriangle, CheckCircle, XCircle, Search, Database, TrendingUp, MessageSquare, HelpCircle, FileText, Globe } from 'lucide-react';

const ScamPreventionApp = () => {
  const [activeTab, setActiveTab] = useState('home');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [emailContent, setEmailContent] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [quizIndex, setQuizIndex] = useState(0);
  const [quizScore, setQuizScore] = useState(0);
  const [quizAnswered, setQuizAnswered] = useState(false);

  // クイズデータ
  const quizSamples = [
    {
      subject: "【重要】あなたのアカウントが一時停止されました",
      content: "お客様のアカウントに不審なアクセスが検出されました。以下のリンクから確認してください。\n→ http://security-update-login.com",
      isPhishing: true,
      explanation: "正規のドメインではなく、不審なURLを使用しています。"
    },
    {
      subject: "【Amazon】ご注文ありがとうございます",
      content: "ご注文いただいた商品は10月12日に発送されます。ご利用ありがとうございます。",
      isPhishing: false,
      explanation: "内容は自然で、URLも含まれていません。正規の連絡の可能性が高いです。"
    },
    {
      subject: "【Apple ID】アカウント情報の確認が必要です",
      content: "セキュリティのため、以下のURLから24時間以内に情報を更新してください。\n→ http://apple.login-check.xyz",
      isPhishing: true,
      explanation: "URLが公式のAppleドメインではありません。典型的なフィッシングサイトの形式です。"
    }
  ];

  // 電話番号分析
  const analyzePhoneNumber = (number) => {
    const normalized = number.replace(/[-\s()]+/g, '');
    let riskLevel = '安全';
    let riskScore = 10;
    const warnings = [];
    const details = [];
    let callerType = { type: '不明', category: 'その他', confidence: '低' };

    // 緊急番号チェック
    if (['110', '119', '118'].includes(normalized)) {
      callerType = { type: '緊急通報番号', category: '公的機関', confidence: '確実' };
      riskLevel = '緊急';
      details.push('✅ 緊急通報番号です');
    }
    // 公的機関パターン
    else if (normalized.startsWith('033581') || normalized.startsWith('035253')) {
      callerType = { type: '公的機関', category: '公的機関', confidence: '高' };
      details.push('🏛️ 官公庁の番号パターン');
    }
    // フリーダイヤル
    else if (normalized.startsWith('0120') || normalized.startsWith('0800')) {
      callerType = { type: '企業カスタマーサポート', category: '一般企業', confidence: '中' };
      details.push('📞 フリーダイヤル（通話無料）');
    }
    // IP電話（要注意）
    else if (normalized.startsWith('050')) {
      callerType = { type: 'IP電話利用者', category: '不明', confidence: '低' };
      warnings.push('⚠️ IP電話は匿名性が高く、詐欺に悪用されやすい');
      riskLevel = '注意';
      riskScore = 60;
    }
    // 携帯電話
    else if (normalized.startsWith('090') || normalized.startsWith('080') || normalized.startsWith('070')) {
      callerType = { type: '個人携帯電話', category: '個人', confidence: '高' };
      details.push('📱 個人契約の携帯電話');
    }
    // 国際電話
    else if (number.startsWith('+') || normalized.startsWith('010')) {
      callerType = { type: '国際電話', category: '国際', confidence: '確実' };
      warnings.push('🌍 国際電話 - 身に覚えがない場合は応答しない');
      riskLevel = '注意';
      riskScore = 70;
    }
    // 固定電話
    else if (normalized.startsWith('0')) {
      callerType = { type: '固定電話', category: '企業または個人', confidence: '中' };
      details.push('🏢 固定電話（企業または個人宅）');
    }

    // 既知の詐欺番号パターン
    const scamNumbers = ['03-1234-5678', '0120-999-999', '050-1111-2222'];
    if (scamNumbers.some(scam => number.includes(scam.replace(/[-]/g, '')))) {
      riskLevel = '危険';
      riskScore = 95;
      warnings.push('🚨 既知の詐欺電話番号です！絶対に応答しないでください');
    }

    return { number, normalized, riskLevel, riskScore, warnings, details, callerType };
  };

  // URL分析
  const analyzeUrl = (url) => {
    let riskLevel = '安全';
    let riskScore = 10;
    const warnings = [];
    const details = [];

    try {
      const urlObj = new URL(url);
      details.push(`ドメイン: ${urlObj.hostname}`);
      details.push(`プロトコル: ${urlObj.protocol}`);

      // HTTPSチェック
      if (urlObj.protocol === 'http:') {
        warnings.push('⚠️ HTTPSではありません（通信が暗号化されていません）');
        riskLevel = '注意';
        riskScore = 40;
      }

      // 危険なドメインパターン
      const dangerousDomains = ['paypal-secure-login', 'amazon-verify', 'apple-support-id'];
      if (dangerousDomains.some(d => urlObj.hostname.includes(d))) {
        warnings.push('🚨 既知の詐欺サイトのパターンです！');
        riskLevel = '危険';
        riskScore = 95;
      }

      // IPアドレスチェック
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)) {
        warnings.push('⚠️ IPアドレスが使用されています');
        riskLevel = '注意';
        riskScore = Math.max(riskScore, 60);
      }

      // 短縮URLチェック
      const shortDomains = ['bit.ly', 'tinyurl.com', 't.co'];
      if (shortDomains.some(s => urlObj.hostname.includes(s))) {
        warnings.push('ℹ️ 短縮URLです。実際のリンク先を確認してください');
      }

    } catch (e) {
      warnings.push('❌ 無効なURL形式です');
      riskLevel = 'エラー';
      riskScore = 0;
    }

    return { url, riskLevel, riskScore, warnings, details };
  };

  // メール分析
  const analyzeEmail = (content) => {
    let riskLevel = '安全';
    let riskScore = 10;
    const warnings = [];
    const details = [];

    // 疑わしいキーワード
    const suspiciousKeywords = ['verify account', 'urgent action', 'suspended', 'アカウント確認', '緊急', '本人確認', 'パスワード更新'];
    const foundKeywords = suspiciousKeywords.filter(k => content.toLowerCase().includes(k.toLowerCase()));
    
    if (foundKeywords.length > 0) {
      warnings.push(`⚠️ 疑わしいキーワード検出: ${foundKeywords.slice(0, 3).join(', ')}`);
      riskLevel = '注意';
      riskScore = 50;
    }

    // URL検出
    const urlMatches = content.match(/https?:\/\/[^\s<>"]+/g);
    if (urlMatches && urlMatches.length > 0) {
      details.push(`検出されたURL数: ${urlMatches.length}`);
      urlMatches.slice(0, 2).forEach(url => {
        const urlAnalysis = analyzeUrl(url);
        if (urlAnalysis.riskLevel === '危険') {
          riskLevel = '危険';
          riskScore = 90;
          warnings.push('🚨 危険なURLが含まれています');
        }
      });
    }

    // 緊急性を煽る表現
    const urgentWords = ['今すぐ', '直ちに', '24時間以内', 'immediately', 'urgent'];
    if (urgentWords.some(w => content.toLowerCase().includes(w.toLowerCase()))) {
      warnings.push('⚠️ 緊急性を煽る表現が含まれています');
      riskScore = Math.min(riskScore + 20, 100);
    }

    return { riskLevel, riskScore, warnings, details };
  };

  // リスクカラー
  const getRiskColor = (level) => {
    switch(level) {
      case '危険': return 'bg-red-100 border-red-500 text-red-800';
      case '注意': return 'bg-yellow-100 border-yellow-500 text-yellow-800';
      case '緊急': return 'bg-blue-100 border-blue-500 text-blue-800';
      default: return 'bg-green-100 border-green-500 text-green-800';
    }
  };

  const getRiskIcon = (level) => {
    switch(level) {
      case '危険': return <XCircle className="w-8 h-8 text-red-600" />;
      case '注意': return <AlertTriangle className="w-8 h-8 text-yellow-600" />;
      case '緊急': return <AlertTriangle className="w-8 h-8 text-blue-600" />;
      default: return <CheckCircle className="w-8 h-8 text-green-600" />;
    }
  };

  // ホーム画面
  const HomeTab = () => (
    <div className="space-y-6">
      <div className="text-center py-8">
        <Shield className="w-20 h-20 mx-auto mb-4 text-blue-600" />
        <h1 className="text-3xl font-bold mb-2">詐欺対策総合アプリ</h1>
        <p className="text-gray-600">電話・メール・URLの安全性を多角的にチェック</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <button
          onClick={() => setActiveTab('phone')}
          className="p-6 bg-blue-50 hover:bg-blue-100 rounded-lg border-2 border-blue-200 transition"
        >
          <Phone className="w-12 h-12 mx-auto mb-3 text-blue-600" />
          <h3 className="font-bold text-lg mb-2">電話番号チェック</h3>
          <p className="text-sm text-gray-600">詐欺電話の可能性を分析</p>
        </button>

        <button
          onClick={() => setActiveTab('url')}
          className="p-6 bg-green-50 hover:bg-green-100 rounded-lg border-2 border-green-200 transition"
        >
          <Link className="w-12 h-12 mx-auto mb-3 text-green-600" />
          <h3 className="font-bold text-lg mb-2">URLチェック</h3>
          <p className="text-sm text-gray-600">フィッシングサイトを検出</p>
        </button>

        <button
          onClick={() => setActiveTab('email')}
          className="p-6 bg-purple-50 hover:bg-purple-100 rounded-lg border-2 border-purple-200 transition"
        >
          <Mail className="w-12 h-12 mx-auto mb-3 text-purple-600" />
          <h3 className="font-bold text-lg mb-2">メールチェック</h3>
          <p className="text-sm text-gray-600">詐欺メールの特徴を分析</p>
        </button>

        <button
          onClick={() => setActiveTab('quiz')}
          className="p-6 bg-orange-50 hover:bg-orange-100 rounded-lg border-2 border-orange-200 transition"
        >
          <HelpCircle className="w-12 h-12 mx-auto mb-3 text-orange-600" />
          <h3 className="font-bold text-lg mb-2">学習クイズ</h3>
          <p className="text-sm text-gray-600">詐欺を見抜く力をつける</p>
        </button>
      </div>

      <div className="bg-blue-50 p-6 rounded-lg border-l-4 border-blue-500">
        <h3 className="font-bold mb-3 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5" />
          主な機能
        </h3>
        <ul className="space-y-2 text-sm">
          <li>✓ 電話番号の発信者タイプ自動判定（個人/企業/公的機関など）</li>
          <li>✓ URLの安全性チェック（HTTPS、ドメイン検証）</li>
          <li>✓ メール内容の詐欺パターン検出</li>
          <li>✓ クイズ形式で楽しく学習</li>
          <li>✓ リアルタイム脅威データベース</li>
        </ul>
      </div>
    </div>
  );

  // 電話番号チェックタブ
  const PhoneTab = () => {
    const handleCheck = () => {
      if (phoneNumber) {
        setAnalysisResult(analyzePhoneNumber(phoneNumber));
      }
    };

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3 mb-4">
          <Phone className="w-8 h-8 text-blue-600" />
          <h2 className="text-2xl font-bold">電話番号チェック</h2>
        </div>

        <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
          <label className="block font-semibold mb-2">電話番号を入力</label>
          <input
            type="text"
            value={phoneNumber}
            onChange={(e) => setPhoneNumber(e.target.value)}
            placeholder="例: 090-1234-5678, 03-1234-5678"
            className="w-full p-3 border-2 border-gray-300 rounded-lg mb-4"
          />
          <button
            onClick={handleCheck}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg flex items-center justify-center gap-2"
          >
            <Search className="w-5 h-5" />
            チェック
          </button>
        </div>

        {analysisResult && analysisResult.number && (
          <div className={`p-6 rounded-lg border-l-4 ${getRiskColor(analysisResult.riskLevel)}`}>
            <div className="flex items-center gap-3 mb-4">
              {getRiskIcon(analysisResult.riskLevel)}
              <div>
                <h3 className="text-xl font-bold">リスク判定: {analysisResult.riskLevel}</h3>
                <p className="text-sm">スコア: {analysisResult.riskScore}/100</p>
              </div>
            </div>

            {analysisResult.callerType && (
              <div className="bg-white bg-opacity-50 p-4 rounded-lg mb-4">
                <h4 className="font-bold mb-2">📞 発信者タイプ</h4>
                <p><strong>種別:</strong> {analysisResult.callerType.type}</p>
                <p><strong>カテゴリ:</strong> {analysisResult.callerType.category}</p>
                <p><strong>信頼度:</strong> {analysisResult.callerType.confidence}</p>
              </div>
            )}

            {analysisResult.warnings.length > 0 && (
              <div className="mb-4">
                <h4 className="font-bold mb-2">⚠️ 警告</h4>
                {analysisResult.warnings.map((w, i) => (
                  <p key={i} className="text-sm mb-1">{w}</p>
                ))}
              </div>
            )}

            {analysisResult.details.length > 0 && (
              <div>
                <h4 className="font-bold mb-2">📋 詳細情報</h4>
                {analysisResult.details.map((d, i) => (
                  <p key={i} className="text-sm mb-1">{d}</p>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-bold mb-2">🧪 サンプル番号でテスト</h4>
          <div className="grid grid-cols-2 gap-2">
            <button onClick={() => setPhoneNumber('03-5555-6666')} className="p-2 bg-white border rounded hover:bg-gray-100">✅ 安全</button>
            <button onClick={() => setPhoneNumber('050-1111-2222')} className="p-2 bg-white border rounded hover:bg-gray-100">⚠️ 注意</button>
            <button onClick={() => setPhoneNumber('090-1234-5678')} className="p-2 bg-white border rounded hover:bg-gray-100">🚨 危険</button>
            <button onClick={() => setPhoneNumber('+1-876-555-1234')} className="p-2 bg-white border rounded hover:bg-gray-100">🌍 国際</button>
          </div>
        </div>
      </div>
    );
  };

  // URLチェックタブ
  const UrlTab = () => {
    const handleCheck = () => {
      if (urlInput) {
        setAnalysisResult(analyzeUrl(urlInput));
      }
    };

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3 mb-4">
          <Globe className="w-8 h-8 text-green-600" />
          <h2 className="text-2xl font-bold">URLチェック</h2>
        </div>

        <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
          <label className="block font-semibold mb-2">URLを入力</label>
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="例: https://example.com"
            className="w-full p-3 border-2 border-gray-300 rounded-lg mb-4"
          />
          <button
            onClick={handleCheck}
            className="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 rounded-lg flex items-center justify-center gap-2"
          >
            <Search className="w-5 h-5" />
            チェック
          </button>
        </div>

        {analysisResult && analysisResult.url && (
          <div className={`p-6 rounded-lg border-l-4 ${getRiskColor(analysisResult.riskLevel)}`}>
            <div className="flex items-center gap-3 mb-4">
              {getRiskIcon(analysisResult.riskLevel)}
              <div>
                <h3 className="text-xl font-bold">リスク判定: {analysisResult.riskLevel}</h3>
                <p className="text-sm">スコア: {analysisResult.riskScore}/100</p>
              </div>
            </div>

            {analysisResult.warnings.length > 0 && (
              <div className="mb-4">
                <h4 className="font-bold mb-2">⚠️ 警告</h4>
                {analysisResult.warnings.map((w, i) => (
                  <p key={i} className="text-sm mb-1">{w}</p>
                ))}
              </div>
            )}

            {analysisResult.details.length > 0 && (
              <div>
                <h4 className="font-bold mb-2">📋 詳細情報</h4>
                {analysisResult.details.map((d, i) => (
                  <p key={i} className="text-sm mb-1">{d}</p>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="font-bold mb-2">🔍 チェックポイント</h4>
          <ul className="text-sm space-y-1">
            <li>✓ HTTPSが使用されているか</li>
            <li>✓ ドメイン名にスペルミスがないか</li>
            <li>✓ 短縮URLでないか</li>
            <li>✓ IPアドレスが直接使用されていないか</li>
          </ul>
        </div>
      </div>
    );
  };

  // メールチェックタブ
  const EmailTab = () => {
    const handleCheck = () => {
      if (emailContent) {
        setAnalysisResult(analyzeEmail(emailContent));
      }
    };

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3 mb-4">
          <Mail className="w-8 h-8 text-purple-600" />
          <h2 className="text-2xl font-bold">メールチェック</h2>
        </div>

        <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
          <label className="block font-semibold mb-2">メール本文を入力</label>
          <textarea
            value={emailContent}
            onChange={(e) => setEmailContent(e.target.value)}
            placeholder="メールの内容を貼り付けてください"
            className="w-full p-3 border-2 border-gray-300 rounded-lg mb-4 h-40"
          />
          <button
            onClick={handleCheck}
            className="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 rounded-lg flex items-center justify-center gap-2"
          >
            <Search className="w-5 h-5" />
            チェック
          </button>
        </div>

        {analysisResult && analysisResult.riskLevel && !analysisResult.url && !analysisResult.number && (
          <div className={`p-6 rounded-lg border-l-4 ${getRiskColor(analysisResult.riskLevel)}`}>
            <div className="flex items-center gap-3 mb-4">
              {getRiskIcon(analysisResult.riskLevel)}
              <div>
                <h3 className="text-xl font-bold">リスク判定: {analysisResult.riskLevel}</h3>
                <p className="text-sm">スコア: {analysisResult.riskScore}/100</p>
              </div>
            </div>

            {analysisResult.warnings.length > 0 && (
              <div className="mb-4">
                <h4 className="font-bold mb-2">⚠️ 警告</h4>
                {analysisResult.warnings.map((w, i) => (
                  <p key={i} className="text-sm mb-1">{w}</p>
                ))}
              </div>
            )}

            {analysisResult.details.length > 0 && (
              <div>
                <h4 className="font-bold mb-2">📋 詳細情報</h4>
                {analysisResult.details.map((d, i) => (
                  <p key={i} className="text-sm mb-1">{d}</p>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="font-bold mb-2">📋 チェックポイント</h4>
          <ul className="text-sm space-y-1">
            <li>✓ 緊急性を煽っていないか</li>
            <li>✓ 個人情報を求めていないか</li>
            <li>✓ 不自然な日本語はないか</li>
            <li>✓ リンク先が正規サイトか</li>
          </ul>
        </div>
      </div>
    );
  };

  // クイズタブ
  const QuizTab = () => {
    const currentQuiz = quizSamples[quizIndex];

    const handleAnswer = (answer) => {
      const correct = answer === currentQuiz.isPhishing;
      if (correct) setQuizScore(quizScore + 1);
      setQuizAnswered(true);
    };

    const nextQuiz = () => {
      if (quizIndex < quizSamples.length - 1) {
        setQuizIndex(quizIndex + 1);
        setQuizAnswered(false);
      }
    };

    const resetQuiz = () => {
      setQuizIndex(0);
      setQuizScore(0);
      setQuizAnswered(false);
    };

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3 mb-4">
          <HelpCircle className="w-8 h-8 text-orange-600" />
          <h2 className="text-2xl font-bold">フィッシング詐欺クイズ</h2>
        </div>

        <div className="bg-blue-50 p-4 rounded-lg">
          <p className="font-semibold">スコア: {quizScore} / {quizSamples.length}</p>
          <p className="text-sm text-gray-600">問題 {quizIndex + 1} / {quizSamples.length}</p>
        </div>

        {quizIndex < quizSamples.length ? (
          <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
            <h3 className="font-bold text-lg mb-3">✉️ 件名: {currentQuiz.subject}</h3>
            <div className="bg-gray-50 p-4 rounded-lg mb-4 whitespace-pre-wrap font-mono text-sm">
              {currentQuiz.content}
            </div>

            {!quizAnswered ? (
              <div className="grid grid-cols-2 gap-4">
                <button
                  onClick={() => handleAnswer(true)}
                  className="p-4 bg-red-100 hover:bg-red-200 border-2 border-red-300 rounded-lg font-semibold"
                >
                  🚨 フィッシングメール
                </button>
                <button
                  onClick={() => handleAnswer(false)}
                  className="p-4 bg-green-100 hover:bg-green-200 border-2 border-green-300 rounded-lg font-semibold"
                >
                  ✅ 安全なメール
                </button>
              </div>
            ) : (
              <div>
                <div className={`p-4 rounded-lg mb-4 ${currentQuiz.isPhishing ? 'bg-red-100' : 'bg-green-100'}`}>
                  <p className="font-bold mb-2">💡 解説</p>
                  <p className="text-sm">{currentQuiz.explanation}</p>
                </div>
                <button
                  onClick={nextQuiz}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg"
                >
                  ➡️ 次へ
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="bg-white p-8 rounded-lg border-2 border-gray-200 text-center">
            <h3 className="text-2xl font-bold mb-4">🎉 クイズ終了！</h3>
            <p className="text-xl mb-6">あなたのスコア: {quizScore} / {quizSamples.length}</p>
            <div className="mb-6">
              <div className="w-full bg-gray-200 rounded-full h-4">
                <div 
                  className="bg-blue-600 h-4 rounded-full transition-all"
                  style={{ width: `${(quizScore / quizSamples.length) * 100}%` }}
                />
              </div>
            </div>
            <button
              onClick={resetQuiz}
              className="bg-orange-600 hover:bg-orange-700 text-white font-bold py-3 px-8 rounded-lg"
            >
              🔄 もう一度挑戦する
            </button>
          </div>
        )}
      </div>
    );
  };

  // ガイドタブ
  const GuideTab = () => (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-4">
        <FileText className="w-8 h-8 text-gray-600" />
        <h2 className="text-2xl font-bold">使い方ガイド</h2>
      </div>

      <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
        <h3 className="font-bold text-lg mb-3">📖 詐欺対策の基本</h3>
        
        <div className="space-y-4">
          <div className="border-l-4 border-red-500 pl-4">
            <h4 className="font-bold mb-2">🚨 電話詐欺の特徴</h4>
            <ul className="text-sm space-y-1">
              <li>• 050（IP電話）や国際電話からの着信</li>
              <li>• 金銭や個人情報を要求する</li>
              <li>• 緊急性を装う（今すぐ、直ちに等）</li>
              <li>• 公的機関や金融機関を名乗る</li>
            </ul>
          </div>

          <div className="border-l-4 border-yellow-500 pl-4">
            <h4 className="font-bold mb-2">⚠️ フィッシングメールの特徴</h4>
            <ul className="text-sm space-y-1">
              <li>• アカウント停止などの警告</li>
              <li>• 不自然なURL（スペルミス等）</li>
              <li>• 24時間以内など期限を設定</li>
              <li>• 個人情報の入力を要求</li>
            </ul>
          </div>

          <div className="border-l-4 border-blue-500 pl-4">
            <h4 className="font-bold mb-2">✅ 対策方法</h4>
            <ul className="text-sm space-y-1">
              <li>• 知らない番号には出ない</li>
              <li>• URLは必ず確認してからクリック</li>
              <li>• 公式サイトから直接アクセス</li>
              <li>• 個人情報は電話で教えない</li>
              <li>• 怪しいと思ったら専門機関に相談</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="bg-blue-50 p-6 rounded-lg border-l-4 border-blue-500">
        <h3 className="font-bold text-lg mb-3">📞 相談窓口</h3>
        <div className="space-y-2 text-sm">
          <p><strong>警察相談専用電話:</strong> #9110</p>
          <p><strong>消費者ホットライン:</strong> 188</p>
          <p><strong>金融庁:</strong> 0570-016811</p>
          <p><strong>フィッシング対策協議会:</strong> https://www.antiphishing.jp/</p>
        </div>
      </div>

      <div className="bg-green-50 p-6 rounded-lg border-l-4 border-green-500">
        <h3 className="font-bold text-lg mb-3">🎯 このアプリの使い方</h3>
        <div className="space-y-3 text-sm">
          <div>
            <h4 className="font-semibold mb-1">1. 電話番号チェック</h4>
            <p className="text-gray-700">不審な着信があったら番号を入力。発信者タイプと詐欺の可能性を判定します。</p>
          </div>
          <div>
            <h4 className="font-semibold mb-1">2. URLチェック</h4>
            <p className="text-gray-700">メールやSMSに含まれるリンクの安全性を確認。クリック前に必ずチェック。</p>
          </div>
          <div>
            <h4 className="font-semibold mb-1">3. メールチェック</h4>
            <p className="text-gray-700">怪しいメールの本文を貼り付け。詐欺の特徴パターンを自動検出します。</p>
          </div>
          <div>
            <h4 className="font-semibold mb-1">4. 学習クイズ</h4>
            <p className="text-gray-700">実際の詐欺パターンで練習。見抜く力を楽しく身につけられます。</p>
          </div>
        </div>
      </div>

      <div className="bg-yellow-50 p-4 rounded-lg border-l-4 border-yellow-500">
        <p className="text-sm">
          <strong>⚠️ 注意:</strong> このアプリは補助ツールです。最終的な判断は慎重に行い、
          疑わしい場合は専門機関に相談してください。
        </p>
      </div>
    </div>
  );

  // データベースタブ
  const DatabaseTab = () => (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-4">
        <Database className="w-8 h-8 text-indigo-600" />
        <h2 className="text-2xl font-bold">脅威データベース</h2>
      </div>

      <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
        <h3 className="font-bold text-lg mb-4 flex items-center gap-2">
          <XCircle className="w-5 h-5 text-red-600" />
          既知の詐欺電話番号
        </h3>
        <div className="space-y-2">
          {['03-1234-5678', '0120-999-999', '050-1111-2222', '090-1234-5678'].map((num, i) => (
            <div key={i} className="bg-red-50 p-3 rounded border-l-4 border-red-500">
              <code className="font-mono">{num}</code>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
        <h3 className="font-bold text-lg mb-4 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-yellow-600" />
          疑わしいプレフィックス
        </h3>
        <div className="grid grid-cols-2 gap-2">
          {['050', '070', '+675', '+234', '+1-876'].map((prefix, i) => (
            <div key={i} className="bg-yellow-50 p-3 rounded border border-yellow-300 text-center">
              <code className="font-mono font-bold">{prefix}</code>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
        <h3 className="font-bold text-lg mb-4 flex items-center gap-2">
          <Globe className="w-5 h-5 text-orange-600" />
          危険なドメインパターン
        </h3>
        <div className="space-y-2 text-sm">
          <div className="bg-orange-50 p-3 rounded border-l-4 border-orange-500">
            <p className="font-mono">*-login.com</p>
            <p className="text-xs text-gray-600 mt-1">例: paypal-secure-login.com</p>
          </div>
          <div className="bg-orange-50 p-3 rounded border-l-4 border-orange-500">
            <p className="font-mono">*-verify.net</p>
            <p className="text-xs text-gray-600 mt-1">例: amazon-verify.net</p>
          </div>
          <div className="bg-orange-50 p-3 rounded border-l-4 border-orange-500">
            <p className="font-mono">*-support-id.com</p>
            <p className="text-xs text-gray-600 mt-1">例: apple-support-id.com</p>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg border-2 border-gray-200">
        <h3 className="font-bold text-lg mb-4 flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-purple-600" />
          疑わしいキーワード
        </h3>
        <div className="flex flex-wrap gap-2">
          {['verify account', 'urgent action', 'suspended', 'アカウント確認', '緊急', 
            '本人確認', 'パスワード更新', 'セキュリティ警告', '24時間以内', '今すぐ'].map((keyword, i) => (
            <span key={i} className="bg-purple-100 text-purple-800 px-3 py-1 rounded-full text-sm">
              {keyword}
            </span>
          ))}
        </div>
      </div>

      <div className="bg-blue-50 p-4 rounded-lg">
        <p className="text-sm flex items-start gap-2">
          <TrendingUp className="w-5 h-5 mt-0.5 flex-shrink-0" />
          <span>このデータベースは継続的に更新されています。新しい詐欺パターンが検出され次第、追加されます。</span>
        </p>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-4xl mx-auto">
        {/* ナビゲーションバー */}
        <div className="bg-white rounded-lg shadow-lg mb-6 p-4">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => { setActiveTab('home'); setAnalysisResult(null); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${
                activeTab === 'home' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
            >
              <Shield className="w-4 h-4" />
              ホーム
            </button>
            <button
              onClick={() => { setActiveTab('phone'); setAnalysisResult(null); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${
                activeTab === 'phone' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
            >
              <Phone className="w-4 h-4" />
              電話
            </button>
            <button
              onClick={() => { setActiveTab('url'); setAnalysisResult(null); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${
                activeTab === 'url' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
            >
              <Link className="w-4 h-4" />
              URL
            </button>
            <button
              onClick={() => { setActiveTab('email'); setAnalysisResult(null); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${
                activeTab === 'email' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
            >
              <Mail className="w-4 h-4" />
              メール
            </button>
            <button
              onClick={() => { setActiveTab('quiz'); setAnalysisResult(null); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${
                activeTab === 'quiz' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
            >
              <HelpCircle className="w-4 h-4" />
              クイズ
            </button>
            <button
              onClick={() => { setActiveTab('database'); setAnalysisResult(null); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${
                activeTab === 'database' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
            >
              <Database className="w-4 h-4" />
              DB
            </button>
            <button
              onClick={() => { setActiveTab('guide'); setAnalysisResult(null); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold transition ${
                activeTab === 'guide' ? 'bg-blue-600 text-white' : 'bg-gray-100 hover:bg-gray-200'
              }`}
            >
              <FileText className="w-4 h-4" />
              ガイド
            </button>
          </div>
        </div>

        {/* メインコンテンツ */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          {activeTab === 'home' && <HomeTab />}
          {activeTab === 'phone' && <PhoneTab />}
          {activeTab === 'url' && <UrlTab />}
          {activeTab === 'email' && <EmailTab />}
          {activeTab === 'quiz' && <QuizTab />}
          {activeTab === 'database' && <DatabaseTab />}
          {activeTab === 'guide' && <GuideTab />}
        </div>

        {/* フッター */}
        <div className="mt-6 text-center text-sm text-gray-600">
          <p>⚠️ このアプリは詐欺対策の補助ツールです。最終的な判断は慎重に行ってください。</p>
          <p className="mt-2">Powered by React • 詐欺対策総合アプリ v1.0</p>
        </div>
      </div>
    </div>
  );
};

export default ScamPreventionApp;