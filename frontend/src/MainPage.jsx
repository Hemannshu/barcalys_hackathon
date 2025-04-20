import { useState, useCallback, useEffect, useMemo } from 'react';
import './App.css';
import AttackSimulator from './AttackSimulator';
import logo from './images/image.png';
import { useNavigate } from 'react-router-dom';

const MainPage = ({ password, setPassword, showPassword, setShowPassword }) => {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [strength, setStrength] = useState(0);
  const [strengthLabel, setStrengthLabel] = useState('');
  const [crackTime, setCrackTime] = useState('');
  const [passwordSuggestions, setPasswordSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const navigate = useNavigate();

  const calculateCharsetSize = (pwd) => {
    let size = 0;
    if (/[a-z]/.test(pwd)) size += 26;
    if (/[A-Z]/.test(pwd)) size += 26;
    if (/[0-9]/.test(pwd)) size += 10;
    if (/[^A-Za-z0-9]/.test(pwd)) size += 32;
    return size;
  };

  const attackTypes = useMemo(() => ({
    DICTIONARY: {
      name: "Dictionary Attack",
      description: "Uses common words/phrases",
      indicator: (pwd) => /[a-z]{4,}/i.test(pwd) && !/[^a-z0-9]/i.test(pwd),
      severity: "high"
    },
    BRUTE_FORCE: {
      name: "Brute Force",
      description: "Tries all combinations",
      indicator: (pwd) => pwd.length < 8,
      severity: "medium"
    },
    PATTERN: {
      name: "Pattern",
      description: "Targets common sequences",
      indicator: (pwd) => /123|abc|qwerty|asdf|password/i.test(pwd),
      severity: "high"
    },
    REPEATING: {
      name: "Repeating",
      description: "Exploits repeated patterns",
      indicator: (pwd) => /(.)\1{2,}/.test(pwd),
      severity: "medium"
    },
    PERSONAL_INFO: {
      name: "Personal Info",
      description: "Uses names/birthdays",
      indicator: (pwd) => pwd.toLowerCase().includes('barclays'),
      severity: "high"
    },
    SPRAYING: {
      name: "Spraying",
      description: "Tries common passwords",
      indicator: (pwd) => ['password', '123456', 'welcome'].includes(pwd.toLowerCase()),
      severity: "critical"
    }
  }), []);

  const generateStrongPasswords = useCallback((userInput) => {
    const adjectives = ["Red", "Secure", "Happy", "Digital", "Quantum", "Epic"];
    const nouns = ["Dragon", "Password", "Shield", "Fortress", "Guard", "Vault"];
    const specialChars = ["!", "@", "#", "$", "&", "*"];
    const verbs = ["Run", "Jump", "Protect", "Defend", "Encode"];
    
    const variants = [
      `${adjectives[Math.floor(Math.random() * adjectives.length)]}${
        verbs[Math.floor(Math.random() * verbs.length)]
      }${nouns[Math.floor(Math.random() * nouns.length)]}${
        Math.floor(Math.random() * 90) + 10
      }${specialChars[Math.floor(Math.random() * specialChars.length)]}`,
      
      `${userInput.slice(0, 2)}${window.crypto.getRandomValues(new Uint8Array(2)).join('').slice(0, 4)}${userInput.slice(-2)}${specialChars[Math.floor(Math.random() * specialChars.length)]}`,
      
      window.crypto.getRandomValues(new Uint32Array(3)).join('-').slice(0, 16),
      
      `${userInput}${Math.floor(Math.random() * 100)}`
        .replace(/a/gi, '@')
        .replace(/s/gi, '5')
        .replace(/o/gi, '0')
        .replace(/i/gi, '1'),
    ];

    return variants;
  }, []);

  const calculatePasswordStrength = (pwd) => {
    if (!pwd) return 0;
    
    let score = 0;
    score += Math.min(4, Math.floor(pwd.length / 3)) * 10;
    score += /[A-Z]/.test(pwd) ? 15 : 0;
    score += /[0-9]/.test(pwd) ? 15 : 0;
    score += /[^A-Za-z0-9]/.test(pwd) ? 20 : 0;
    score += !(/^[a-z]+$/i.test(pwd)) ? 20 : 0;
    score += !(/(.)\1{2,}/.test(pwd)) ? 15 : 0;
    
    return Math.min(100, score);
  };

  const handleGenerateSuggestions = () => {
    const suggestions = generateStrongPasswords(password);
    const suggestionsWithStrength = suggestions.map(pwd => ({
      password: pwd,
      strength: calculatePasswordStrength(pwd)
    }));
    setPasswordSuggestions(suggestionsWithStrength);
    setShowSuggestions(true);
  };

  const calculateAttackRiskScores = useCallback((pwd) => {
    if (!pwd) return {};
    
    const scores = {};
    const length = pwd.length;
    
    scores.DICTIONARY = /[a-z]{4,}/i.test(pwd) && !/[^a-z0-9]/i.test(pwd) 
      ? Math.min(100, 70 + (length * 2)) : 10;
    
    scores.BRUTE_FORCE = length < 8 
      ? Math.min(100, 30 + (60 - (length * 7.5))) 
      : Math.max(10, 50 - (length * 2));
    
    scores.PATTERN = /123|abc|qwerty|asdf|password/i.test(pwd) ? 85 : 15;
    
    scores.REPEATING = /(.)\1{2,}/.test(pwd) 
      ? Math.min(100, 60 + (pwd.match(/(.)\1{2,}/g)?.length * 10 || 0)) : 10;
    
    scores.PERSONAL_INFO = pwd.toLowerCase().includes('barclays') ? 90 : 10;
    
    scores.SPRAYING = ['password', '123456', 'welcome'].includes(pwd.toLowerCase()) ? 100 : 10;
    
    return scores;
  }, []);

  const calculateVulnerabilities = useCallback((pwd) => {
    const riskScores = calculateAttackRiskScores(pwd);
    return Object.entries(attackTypes)
      .map(([key, attack]) => ({
        id: key,
        name: attack.name,
        description: attack.description,
        severity: attack.severity,
        riskScore: riskScores[key] || 0,
        isVulnerable: attack.indicator(pwd)
      }));
  }, [attackTypes, calculateAttackRiskScores]);

  const generateWeaknessReview = useCallback((pwd) => {
    const review = [];
    const lowerPwd = pwd.toLowerCase();

    if (pwd.length < 12) {
      review.push({
        title: "Too Short",
        description: `Your password is only ${pwd.length} characters long. For strong security, use at least 12 characters.`,
        severity: "high"
      });
    }

    if (!/[A-Z]/.test(pwd)) {
      review.push({
        title: "Missing Uppercase",
        description: "Your password doesn't contain any uppercase letters. Mixing uppercase and lowercase letters improves security.",
        severity: "medium"
      });
    }

    if (!/[0-9]/.test(pwd)) {
      review.push({
        title: "Missing Numbers",
        description: "Your password doesn't contain any numbers. Including numbers makes your password harder to guess.",
        severity: "medium"
      });
    }

    if (!/[^A-Za-z0-9]/.test(pwd)) {
      review.push({
        title: "Missing Special Characters",
        description: "Your password doesn't contain any special characters (!@#$%^&*). These significantly increase password strength.",
        severity: "medium"
      });
    }

    if (/123|abc|qwerty|asdf/.test(lowerPwd)) {
      review.push({
        title: "Common Pattern",
        description: "Your password contains a common keyboard pattern that attackers can easily guess.",
        severity: "high"
      });
    }

    if (/(.)\1{2,}/.test(pwd)) {
      review.push({
        title: "Repeating Characters",
        description: "Your password has repeating characters which makes it easier to crack.",
        severity: "medium"
      });
    }

    if (/[a-z]{4,}/i.test(pwd) && !/[^a-z0-9]/i.test(pwd)) {
      review.push({
        title: "Dictionary Word",
        description: "Your password appears to be based on a dictionary word. Attackers use dictionary attacks to break these quickly.",
        severity: "high"
      });
    }

    if (['password', '123456', 'welcome'].includes(lowerPwd)) {
      review.push({
        title: "Common Password",
        description: "Your password is among the most commonly used passwords and is extremely vulnerable.",
        severity: "critical"
      });
    }

    if (lowerPwd.includes('barclays')) {
      review.push({
        title: "Contains Personal Info",
        description: "Your password contains identifiable information that can be easily guessed.",
        severity: "high"
      });
    }

    return review;
  }, []);

  const calculatePasswordMetrics = useCallback((pwd) => {
    if (!pwd) return {
      strength: 0,
      label: '',
      crackTime: '',
      entropyScore: 0,
      vulnerabilities: [],
      weaknesses: []
    };

    const hasLower = /[a-z]/.test(pwd);
    const hasUpper = /[A-Z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSymbol = /[^A-Za-z0-9]/.test(pwd);
    
    let charsetSize = 0;
    if (hasLower) charsetSize += 26;
    if (hasUpper) charsetSize += 26;
    if (hasNumber) charsetSize += 10;
    if (hasSymbol) charsetSize += 32;

    const entropy = Math.log2(charsetSize) * pwd.length;

    let entropyPenalty = 0;
    if (/(.)\1{2,}/.test(pwd)) entropyPenalty += 20;
    if (/[a-z]{4,}/.test(pwd)) entropyPenalty += 15;
    if (/123|abc|qwerty/.test(pwd)) entropyPenalty += 30;
    if (pwd.toLowerCase().includes('barclays')) entropyPenalty += 40;

    const effectiveEntropy = Math.max(1, entropy - entropyPenalty);
    const seconds = Math.pow(2, effectiveEntropy) / 1e12;
    
    const formatTime = (sec) => {
      if (sec < 1) return "instantly";
      if (sec < 60) return `${sec.toFixed(2)} seconds`;
      if (sec < 3600) return `${(sec/60).toFixed(2)} minutes`;
      if (sec < 86400) return `${(sec/3600).toFixed(2)} hours`;
      if (sec < 31536000) return `${(sec/86400).toFixed(2)} days`;
      return `${(sec/31536000).toFixed(2)} years`;
    };

    let score = 0;
    if (effectiveEntropy > 100) score = 4;
    else if (effectiveEntropy > 60) score = 3;
    else if (effectiveEntropy > 30) score = 2;
    else if (effectiveEntropy > 10) score = 1;
    
    const labels = [
      'Very Weak',
      'Weak',
      'Moderate', 
      'Strong',
      'Very Strong'
    ];

    return {
      strength: score,
      label: labels[score],
      crackTime: formatTime(seconds),
      entropyScore: Math.min(100, Math.floor(effectiveEntropy * 1.5)),
      vulnerabilities: calculateVulnerabilities(pwd),
      weaknesses: generateWeaknessReview(pwd)
    };
  }, [calculateVulnerabilities, generateWeaknessReview]);

  useEffect(() => {
    const metrics = calculatePasswordMetrics(password);
    setStrength(metrics.strength);
    setStrengthLabel(metrics.label);
    setCrackTime(metrics.crackTime);
  }, [password, calculatePasswordMetrics]);

  const sha1 = async (message) => {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const checkPasswordBreach = useCallback(async (pwd) => {
    try {
      const hash = await sha1(pwd);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5).toUpperCase();

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      const hashes = await response.text();
      const match = hashes.split('\r\n').find(h => h.startsWith(suffix));
      
      return match ? parseInt(match.split(':')[1]) : 0;
    } catch (error) {
      console.error("Breach check failed:", error);
      return 0;
    }
  }, []);

  const generateFeedback = useCallback((pwd, metrics, breachCount) => {
    const feedback = {
      main: "",
      suggestions: [],
      vulnerabilities: metrics.vulnerabilities,
      weaknesses: metrics.weaknesses
    };

    if (metrics.strength === 0) feedback.main = "🚨 Extremely weak - crackable instantly";
    else if (metrics.strength === 1) feedback.main = "⚠️ Weak - vulnerable to attacks";
    else if (metrics.strength === 2) feedback.main = "🟡 Moderate - could be stronger";
    else feedback.main = "✅ Strong password";

    if (pwd.length < 12) feedback.suggestions.push("Use 12+ characters");
    if (!/[A-Z]/.test(pwd)) feedback.suggestions.push("Add uppercase letters");
    if (!/[0-9]/.test(pwd)) feedback.suggestions.push("Include numbers");
    if (!/[^A-Za-z0-9]/.test(pwd)) feedback.suggestions.push("Add special characters");
    if (breachCount > 0) {
      feedback.main += ` (Found in ${breachCount} breaches)`;
      feedback.suggestions.unshift("Change this password immediately!");
    }

    return feedback;
  }, []);

  const analyzePassword = useCallback(async () => {
    if (!password.trim()) {
      setAnalysis({
        message: 'Please enter a password',
        isBreached: false,
        breachCount: 0
      });
      return;
    }
   
    setIsLoading(true);
    try {
      const metrics = calculatePasswordMetrics(password);
      const breachCount = await checkPasswordBreach(password);
      const feedback = generateFeedback(password, metrics, breachCount);

      setAnalysis({
        crackTime: metrics.crackTime,
        entropyScore: metrics.entropyScore,
        breachCount,
        feedback,
        isBreached: breachCount > 0,
        vulnerabilities: metrics.vulnerabilities,
        weaknesses: metrics.weaknesses
      });
    } catch (error) {
      setAnalysis({
        message: 'Error analyzing password',
        isBreached: false,
        breachCount: 0
      });
      console.error("Analysis error:", error);
    } finally {
      setIsLoading(false);
    }
  }, [password, calculatePasswordMetrics, checkPasswordBreach, generateFeedback]);

  return (
    <div className="app">
      <header className="header">
        <img src={logo} alt="Barclays" className="logo" />
        <h2>Password Strength Analyzer</h2>
      </header>

      <div className="password-checker">
        <div className="input-group">
          <input
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            className="password-input"
          />
          <button 
            className="toggle-visibility"
            onClick={() => setShowPassword(!showPassword)}
          >
            {showPassword ? "🙈" : "👁️"}
          </button>
        </div>

        <div className="strength-meter">
          <div className={`strength-fill strength-${strength}`} />
        </div>

        {password && (
          <div className="strength-info">
            <div className="strength-label">Strength: {strengthLabel}</div>
            <div className="real-time-crack">Crack time: {crackTime}</div>
          </div>
        )}

        <div className="button-group">
          <button 
            onClick={analyzePassword}
            disabled={isLoading}
            className={`analyze-btn ${isLoading ? 'loading' : ''}`}
          >
            {isLoading ? 'Analyzing...' : 'Analyze Password'}
          </button>
          
          <button
            onClick={handleGenerateSuggestions}
            className="fix-btn"
            disabled={!password}
          >
            How to Fix
          </button>
        </div>

        {showSuggestions && (
          <div className="suggestions-popup">
            <h4>Strong Password Suggestions:</h4>
            <ul>
              {passwordSuggestions.map((suggestion, index) => (
                <li key={index}>
                  <div className="suggestion-container">
                    <button 
                      onClick={() => {
                        setPassword(suggestion.password);
                        setShowSuggestions(false);
                      }}
                      className="suggestion-btn"
                    >
                      {suggestion.password}
                    </button>
                    <div className="strength-badge">
                      <div className="strength-meter-mini">
                        <div 
                          className="strength-fill-mini" 
                          style={{ width: `${suggestion.strength}%` }}
                        />
                      </div>
                      <span>{suggestion.strength}%</span>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
            <button 
              onClick={() => setShowSuggestions(false)}
              className="close-btn"
            >
              Close
            </button>
          </div>
        )}

        {isLoading && (
          <div className="loading-spinner">
            <div className="spinner"></div>
          </div>
        )}

        {analysis && !isLoading && (
          <div className="results-container">
            <div className="metrics-section">
              <h3>Password Metrics</h3>
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-value">{analysis.entropyScore}/100</div>
                  <div className="metric-label">Entropy</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value">{analysis.crackTime}</div>
                  <div className="metric-label">Crack Time</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value">{analysis.breachCount}</div>
                  <div className="metric-label">Breaches</div>
                </div>
              </div>
            </div>

            <AttackSimulator 
              password={password}
              charsetSize={calculateCharsetSize(password)}
              entropyScore={analysis.entropyScore}
            />

            {analysis.weaknesses.length > 0 && (
              <div className="weakness-review">
                <h3>Weakness Review</h3>
                <div className="weakness-cards">
                  {analysis.weaknesses.map((weakness, index) => (
                    <div key={index} className={`weakness-card ${weakness.severity}`}>
                      <div className="weakness-header">
                        <h4>{weakness.title}</h4>
                        <div className="weakness-severity">{weakness.severity}</div>
                      </div>
                      <p className="weakness-description">{weakness.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="suggestions-section">
              <h3>Improvement Suggestions</h3>
              <ul className="suggestions-list">
                {analysis.feedback.suggestions.map((s, i) => (
                  <li key={i}>
                    <span className="suggestion-bullet">•</span>
                    <span className="suggestion-text">{s}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="vulnerability-link">
              <button 
                onClick={() => {
                  console.log('Navigating to vulnerability analysis...');
                  navigate('/vulnerability-analysis', { state: { password } });
                }}
                className="vulnerability-button"
              >
                View Detailed Vulnerability Analysis →
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default MainPage;