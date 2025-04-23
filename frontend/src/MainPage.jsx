import { useState, useCallback, useEffect, useMemo } from 'react';
import './App.css';
import AttackSimulator from './AttackSimulator';
import logo from './images/image.png';
import { useNavigate } from 'react-router-dom';
import Chatbot from './Chatbot';

// Helper function to determine strength class based on score
const getStrengthClass = (score) => {
  if (score >= 8) return 'strong';
  if (score >= 5) return 'medium';
  return 'weak';
};

const MainPage = ({ password, setPassword, showPassword, setShowPassword }) => {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [strength, setStrength] = useState(0);
  const [strengthLabel, setStrengthLabel] = useState('');
  const [crackTime, setCrackTime] = useState('');
  const [passwordSuggestions, setPasswordSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [showMLAnalysis, setShowMLAnalysis] = useState(false);
  const [mlAnalysis, setMLAnalysis] = useState(null);
  const [isMLLoading, setIsMLLoading] = useState(false);
  const [showMLModal, setShowMLModal] = useState(false);
  const [mlResults, setMLResults] = useState(null);
  const [showChatbot, setShowChatbot] = useState(false);
  const navigate = useNavigate();
  
  useEffect(() => {
    // Check if user has completed face authentication
    const checkAuthStatus = async () => {
      const token = localStorage.getItem('token');
      const facialId = localStorage.getItem('facialId');
      
      if (!token) {
        navigate('/login');
        return;
      }
      
      // If no facialId exists but user is logged in, redirect to appropriate face auth
      if (!facialId) {
        const response = await fetch('/api/auth/check-face-auth', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        
        const data = await response.json();
        if (data.hasFaceAuth) {
          localStorage.setItem('facialId', data.facialId);
        } else {
          window.location.href = '/faceauth.html?action=enroll';
        }
      }
    };
    
    checkAuthStatus();
  }, [navigate]);

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
    const length = pwd.length;
    
    // Length score (max 30 points)
    if (length >= 12) score += 30;
    else if (length >= 10) score += 25;
    else if (length >= 8) score += 20;
    else score += Math.max(0, length * 2); // 2 points per character for short passwords

    // Character variety score (max 30 points)
    const hasLower = /[a-z]/.test(pwd);
    const hasUpper = /[A-Z]/.test(pwd);
    const hasDigit = /[0-9]/.test(pwd);
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
    
    score += (hasLower ? 7.5 : 0);
    score += (hasUpper ? 7.5 : 0);
    score += (hasDigit ? 7.5 : 0);
    score += (hasSpecial ? 7.5 : 0);

    // Complexity bonuses (max 20 points)
    const charTypes = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
    score += (charTypes - 1) * 5; // Bonus for mixing character types

    // Pattern penalties
    const patterns = {
      repeatingChars: /(.)\1{2,}/,                    // aaa, 111, ...
      sequentialLetters: /abc|bcd|cde|def|efg|fgh/i,  // abc, cde, ...
      sequentialNumbers: /123|234|345|456|567|678|789/, // 123, 234, ...
      commonWords: /password|admin|user|login|welcome/i,
      keyboardPatterns: /qwerty|asdfgh|zxcvbn/i
    };

    // Apply penalties (max -30 points)
    Object.values(patterns).forEach(pattern => {
      if (pattern.test(pwd)) {
        score -= 6;
      }
    });

    // Entropy bonus (max 20 points)
    const charsetSize = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + 
                       (hasDigit ? 10 : 0) + (hasSpecial ? 32 : 0);
    const entropy = Math.log2(Math.pow(charsetSize || 1, length));
    score += Math.min(20, entropy / 4);

    // Final adjustments
    score = Math.max(0, Math.min(100, score)); // Ensure score is between 0 and 100
    
    // Convert to 0-10 scale for display
    return score / 10;
  };

  const handleGenerateSuggestions = () => {
    setShowChatbot(true);
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

  const generateFeedback = useCallback((pwd, backendAnalysis, breachCount) => {
    const feedback = {
      main: "",
      suggestions: [],
      vulnerabilities: backendAnalysis.patterns || [],
      weaknesses: backendAnalysis.attack_types || []
    };

    // Map backend strength score to our categories
    const strengthScore = backendAnalysis.strength_score;
    if (strengthScore < 20) feedback.main = "🚨 Extremely weak - crackable instantly";
    else if (strengthScore < 40) feedback.main = "⚠️ Weak - vulnerable to attacks";
    else if (strengthScore < 60) feedback.main = "🟡 Moderate - could be stronger";
    else feedback.main = "✅ Strong password";

    // Add suggestions from backend
    if (backendAnalysis.suggestions) {
      feedback.suggestions = backendAnalysis.suggestions;
    }

    // Add breach information if found
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

      setAnalysis({
        entropyScore: metrics.entropyScore,
        crackTime: metrics.crackTime,
        breachCount,
        isBreached: breachCount > 0,
        feedback: generateFeedback(password, metrics, breachCount),
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

  const handleMLAnalysis = async () => {
    if (!password) return;
    
    setIsMLLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/analyze-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ password })
      });

      let data;
      const text = await response.text();
      
      try {
        data = JSON.parse(text);
      } catch (e) {
        console.error('Failed to parse response:', text);
        throw new Error('Invalid response from server');
      }

      if (!response.ok) {
        throw new Error(data.message || 'Failed to analyze password');
      }
      
      if (data.error) {
        throw new Error(data.message || 'Failed to analyze password');
      }
      
      // Calculate our own strength score
      const strengthScore = calculatePasswordStrength(password);
      
      // Transform the data to match our UI expectations
      const processedData = {
        score: strengthScore,
        category: getStrengthCategory(strengthScore),
        confidence: data?.confidence || 0,
        details: {
          length: data?.features?.length || password.length,
          entropy: data?.features?.entropy || calculateEntropy(password),
          characterTypes: {
            uppercase: data?.features?.has_upper || /[A-Z]/.test(password),
            lowercase: data?.features?.has_lower || /[a-z]/.test(password),
            numbers: data?.features?.has_digit || /[0-9]/.test(password),
            symbols: data?.features?.has_special || /[^A-Za-z0-9]/.test(password),
            total: data?.features?.char_types || [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/]
              .filter(regex => regex.test(password)).length
          }
        },
        crackTimes: data?.crack_times || {},
        suggestions: data?.suggestions || generateSuggestions(password, strengthScore)
      };

      console.log('Processed data:', processedData);
      setMLResults(processedData);
      setShowMLModal(true);
    } catch (error) {
      console.error('ML Analysis error:', error);
      // Even on error, calculate and show local strength analysis
      const strengthScore = calculatePasswordStrength(password);
      setMLResults({
        error: true,
        message: error.message || 'Unable to analyze password. Please try again.',
        score: strengthScore,
        category: getStrengthCategory(strengthScore),
        confidence: 0.85, // Local analysis confidence
        details: {
          length: password.length,
          entropy: calculateEntropy(password),
          characterTypes: {
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            numbers: /[0-9]/.test(password),
            symbols: /[^A-Za-z0-9]/.test(password),
            total: [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/]
              .filter(regex => regex.test(password)).length
          }
        },
        crackTimes: {},
        suggestions: generateSuggestions(password, strengthScore)
      });
      setShowMLModal(true);
    } finally {
      setIsMLLoading(false);
    }
  };

  // Helper function to get strength category based on score
  const getStrengthCategory = (score) => {
    if (score >= 9) return 'Very Strong';
    if (score >= 7) return 'Strong';
    if (score >= 5) return 'Moderate';
    if (score >= 3) return 'Weak';
    return 'Very Weak';
  };

  // Helper function to calculate entropy
  const calculateEntropy = (password) => {
    const charsetSize = (/[a-z]/.test(password) ? 26 : 0) +
                       (/[A-Z]/.test(password) ? 26 : 0) +
                       (/[0-9]/.test(password) ? 10 : 0) +
                       (/[^A-Za-z0-9]/.test(password) ? 32 : 0);
    return Math.log2(Math.pow(charsetSize || 1, password.length));
  };

  // Helper function to generate suggestions based on password analysis
  const generateSuggestions = (password, score) => {
    const suggestions = [];
    
    if (password.length < 12) {
      suggestions.push('Increase password length to at least 12 characters');
    }
    
    if (!/[A-Z]/.test(password)) {
      suggestions.push('Add uppercase letters');
    }
    
    if (!/[a-z]/.test(password)) {
      suggestions.push('Add lowercase letters');
    }
    
    if (!/[0-9]/.test(password)) {
      suggestions.push('Add numbers');
    }
    
    if (!/[^A-Za-z0-9]/.test(password)) {
      suggestions.push('Add special characters');
    }
    
    if (/(.)\1{2,}/.test(password)) {
      suggestions.push('Avoid repeating characters');
    }
    
    if (/123|abc|qwerty|password/i.test(password)) {
      suggestions.push('Avoid common patterns and sequences');
    }
    
    return suggestions;
  };

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
            Analyze Password
          </button>
          
          <button
            onClick={handleGenerateSuggestions}
            className="fix-btn"
            disabled={!password}
          >
            Fix It AI
          </button>

          <button
            onClick={handleMLAnalysis}
            className="ml-analysis-btn"
            disabled={!password || isMLLoading}
          >
            Advanced ML Analysis
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

            <div className="attack-section">
              <h3>Attack Simulation</h3>
              <AttackSimulator 
                password={password}
                charsetSize={calculateCharsetSize(password)}
                entropyScore={analysis.entropyScore}
              />
            </div>

            {analysis.weaknesses && analysis.weaknesses.length > 0 && (
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

            {analysis.feedback && analysis.feedback.suggestions && (
              <div className="suggestions-section">
                <h3>Improvement Suggestions</h3>
                <ul className="suggestions-list">
                  {analysis.feedback.suggestions.map((suggestion, i) => (
                    <li key={i}>
                      <span className="suggestion-bullet">•</span>
                      <span className="suggestion-text">{suggestion}</span>
                    </li>
                  ))}
                </ul>
                <button 
                  className="vulnerability-analysis-btn"
                  onClick={() => {
                    const analysisData = {
                      password,
                      score: analysis.entropyScore / 100, // Convert to 0-1 scale
                      category: analysis.feedback?.strengthCategory || 'Unknown',
                      confidence: 0.95,
                      features: {
                        length: password.length,
                        has_upper: /[A-Z]/.test(password),
                        has_lower: /[a-z]/.test(password),
                        has_digit: /[0-9]/.test(password),
                        has_special: /[^A-Za-z0-9]/.test(password),
                        char_types: ((/[A-Z]/.test(password) ? 1 : 0) +
                                   (/[a-z]/.test(password) ? 1 : 0) +
                                   (/[0-9]/.test(password) ? 1 : 0) +
                                   (/[^A-Za-z0-9]/.test(password) ? 1 : 0))
                      },
                      entropy: analysis.entropyScore,
                      patterns: analysis.vulnerabilities?.map(v => ({
                        type: v.name,
                        pattern: v.description,
                        severity: v.severity
                      })) || [],
                      crack_times: analysis.crack_times || {}
                    };
                    navigate('/vulnerability-analysis', { 
                      state: { analysisData } 
                    });
                  }}
                >
                  View Vulnerability Analysis
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {showMLModal && mlResults && (
        <div className="ml-modal-overlay">
          <div className="ml-modal">
            <button className="ml-modal-close" onClick={() => setShowMLModal(false)}>×</button>
            <h2>Advanced ML Analysis Results</h2>
            
            <div className="ml-score-section">
              <div className="ml-score">
                <h3>Strength Score</h3>
                <div className="score-value">{mlResults.score?.toFixed(1)}/10</div>
                <div className="score-category">{mlResults.category}</div>
                <div className="confidence">Confidence: {(mlResults.confidence * 100).toFixed(1)}%</div>
              </div>
            </div>

            <div className="ml-details">
              <h3>Password Features</h3>
              <div className="feature-grid">
                <div className="feature">
                  <span>Length:</span>
                  <span>{mlResults.details?.length || 0} characters</span>
                </div>
                <div className="feature">
                  <span>Entropy:</span>
                  <span>{(mlResults.details?.entropy || 0).toFixed(2)} bits</span>
                </div>
                <div className="feature">
                  <span>Character Types:</span>
                  <span>{mlResults.details?.characterTypes?.total || 0}/4</span>
                </div>
              </div>

              <div className="char-types">
                <h4>Character Sets Used:</h4>
                <div className="char-type-grid">
                  <div className={`char-type ${mlResults.details?.characterTypes?.uppercase ? 'active' : ''}`}>
                    <span>ABC</span>
                    <span>Uppercase</span>
                  </div>
                  <div className={`char-type ${mlResults.details?.characterTypes?.lowercase ? 'active' : ''}`}>
                    <span>abc</span>
                    <span>Lowercase</span>
                  </div>
                  <div className={`char-type ${mlResults.details?.characterTypes?.numbers ? 'active' : ''}`}>
                    <span>123</span>
                    <span>Numbers</span>
                  </div>
                  <div className={`char-type ${mlResults.details?.characterTypes?.symbols ? 'active' : ''}`}>
                    <span>@#$</span>
                    <span>Symbols</span>
                  </div>
                </div>
              </div>
            </div>

            {Object.keys(mlResults.crackTimes || {}).length > 0 && (
              <div className="crack-times">
                <h3>Estimated Crack Times</h3>
                <div className="crack-times-grid">
                  {Object.entries(mlResults.crackTimes).map(([method, data]) => (
                    <div key={method} className="crack-time-card">
                      <div className="attack-type">
                        <span className="method">{method}</span>
                        <span className="description">{data.description}</span>
                      </div>
                      <div className="time-estimate">
                        <span className="time">{data.time_readable}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            
          </div>
        </div>
      )}

      {showChatbot && (
        <div className="chatbot-modal">
          <div className="chatbot-modal-content">
            <button 
              className="close-chatbot"
              onClick={() => setShowChatbot(false)}
            >
              ×
            </button>
            <Chatbot 
              password={password}
              onPasswordSelect={(newPassword) => {
                setPassword(newPassword);
                setShowChatbot(false);
              }}
            />
          </div>
        </div>
      )}

      <style jsx>{`
        .button-group {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 10px;
          margin: 20px 0;
        }

        .analyze-btn {
          grid-column: 1 / -1;
          background: #4a89dc;
          color: white;
          border: none;
          padding: 15px;
          border-radius: 8px;
          font-size: 1rem;
          cursor: pointer;
          transition: background 0.3s;
        }

        .analyze-btn:hover {
          background: #357abd;
        }

        .fix-btn, .ml-analysis-btn {
          background: #6c757d;
          color: white;
          border: none;
          padding: 15px;
          border-radius: 8px;
          font-size: 1rem;
          cursor: pointer;
          transition: background 0.3s;
        }

        .fix-btn:hover, .ml-analysis-btn:hover {
          background: #5a6268;
        }

        .fix-btn:disabled, .ml-analysis-btn:disabled {
          background: #cccccc;
          cursor: not-allowed;
        }

        @media (max-width: 768px) {
          .button-group {
            grid-template-columns: 1fr;
          }
        }

        .ml-analysis-btn {
          background: #2c3e50;
          color: white;
          border: none;
          padding: 10px 20px;
          border-radius: 5px;
          cursor: pointer;
          margin-left: 10px;
        }

        .ml-analysis-btn:disabled {
          background: #95a5a6;
          cursor: not-allowed;
        }

        .ml-modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.7);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 1000;
        }

        .ml-modal {
          background: white;
          border-radius: 12px;
          padding: 2rem;
          max-width: 800px;
          width: 90%;
          max-height: 90vh;
          overflow-y: auto;
          position: relative;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        }

        .ml-modal-close {
          position: absolute;
          top: 1rem;
          right: 1rem;
          background: none;
          border: none;
          font-size: 1.5rem;
          cursor: pointer;
          color: #666;
        }

        .ml-score-section {
          text-align: center;
          margin: 2rem 0;
          padding: 1.5rem;
          background: #f8f9fa;
          border-radius: 8px;
        }

        .score-value {
          font-size: 3rem;
          font-weight: bold;
          color: #2c3e50;
          margin: 0.5rem 0;
        }

        .score-category {
          font-size: 1.2rem;
          color: #4a89dc;
          margin-bottom: 0.5rem;
        }

        .confidence {
          color: #666;
        }

        .feature-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 1rem;
          margin: 1rem 0;
        }

        .feature {
          display: flex;
          justify-content: space-between;
          padding: 0.75rem;
          background: #f8f9fa;
          border-radius: 6px;
        }

        .char-types {
          margin: 2rem 0;
        }

        .char-type-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
          gap: 1rem;
          margin-top: 1rem;
        }

        .char-type {
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 1rem;
          background: #f8f9fa;
          border-radius: 6px;
          opacity: 0.5;
          transition: all 0.3s ease;
        }

        .char-type.active {
          opacity: 1;
          background: #e3f2fd;
          color: #1976d2;
        }

        .crack-times {
          margin: 2rem 0;
          background: #f8f9fa;
          border-radius: 12px;
          padding: 1.5rem;
        }

        .crack-times h3 {
          margin-bottom: 1.5rem;
          color: #2c3e50;
          font-size: 1.25rem;
        }

        .crack-times-grid {
          display: grid;
          gap: 1rem;
        }

        .crack-time-card {
          background: white;
          border-radius: 8px;
          padding: 1.25rem;
          display: flex;
          justify-content: space-between;
          align-items: center;
          box-shadow: 0 2px 4px rgba(0,0,0,0.05);
          transition: transform 0.2s, box-shadow 0.2s;
        }

        .crack-time-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }

        .attack-type {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .method {
          font-weight: 600;
          color: #2c3e50;
          font-size: 1.1rem;
        }

        .description {
          color: #666;
          font-size: 0.9rem;
        }

        .time-estimate {
          text-align: right;
          padding-left: 1rem;
        }

        .time {
          font-weight: 500;
          color: #1a73e8;
          font-size: 1rem;
          white-space: nowrap;
        }

        @media (max-width: 768px) {
          .crack-time-card {
            flex-direction: column;
            text-align: center;
            gap: 1rem;
          }

          .time-estimate {
            text-align: center;
            padding-left: 0;
          }

          .attack-type {
            align-items: center;
          }
        }

        .ml-suggestions {
          margin: 2rem 0;
        }

        .ml-suggestions ul {
          list-style-type: none;
          padding: 0;
        }

        .ml-suggestions li {
          margin: 0.5rem 0;
          padding: 0.75rem;
          background: #fff3e0;
          border-radius: 6px;
        }

        .vulnerability-analysis-btn {
          background: #2c3e50;
          color: white;
          border: none;
          padding: 12px 20px;
          border-radius: 8px;
          font-size: 1rem;
          cursor: pointer;
          transition: all 0.3s;
          margin-top: 15px;
          width: 100%;
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 8px;
        }
        
        .vulnerability-analysis-btn:hover {
          background: #34495e;
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }

        .chatbot-modal {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.7);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 1000;
        }

        .chatbot-modal-content {
          background: white;
          border-radius: 12px;
          padding: 2rem;
          max-width: 800px;
          width: 90%;
          max-height: 90vh;
          overflow-y: auto;
          position: relative;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        }

        .close-chatbot {
          position: absolute;
          top: 1rem;
          right: 1rem;
          background: none;
          border: none;
          font-size: 1.5rem;
          cursor: pointer;
          color: #666;
        }

        .vulnerability-analysis-btn {
          background: #2c3e50;
          color: white;
          border: none;
          padding: 12px 20px;
          border-radius: 8px;
          font-size: 1rem;
          cursor: pointer;
          transition: all 0.3s;
          margin-top: 15px;
          width: 100%;
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 8px;
        }
        
        .vulnerability-analysis-btn:hover {
          background: #34495e;
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
      `}</style>
    </div>
  );
};

export default MainPage;