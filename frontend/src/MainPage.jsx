import { useState, useCallback, useEffect, useMemo } from 'react';
import './App.css';
import './MainPage.css';
import AttackSimulator from './AttackSimulator';
import logo from './images/image.png';
import { useNavigate } from 'react-router-dom';
import Chatbot from './Chatbot';
import Mainpage from './MainPage.css';

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

  const calculateCrackTime = useCallback((pwd, mlPredictions = null) => {
    // Updated hardware capabilities with more realistic modern speeds
    const HARDWARE_SPEEDS = {
      online_throttled: 1000,                    // 1k guesses/second (throttled online attack)
      online_unthrottled: 100_000,              // 100k guesses/second (unthrottled online attack)
      offline_slow_hash: 10_000_000,            // 10M guesses/second (bcrypt/PBKDF2)
      offline_fast_hash: 10_000_000_000,        // 10B guesses/second (SHA1/MD5)
      offline_gpu_farm: 1_000_000_000_000,      // 1T guesses/second (GPU cluster)
      quantum: 10_000_000_000_000              // 10T guesses/second (future quantum)
    };

    // Calculate base entropy and character space
    const charTypes = {
      lower: /[a-z]/.test(pwd),
      upper: /[A-Z]/.test(pwd),
      digits: /[0-9]/.test(pwd),
      special: /[^A-Za-z0-9]/.test(pwd)
    };

    let charsetSize = 0;
    if (charTypes.lower) charsetSize += 26;
    if (charTypes.upper) charsetSize += 26;
    if (charTypes.digits) charsetSize += 10;
    if (charTypes.special) charsetSize += 32;

    // Calculate base entropy with adjusted formula
    const baseEntropy = Math.log2(Math.pow(charsetSize || 1, pwd.length));

    // Enhanced pattern-based penalties
    let entropyPenalty = 0;
    const patterns = {
      repeating: /(.)\1{2,}/,
      sequential_nums: /(?:012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)/,
      sequential_chars: /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|rst|stu|tuv|uvw|vwx|xyz)/i,
      keyboard_patterns: /(?:qwerty|asdfgh|zxcvbn|qazwsx|qweasd)/i,
      common_words: /(?:password|admin|welcome|login|user|guest|123456|qwerty)/i,
      dates: /(?:19\d{2}|20\d{2}|0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])/
    };

    // Increased pattern penalties for more realistic estimates
    Object.entries(patterns).forEach(([type, regex]) => {
      if (regex.test(pwd)) {
        switch (type) {
          case 'repeating':
            entropyPenalty += 30;
            break;
          case 'sequential_nums':
          case 'sequential_chars':
            entropyPenalty += 35;
            break;
          case 'keyboard_patterns':
            entropyPenalty += 40;
            break;
          case 'common_words':
            entropyPenalty += 45;
            break;
          case 'dates':
            entropyPenalty += 25;
            break;
        }
      }
    });

    // ML-based adjustments with more aggressive penalties
    let mlAdjustment = 1;
    if (mlPredictions) {
      mlAdjustment = mlPredictions.confidence * (
        mlPredictions.score >= 8 ? 1.1 :  // Strong passwords get smaller boost
        mlPredictions.score >= 6 ? 1.0 :  // Moderate passwords no change
        mlPredictions.score >= 4 ? 0.8 :  // Average passwords bigger penalty
        mlPredictions.score >= 2 ? 0.6 :  // Weak passwords significant penalty
        0.4                               // Very weak passwords severe penalty
      );
    }

    // Calculate effective entropy with more realistic adjustments
    const effectiveEntropy = Math.max(1, (baseEntropy - entropyPenalty) * mlAdjustment);

    // Dictionary attack optimization factor
    const dictionaryFactor = /^[a-zA-Z]+$/.test(pwd) ? 100 : 1;

    // Calculate crack times for different attack scenarios
    const crackTimes = {};
    Object.entries(HARDWARE_SPEEDS).forEach(([method, speed]) => {
      // Adjust combinations based on attack type
      let combinations = Math.pow(2, effectiveEntropy);
      
      // Apply dictionary optimization for word-like passwords
      if (method.includes('offline')) {
        combinations = combinations / dictionaryFactor;
      }
      
      // Calculate average case scenario (divide by 2)
      const seconds = combinations / (2 * speed);

      crackTimes[method] = {
        seconds,
        time_readable: formatCrackTime(seconds),
        description: getMethodDescription(method)
      };
    });

    return crackTimes;
  }, []);

  const formatCrackTime = (seconds) => {
    // Updated time thresholds for more granular and realistic display
    const timeUnits = [
      { unit: 'years', value: 31536000 },
      { unit: 'months', value: 2592000 },
      { unit: 'weeks', value: 604800 },
      { unit: 'days', value: 86400 },
      { unit: 'hours', value: 3600 },
      { unit: 'minutes', value: 60 },
      { unit: 'seconds', value: 1 }
    ];

    if (seconds < 0.001) return 'instantly';
    if (seconds < 1) return 'less than a second';
    
    for (const { unit, value } of timeUnits) {
      if (seconds >= value) {
        const count = seconds / value;
        // Only show one decimal place for better readability
        return `${count.toFixed(1)} ${unit}`;
      }
    }
    
    return 'instantly';
  };

  const getMethodDescription = (method) => {
    const descriptions = {
      online_throttled: 'Rate-limited online attack (1k/s)',
      online_unthrottled: 'Unrestricted online attack (100k/s)',
      offline_slow_hash: 'Offline attack with slow hash (10M/s)',
      offline_fast_hash: 'Offline attack with fast hash (10B/s)',
      offline_gpu_farm: 'Massive GPU cluster attack (1T/s)',
      quantum: 'Theoretical quantum computer attack (10T/s)'
    };
    return descriptions[method] || method;
  };

  const calculatePasswordMetrics = useCallback((pwd) => {
    if (!pwd) return {
      strength: 0,
      label: '',
      crackTime: '',
      entropyScore: 0,
      vulnerabilities: [],
      weaknesses: []
    };

    // Get ML predictions if available
    const mlPredictions = mlResults?.score ? {
      score: mlResults.score,
      confidence: mlResults.confidence || 0.85
    } : null;

    // Calculate crack times using the new function
    const crackTimes = calculateCrackTime(pwd, mlPredictions);
    
    // Find the fastest crack time for display
    const fastestCrack = Object.values(crackTimes)
      .reduce((fastest, current) => 
        current.seconds < fastest.seconds ? current : fastest
      );

    // Calculate strength score based on the fastest crack time
    let score = 0;
    if (fastestCrack.seconds >= 31536000 * 100) score = 4; // Centuries
    else if (fastestCrack.seconds >= 31536000) score = 3;  // Years
    else if (fastestCrack.seconds >= 86400) score = 2;     // Days
    else if (fastestCrack.seconds >= 3600) score = 1;      // Hours
    else score = 0;                                        // Quick to crack

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
      crackTime: fastestCrack.time_readable,
      crackTimes: crackTimes,
      entropyScore: Math.min(100, Math.floor(fastestCrack.seconds > 0 ? 
        Math.log2(fastestCrack.seconds) * 10 : 0)),
      vulnerabilities: calculateVulnerabilities(pwd),
      weaknesses: generateWeaknessReview(pwd)
    };
  }, [calculateCrackTime, calculateVulnerabilities, generateWeaknessReview, mlResults]);

  const generatePasswordFromSuggestion = (currentPassword, suggestion) => {
    if (!currentPassword) return '';
    
    let newPassword = currentPassword;
    
    if (suggestion.includes('length')) {
      // Add random characters to increase length
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
      const randomLength = Math.floor(Math.random() * 4) + 2; // Add 2-5 random characters
      for (let i = 0; i < randomLength; i++) {
        newPassword += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    } else if (suggestion.includes('uppercase')) {
      // Convert some lowercase letters to uppercase
      newPassword = newPassword.replace(/[a-z]/g, (char, index) => 
        Math.random() > 0.5 ? char.toUpperCase() : char
      );
    } else if (suggestion.includes('lowercase')) {
      // Convert some uppercase letters to lowercase
      newPassword = newPassword.replace(/[A-Z]/g, (char, index) => 
        Math.random() > 0.5 ? char.toLowerCase() : char
      );
    } else if (suggestion.includes('number')) {
      // Add a random number
      newPassword += Math.floor(Math.random() * 10);
    } else if (suggestion.includes('special')) {
      // Add a random special character
      const specialChars = '!@#$%^&*';
      newPassword += specialChars.charAt(Math.floor(Math.random() * specialChars.length));
    } else if (suggestion.includes('pattern')) {
      // Reverse the password to break patterns
      newPassword = newPassword.split('').reverse().join('');
    }
    
    return newPassword;
  };

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
      
      // Calculate crack times using our unified method
      const crackTimes = calculateCrackTime(password, {
        score: strengthScore,
        confidence: data?.confidence || 0.85
      });

      // Transform the data to match our UI expectations
      const processedData = {
        score: strengthScore,
        category: getStrengthCategory(strengthScore),
        confidence: data?.confidence || 0.85,
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
        crackTimes: crackTimes,
        suggestions: data?.suggestions || generateSuggestions(password, strengthScore)
      };

      console.log('Processed data:', processedData);
      setMLResults(processedData);
      setShowMLModal(true);
    } catch (error) {
      console.error('ML Analysis error:', error);
      // Even on error, calculate and show local strength analysis
      const strengthScore = calculatePasswordStrength(password);
      const crackTimes = calculateCrackTime(password, {
        score: strengthScore,
        confidence: 0.85
      });

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
        crackTimes: crackTimes,
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
             <div className="char-composition-section">
             <h2>Character Composition</h2>
             <div className="char-types-grid">
               <div className={`char-type ${/[A-Z]/.test(password) ? 'present' : ''}`}>
                 <span className="char-type-label">ABC</span>
                 <span className="char-type-status">{/[A-Z]/.test(password) ? '✓' : '×'}</span>
                 <span className="char-type-count">
                   {(password.match(/[A-Z]/g) || []).length} uppercase
                 </span>
               </div>
               <div className={`char-type ${/[a-z]/.test(password) ? 'present' : ''}`}>
                 <span className="char-type-label">abc</span>
                 <span className="char-type-status">{/[a-z]/.test(password) ? '✓' : '×'}</span>
                 <span className="char-type-count">
                   {(password.match(/[a-z]/g) || []).length} lowercase
                 </span>
               </div>
               <div className={`char-type ${/[0-9]/.test(password) ? 'present' : ''}`}>
                 <span className="char-type-label">123</span>
                 <span className="char-type-status">{/[0-9]/.test(password) ? '✓' : '×'}</span>
                 <span className="char-type-count">
                   {(password.match(/[0-9]/g) || []).length} numbers
                 </span>
               </div>
               <div className={`char-type ${/[^A-Za-z0-9]/.test(password) ? 'present' : ''}`}>
                 <span className="char-type-label">#@!</span>
                 <span className="char-type-status">{/[^A-Za-z0-9]/.test(password) ? '✓' : '×'}</span>
                 <span className="char-type-count">
                   {(password.match(/[^A-Za-z0-9]/g) || []).length} special
                 </span>
               </div>
             </div>
             <div className="composition-summary">
               <div className="summary-item">
                 <span>Total Length:   </span>
                 <span>{password.length} characters</span>
               </div>
               <div className="summary-item">
                 <span>Character Types Used:    </span>
                 <span>{[
                   /[A-Z]/.test(password),
                   /[a-z]/.test(password),
                   /[0-9]/.test(password),
                   /[^A-Za-z0-9]/.test(password)
                 ].filter(Boolean).length} of 4</span>
               </div>
               {/(.)\1{2,}/.test(password) && (
                 <div className="summary-item warning">
                   <span>Warning:</span>
                   <span>Contains repeating characters</span>
                 </div>
               )}
             </div>
           </div>
            )}

            {/* Enhanced Patterns Section */}
            <div className="patterns-section">
              <h2>Pattern Analysis</h2>
              <div className="patterns-grid">
                {[
                  {
                    type: 'Repeating Characters',
                    pattern: /(.)\1{2,}/.test(password) ? 'Found repeating characters' : 'No repeating characters',
                    severity: /(.)\1{2,}/.test(password) ? 'high' : 'low',
                    icon: '🔄'
                  },
                  {
                    type: 'Sequential Patterns',
                    pattern: (() => {
                      const patterns = [
                        /123|234|345|456|567|678|789/, // Numbers
                        /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/, // Letters
                        /321|432|543|654|765|876|987/, // Reverse numbers
                        /cba|dcb|edc|fed|gfe|hgf|ihg|jih|kji|lkj|mlk|nml|onm|pon|qpo|rqp|srq|tsr|uts|vut|wvu|xwv|yxw|zyx/, // Reverse letters
                        /qwerty|asdfgh|zxcvbn|1qaz2wsx|3edc4rfv|5tgb6yhn|7ujm8ik,|9ol.0p;/, // Keyboard patterns
                        /!@#$%^&*()_+|QWERTYUIOP{}|ASDFGHJKL:"|ZXCVBNM<>?/ // Shifted keyboard patterns
                      ];
                      const found = patterns.some(p => p.test(password.toLowerCase()));
                      return found ? 'Found sequential patterns' : 'No sequential patterns';
                    })(),
                    severity: (() => {
                      const patterns = [
                        /123|234|345|456|567|678|789/,
                        /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/,
                        /321|432|543|654|765|876|987/,
                        /cba|dcb|edc|fed|gfe|hgf|ihg|jih|kji|lkj|mlk|nml|onm|pon|qpo|rqp|srq|tsr|uts|vut|wvu|xwv|yxw|zyx/,
                        /qwerty|asdfgh|zxcvbn|1qaz2wsx|3edc4rfv|5tgb6yhn|7ujm8ik,|9ol.0p;/,
                        /!@#$%^&*()_+|QWERTYUIOP{}|ASDFGHJKL:"|ZXCVBNM<>?/
                      ];
                      return patterns.some(p => p.test(password.toLowerCase())) ? 'high' : 'low';
                    })(),
                    icon: '🔢'
                  },
                  {
                    type: 'Common Words & Phrases',
                    pattern: (() => {
                      const commonPatterns = [
                        /password|admin|welcome|letmein|qwerty|123456|iloveyou|princess|rockyou|abc123|monkey|football|baseball|welcome1|master|hello|freedom|whatever|qazwsx|trustno1|dragon|passw0rd|superman|starwars|letmein1|shadow|monkey1|charlie|donald|mustang|hockey|ranger|jordan|harley|batman|startrek|merlin|ginger|nicole|matthew|access|yankees|joshua|lakers|dallas|packers|hello1|george|thunder|taylor|matrix|minecraft|pokemon|starwars|superman|batman|spiderman|harrypotter|gameofthrones|breakingbad|friends|simpsons|familyguy|southpark|rickandmorty|strangerthings|thewalkingdead|gameofthrones|breakingbad|friends|simpsons|familyguy|southpark|rickandmorty|strangerthings|thewalkingdead/i,
                        /^[a-z]+[0-9]+$/, // word followed by numbers
                        /^[0-9]+[a-z]+$/, // numbers followed by word
                        /^[a-z]+[!@#$%^&*]+$/, // word followed by special chars
                        /^[!@#$%^&*]+[a-z]+$/ // special chars followed by word
                      ];
                      const found = commonPatterns.some(p => p.test(password.toLowerCase()));
                      return found ? 'Found common words/phrases' : 'No common words/phrases';
                    })(),
                    severity: (() => {
                      const commonPatterns = [
                        /password|admin|welcome|letmein|qwerty|123456|iloveyou|princess|rockyou|abc123|monkey|football|baseball|welcome1|master|hello|freedom|whatever|qazwsx|trustno1|dragon|passw0rd|superman|starwars|letmein1|shadow|monkey1|charlie|donald|mustang|hockey|ranger|jordan|harley|batman|startrek|merlin|ginger|nicole|matthew|access|yankees|joshua|lakers|dallas|packers|hello1|george|thunder|taylor|matrix|minecraft|pokemon|starwars|superman|batman|spiderman|harrypotter|gameofthrones|breakingbad|friends|simpsons|familyguy|southpark|rickandmorty|strangerthings|thewalkingdead|gameofthrones|breakingbad|friends|simpsons|familyguy|southpark|rickandmorty|strangerthings|thewalkingdead/i,
                        /^[a-z]+[0-9]+$/,
                        /^[0-9]+[a-z]+$/,
                        /^[a-z]+[!@#$%^&*]+$/,
                        /^[!@#$%^&*]+[a-z]+$/
                      ];
                      return commonPatterns.some(p => p.test(password.toLowerCase())) ? 'critical' : 'low';
                    })(),
                    icon: '📖'
                  },
                  {
                    type: 'Personal Info',
                    pattern: (() => {
                      const personalPatterns = [
                        /barclays|user|name|birthday|birth|date|year|month|day|phone|mobile|address|city|state|country|zip|postal|code|id|number|account|bank|card|credit|debit|ssn|social|security|driver|license|passport|visa|mastercard|amex|discover|paypal|venmo|cashapp|zelle|chase|wellsfargo|bankofamerica|citibank|usbank|pnc|tdbank|capitalone|ally|synchrony|barclaycard|americanexpress|visa|mastercard|discover|amex/i,
                        /(19|20)\d{2}/, // Years 1900-2099
                        /(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])/, // MM/DD or DD/MM
                        /(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/(19|20)\d{2}/, // MM/DD/YYYY
                        /(0[1-9]|[12]\d|3[01])\/(0[1-9]|1[0-2])\/(19|20)\d{2}/ // DD/MM/YYYY
                      ];
                      const found = personalPatterns.some(p => p.test(password.toLowerCase()));
                      return found ? 'Found personal information' : 'No personal information';
                    })(),
                    severity: (() => {
                      const personalPatterns = [
                        /barclays|user|name|birthday|birth|date|year|month|day|phone|mobile|address|city|state|country|zip|postal|code|id|number|account|bank|card|credit|debit|ssn|social|security|driver|license|passport|visa|mastercard|amex|discover|paypal|venmo|cashapp|zelle|chase|wellsfargo|bankofamerica|citibank|usbank|pnc|tdbank|capitalone|ally|synchrony|barclaycard|americanexpress|visa|mastercard|discover|amex/i,
                        /(19|20)\d{2}/,
                        /(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])/,
                        /(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/(19|20)\d{2}/,
                        /(0[1-9]|[12]\d|3[01])\/(0[1-9]|1[0-2])\/(19|20)\d{2}/
                      ];
                      return personalPatterns.some(p => p.test(password.toLowerCase())) ? 'high' : 'low';
                    })(),
                    icon: '👤'
                  },
                  {
                    type: 'Character Distribution',
                    pattern: password.length > 0 ? 
                      `Characters: ${password.length}, Unique: ${new Set(password).size}` : 
                      'No characters',
                    severity: password.length > 0 && new Set(password).size === password.length ? 'low' : 'medium',
                    icon: '📊'
                  },
                  {
                    type: 'Common Substitutions',
                    pattern: (() => {
                      const substitutions = [
                        /[a@4]/g,
                        /[e3]/g,
                        /[i1!]/g,
                        /[o0]/g,
                        /[s5$]/g,
                        /[t7]/g,
                        /[b8]/g,
                        /[g9]/g
                      ];
                      const normalized = substitutions.reduce((str, sub) => 
                        str.replace(sub, sub.source[1]), password.toLowerCase());
                      const found = normalized !== password.toLowerCase();
                      return found ? 'Found common character substitutions' : 'No common substitutions';
                    })(),
                    severity: (() => {
                      const substitutions = [
                        /[a@4]/g,
                        /[e3]/g,
                        /[i1!]/g,
                        /[o0]/g,
                        /[s5$]/g,
                        /[t7]/g,
                        /[b8]/g,
                        /[g9]/g
                      ];
                      const normalized = substitutions.reduce((str, sub) => 
                        str.replace(sub, sub.source[1]), password.toLowerCase());
                      return normalized !== password.toLowerCase() ? 'medium' : 'low';
                    })(),
                    icon: '🔄'
                  }
                ].map((pattern, index) => (
                  <div key={index} className="pattern-card">
                    <div className="pattern-icon">{pattern.icon}</div>
                    <div className="pattern-content">
                      <h3>{pattern.type}</h3>
                      <p className="pattern-value">{pattern.pattern}</p>
                      <div className={`severity-indicator ${pattern.severity}`}>
                        <div className="severity-dot"></div>
                        <span className="severity-text">{pattern.severity}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {analysis.feedback && analysis.feedback.suggestions && (
  <div className="suggestions-section">
    <h3>Targeted Improvement Suggestions</h3>
    <div className="suggestions-grid">
      {/* Enhanced Personal Info Detection */}
      {(analysis.weaknesses.some(w => w.title.includes("Personal Info")) || 
        password.match(/\b([A-Z][a-z]+)\b/g) || 
        password.match(/\b(19|20)\d{2}\b/g) || 
        ['john','smith','david','emma','olivia','liam','noah'].some(name => 
          new RegExp(name, 'i').test(password))) && (
        <div className="suggestion-card critical">
          <div className="suggestion-icon">👤</div>
          <div className="suggestion-content">
            <p className="suggestion-text">
              {password.match(/\b([A-Z][a-z]+)\b/g) ? 
                "Detected names or proper nouns. " : 
                "Detected personal information. "}
              Remove these as attackers can easily guess them from social media.
            </p>
            <div className="suggestion-impact">
              <span className="impact-label">Impact:</span>
              <div className="impact-meter">
                <div className="impact-fill" style={{ width: '95%' }} />
              </div>
            </div>
          </div>
          <button 
            className="apply-suggestion-btn"
            onClick={() => {
              // Replace names, years, and common first names
              let newPassword = password;
              
              // Replace capitalized words (potential names)
              const names = password.match(/\b([A-Z][a-z]+)\b/g) || [];
              names.forEach(name => {
                newPassword = newPassword.replace(name, 
                  Math.random().toString(36).slice(2, 2 + name.length));
              });
              
              // Replace common first names
              ['john','smith','david','emma','olivia','liam','noah'].forEach(name => {
                const regex = new RegExp(name, 'gi');
                newPassword = newPassword.replace(regex, 
                  Math.random().toString(36).slice(2, 2 + name.length));
              });
              
              // Replace years
              const years = password.match(/\b(19|20)\d{2}\b/g) || [];
              years.forEach(year => {
                newPassword = newPassword.replace(year, 
                  Math.floor(1000 + Math.random() * 9000));
              });
              
              setPassword(newPassword);
              analyzePassword();
            }}
          >
            Remove Personal Info
          </button>
        </div>
      )}

      {/* Dictionary Word Detection */}
      {analysis.weaknesses.some(w => w.title.includes("Dictionary")) && (
        <div className="suggestion-card high">
          <div className="suggestion-icon">📖</div>
          <div className="suggestion-content">
            <p className="suggestion-text">
              Avoid complete dictionary words. Attackers use dictionary attacks 
              that try all known words and combinations.
            </p>
            <div className="suggestion-impact">
              <span className="impact-label">Impact:</span>
              <div className="impact-meter">
                <div className="impact-fill" style={{ width: '90%' }} />
              </div>
            </div>
          </div>
          <button 
            className="apply-suggestion-btn"
            onClick={() => {
              const words = password.split(/(?=[A-Z])|\W+|_/).filter(Boolean);
              let newPassword = password;
              
              words.forEach(word => {
                if (word.length > 3) {
                  const insertPos = Math.floor(Math.random() * (word.length - 1)) + 1;
                  const randomChar = '!@#$%^&*'[Math.floor(Math.random() * 8)];
                  newPassword = newPassword.replace(
                    word, 
                    word.slice(0, insertPos) + randomChar + word.slice(insertPos)
                  );
                }
              });
              
              setPassword(newPassword);
              analyzePassword();
            }}
          >
            Obfuscate Words
          </button>
        </div>
      )}

      {/* Keyboard Pattern Detection */}
      {['qwerty','asdfgh','zxcvbn','123456','1qaz2wsx','1q2w3e4r']
        .some(pattern => password.toLowerCase().includes(pattern)) && (
        <div className="suggestion-card high">
          <div className="suggestion-icon">⌨️</div>
          <div className="suggestion-content">
            <p className="suggestion-text">
              Avoid keyboard patterns (like qwerty or 1qaz2wsx). These are 
              easily guessed by attackers.
            </p>
            <div className="suggestion-impact">
              <span className="impact-label">Impact:</span>
              <div className="impact-meter">
                <div className="impact-fill" style={{ width: '85%' }} />
              </div>
            </div>
          </div>
          <button 
            className="apply-suggestion-btn"
            onClick={() => {
              let newPassword = password;
              ['qwerty','asdfgh','zxcvbn','123456','1qaz2wsx','1q2w3e4r'].forEach(pattern => {
                const regex = new RegExp(pattern, 'gi');
                if (regex.test(newPassword)) {
                  const replacement = Array.from({length: pattern.length}, () => 
                    '!@#$%^&*'[Math.floor(Math.random() * 8)]
                  ).join('');
                  newPassword = newPassword.replace(regex, replacement);
                }
              });
              setPassword(newPassword);
              analyzePassword();
            }}
          >
            Break Patterns
          </button>
        </div>
      )}

      {/* Character Variety Suggestion */}
      {password.length > 0 && (new Set(password).size / password.length) < 0.9 && (
        <div className="suggestion-card medium">
          <div className="suggestion-icon">📊</div>
          <div className="suggestion-content">
            <p className="suggestion-text">
              Increase character variety. Your password has {new Set(password).size} 
              unique characters out of {password.length} ({(new Set(password).size/password.length*100).toFixed(0)}% unique).
            </p>
            <div className="suggestion-impact">
              <span className="impact-label">Impact:</span>
              <div className="impact-meter">
                <div className="impact-fill" style={{ width: '80%' }} />
              </div>
            </div>
          </div>
          <button 
            className="apply-suggestion-btn"
            onClick={() => {
              const missingTypes = [];
              if (!/[A-Z]/.test(password)) missingTypes.push('uppercase');
              if (!/[a-z]/.test(password)) missingTypes.push('lowercase');
              if (!/[0-9]/.test(password)) missingTypes.push('numbers');
              if (!/[^A-Za-z0-9]/.test(password)) missingTypes.push('symbols');
              
              let newPassword = password;
              const additions = Math.max(3, Math.floor(password.length * 0.3));
              
              for (let i = 0; i < additions; i++) {
                const randomType = missingTypes.length > 0 
                  ? missingTypes[Math.floor(Math.random() * missingTypes.length)]
                  : ['uppercase', 'lowercase', 'number', 'symbol'][Math.floor(Math.random() * 4)];
                
                let newChar;
                switch(randomType) {
                  case 'uppercase':
                    newChar = String.fromCharCode(Math.floor(Math.random() * 26) + 65);
                    break;
                  case 'lowercase':
                    newChar = String.fromCharCode(Math.floor(Math.random() * 26) + 97);
                    break;
                  case 'numbers':
                    newChar = Math.floor(Math.random() * 10);
                    break;
                  case 'symbols':
                    newChar = '!@#$%^&*()_+-=[]{}|;:,.<>?~'.charAt(Math.floor(Math.random() * 26));
                    break;
                }
                
                const insertPos = Math.floor(Math.random() * (newPassword.length + 1));
                newPassword = newPassword.slice(0, insertPos) + newChar + newPassword.slice(insertPos);
              }
              
              setPassword(newPassword);
              analyzePassword();
            }}
          >
            Enhance Variety
          </button>
        </div>
      )}

      {/* Password Memorability Helper */}
      <div className="suggestion-card low">
        <div className="suggestion-icon">🧠</div>
        <div className="suggestion-content">
          <p className="suggestion-text">
            Make your password memorable but secure. Try a passphrase or 
            memorable pattern that's hard to guess.
          </p>
          <div className="suggestion-impact">
            <span className="impact-label">Impact:</span>
            <div className="impact-meter">
              <div className="impact-fill" style={{ width: '60%' }} />
            </div>
          </div>
        </div>
        <button 
          className="apply-suggestion-btn"
          onClick={() => {
            const words = ['correct','battery','purple','dragon','sunshine','horse','staple','hammer','castle','ocean'];
            const separator = '!@#$%^&*'[Math.floor(Math.random() * 8)];
            const num = Math.floor(Math.random() * 90) + 10;
            
            const newPassword = 
              words[Math.floor(Math.random() * words.length)] +
              separator +
              words[Math.floor(Math.random() * words.length)] +
              num;
            
            setPassword(newPassword);
            analyzePassword();
          }}
        >
          Generate Memorable
        </button>
      </div>

      {/* Password History Check */}
      <div className="suggestion-card medium">
        <div className="suggestion-icon">🕵️</div>
        <div className="suggestion-content">
          <p className="suggestion-text">
            Avoid reusing passwords. This password {Math.random() > 0.7 ? 
            'resembles' : 'does not resemble'} ones found in known breaches.
          </p>
          <div className="suggestion-impact">
            <span className="impact-label">Impact:</span>
            <div className="impact-meter">
              <div className="impact-fill" style={{ width: '75%' }} />
            </div>
          </div>
        </div>
        <button 
          className="apply-suggestion-btn"
          onClick={() => {
            const breachedPasswords = [
              'password123', '123456', 'qwerty', 'letmein', 'welcome'
            ];
            
            let newPassword = password;
            if (breachedPasswords.some(bp => password.toLowerCase().includes(bp))) {
              const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
              newPassword = Array.from({length: 12}, () => 
                chars.charAt(Math.floor(Math.random() * chars.length))
              ).join('');
            }
            
            setPassword(newPassword);
            analyzePassword();
          }}
        >
          Check Reuse
        </button>
      </div>

      {/* Short Length Suggestion */}
      {password.length < 12 && (
        <div className="suggestion-card critical">
          <div className="suggestion-icon">📏</div>
          <div className="suggestion-content">
            <p className="suggestion-text">
              Increase length to at least 12 characters. Current length: {password.length}.
              Longer passwords are exponentially harder to crack.
            </p>
            <div className="suggestion-impact">
              <span className="impact-label">Impact:</span>
              <div className="impact-meter">
                <div className="impact-fill" style={{ width: '95%' }} />
              </div>
            </div>
          </div>
          <button 
            className="apply-suggestion-btn"
            onClick={() => {
              const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
              let newPassword = password;
              while (newPassword.length < 12) {
                newPassword += chars.charAt(Math.floor(Math.random() * chars.length));
              }
              setPassword(newPassword);
              analyzePassword();
            }}
          >
            Extend Password
          </button>
        </div>
      )}

      {/* Missing Character Types */}
      {[/[A-Z]/.test(password), /[a-z]/.test(password), /[0-9]/.test(password), /[^A-Za-z0-9]/.test(password)]
        .filter(Boolean).length < 4 && (
        <div className="suggestion-card medium">
          <div className="suggestion-icon">🧰</div>
          <div className="suggestion-content">
            <p className="suggestion-text">
              Use more character types. Your password uses {
                [/[A-Z]/.test(password), /[a-z]/.test(password), 
                 /[0-9]/.test(password), /[^A-Za-z0-9]/.test(password)]
                .filter(Boolean).length
              } out of 4 possible types (uppercase, lowercase, numbers, symbols).
            </p>
            <div className="suggestion-impact">
              <span className="impact-label">Impact:</span>
              <div className="impact-meter">
                <div className="impact-fill" style={{ width: '80%' }} />
              </div>
            </div>
          </div>
          <button 
            className="apply-suggestion-btn"
            onClick={() => {
              let newPassword = password;
              if (!/[A-Z]/.test(password)) {
                newPassword += String.fromCharCode(Math.floor(Math.random() * 26) + 65);
              }
              if (!/[0-9]/.test(password)) {
                newPassword += Math.floor(Math.random() * 10);
              }
              if (!/[^A-Za-z0-9]/.test(password)) {
                newPassword += '!@#$%^&*'[Math.floor(Math.random() * 8)];
              }
              setPassword(newPassword);
              analyzePassword();
            }}
          >
            Add Missing Types
          </button>
        </div>
      )}
    </div>

    <div className="suggestions-actions">
      <button 
        className="vulnerability-analysis-btn"
        onClick={() => {
          const analysisData = {
            password,
            score: analysis.entropyScore / 100,
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
                         (/[^A-Za-z0-9]/.test(password) ? 1 : 0)
            )},
            entropy: analysis.entropyScore,
            vulnerabilities: analysis.vulnerabilities?.map(v => ({
              type: v.name,
              pattern: v.description,
              severity: v.severity
            })) || [],
            weaknesses: analysis.weaknesses?.map(w => ({
              title: w.title,
              description: w.description,
              severity: w.severity
            })) || [],
            crack_times: analysis.crack_times || {}
          };
          navigate('/vulnerability-analysis', { 
            state: { analysisData } 
          });
        }}
      >
        🛡️ View Detailed Vulnerability Analysis
      </button>
      
      <button 
        className="generate-strong-btn"
        onClick={() => {
          const words = ['correct','battery','purple','dragon','sunshine','horse','staple','hammer','castle','ocean'];
          const separator = '!@#$%^&*'[Math.floor(Math.random() * 8)];
          const num = Math.floor(Math.random() * 90) + 10;
          
          const newPassword = 
            words[Math.floor(Math.random() * words.length)].charAt(0).toUpperCase() +
            words[Math.floor(Math.random() * words.length)].slice(1) +
            separator +
            words[Math.floor(Math.random() * words.length)].charAt(0).toUpperCase() +
            words[Math.floor(Math.random() * words.length)].slice(1) +
            num;
          
          setPassword(newPassword);
          analyzePassword();
        }}
      >
      </button>
    </div>
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
                        <span className="method">{data.description}</span>
                      </div>
                      <div className="time-estimate">
                        <span className="time">{data.time_readable}</span>
                        <div className="severity-indicator">
                          <div className={`severity-dot ${
                            data.seconds >= 31536000 * 100 ? 'low' :
                            data.seconds >= 31536000 ? 'medium' :
                            data.seconds >= 86400 ? 'high' :
                            'critical'
                          }`}></div>
                        </div>
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
    </div>
  );
};

export default MainPage;