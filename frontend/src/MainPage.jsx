import { useState, useCallback, useEffect, useMemo } from 'react';
import './App.css';
import './MainPage.jsx';
import AttackSimulator from './AttackSimulator';
import logo from './images/BCS-745d30bf.png';
import { useNavigate } from 'react-router-dom';
import Chatbot from './Chatbot';
import Mainpage from './MainPage.css';

// Helper function to safely parse JSON
const safeJSONParse = (data, fallback = null) => {
  if (!data) return fallback;
  try {
    return JSON.parse(data);
  } catch (error) {
    console.error('Error parsing JSON:', error);
    return fallback;
  }
};

// Helper function to safely get localStorage item
const getLocalStorageItem = (key, fallback = null) => {
  try {
    const item = localStorage.getItem(key);
    return item ? safeJSONParse(item, fallback) : fallback;
  } catch (error) {
    console.error(`Error accessing localStorage for key ${key}:`, error);
    return fallback;
  }
};

// Helper function to determine strength class based on score
const getStrengthClass = (score) => {
  if (score >= 9) return 'strength-10';
  if (score >= 7) return 'strength-8';
  if (score >= 5) return 'strength-6';
  if (score >= 3) return 'strength-4';
  if (score > 0) return 'strength-2';
  return 'strength-0';
};

// Helper function to format crack time
const formatCrackTime = (seconds) => {
  if (seconds < 0.001) return 'instantly';
  if (seconds < 1) return 'less than a second';
  
  const timeUnits = [
    { unit: 'quintillion years', value: 31536000000000000000 },
    { unit: 'quadrillion years', value: 31536000000000000 },
    { unit: 'trillion years', value: 31536000000000 },
    { unit: 'billion years', value: 31536000000 },
    { unit: 'million years', value: 31536000 * 1000 },
    { unit: 'years', value: 31536000 },
    { unit: 'months', value: 2592000 },
    { unit: 'weeks', value: 604800 },
    { unit: 'days', value: 86400 },
    { unit: 'hours', value: 3600 },
    { unit: 'minutes', value: 60 },
    { unit: 'seconds', value: 1 }
  ];

  for (const { unit, value } of timeUnits) {
    if (seconds >= value) {
      const count = seconds / value;
      // For very large numbers, don't show decimal places
      if (count >= 1000) {
        return `${Math.floor(count).toLocaleString()} ${unit}`;
      }
      // For smaller numbers, show at most 1 decimal place
      return `${count < 10 ? count.toFixed(1) : Math.floor(count)} ${unit}`;
    }
  }
  
  return 'instantly';
};

// Helper function to get method description
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

// SHA-1 hash function
const sha1 = async (message) => {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

// Password breach check function
const checkPasswordBreach = async (pwd) => {
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
};

// Unified password analysis system
const analyzePassword = (password) => {
  if (!password) {
    return {
      strength: 0,
      strengthScore: 0,
      label: '',
      entropy: 0,
      entropyScore: 0,
      crackTimes: {},
      characterTypes: {
        uppercase: false,
        lowercase: false,
        numbers: false,
        symbols: false,
        total: 0
      },
      patterns: [],
      vulnerabilities: [],
      suggestions: []
    };
  }

  // 1. Basic character analysis
  const charTypes = {
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    numbers: /[0-9]/.test(password),
    symbols: /[^A-Za-z0-9]/.test(password)
  };
  
  const charCounts = {
    uppercase: (password.match(/[A-Z]/g) || []).length,
    lowercase: (password.match(/[a-z]/g) || []).length,
    numbers: (password.match(/[0-9]/g) || []).length,
    symbols: (password.match(/[^A-Za-z0-9]/g) || []).length
  };

  // 2. Calculate base entropy
  const charsetSize = (charTypes.uppercase ? 26 : 0) +
                     (charTypes.lowercase ? 26 : 0) +
                     (charTypes.numbers ? 10 : 0) +
                     (charTypes.symbols ? 32 : 0);
  
  let entropy = Math.log2(Math.pow(charsetSize || 1, password.length));

  // 3. Pattern detection and penalties
  const patterns = {
    repeatingChars: /(.)\1{2,}/g,
    sequentialLetters: /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|rst|stu|tuv|uvw|vwx|xyz)/i,
    sequentialNumbers: /(?:012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)/,
    keyboardPatterns: /(?:qwerty|asdfgh|zxcvbn|qazwsx|qweasd)/i,
    commonWords: /(?:password|admin|welcome|login|user|guest|123456|qwerty|letmein|dragon)/i,
    dates: /(?:19|20)\d{2}|(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])/
  };

  const foundPatterns = [];
  let patternPenalty = 0;

  Object.entries(patterns).forEach(([type, regex]) => {
    const matches = (password.match(regex) || []).length;
    if (matches > 0) {
      foundPatterns.push({
        type,
        matches,
        severity: type === 'commonWords' ? 'critical' :
                 type === 'keyboardPatterns' ? 'high' :
                 type === 'sequentialLetters' || type === 'sequentialNumbers' ? 'medium' : 'low'
      });

      switch (type) {
        case 'repeatingChars':
          patternPenalty += matches * 8;
          break;
        case 'sequentialLetters':
        case 'sequentialNumbers':
          patternPenalty += matches * 10;
          break;
        case 'keyboardPatterns':
          patternPenalty += matches * 12;
          break;
        case 'commonWords':
          patternPenalty += matches * 15;
          break;
        case 'dates':
          patternPenalty += matches * 10;
          break;
      }
    }
  });

  // 4. Calculate final entropy and strength score
  entropy = Math.max(0, entropy - patternPenalty);
  const normalizedEntropy = Math.min(100, Math.max(0, entropy * 2));
  
  // Calculate strength score (0-10)
  const strengthScore = Math.round(normalizedEntropy / 10);

  // 5. Calculate crack times
  const HARDWARE_SPEEDS = {
    online_throttled: 1000,
    online_unthrottled: 100_000,
    offline_slow_hash: 10_000_000,
    offline_fast_hash: 10_000_000_000,
    offline_gpu_farm: 1_000_000_000_000,
    quantum: 10_000_000_000_000
  };

  const crackTimes = {};
  Object.entries(HARDWARE_SPEEDS).forEach(([method, speed]) => {
    const combinations = Math.pow(2, entropy);
    const seconds = combinations / (2 * speed);
    crackTimes[method] = {
      seconds,
      time_readable: formatCrackTime(seconds),
      description: getMethodDescription(method)
    };
  });

  // Get fastest crack time for display
  const fastestCrack = Object.values(crackTimes)
    .reduce((fastest, current) => 
      current.seconds < fastest.seconds ? current : fastest
    );

  // 6. Generate strength label
  const label = strengthScore >= 8 ? 'Very Strong' :
                strengthScore >= 6 ? 'Strong' :
                strengthScore >= 4 ? 'Moderate' :
                strengthScore >= 2 ? 'Weak' : 'Very Weak';

  // Define attack types for vulnerability calculation
  const attackTypes = {
    DICTIONARY: {
      name: "Dictionary Attack",
      description: "Uses common words/phrases",
      indicator: (p) => /[a-z]{4,}/i.test(p) && !/[^a-z0-9]/i.test(p),
      severity: "high"
    },
    BRUTE_FORCE: {
      name: "Brute Force",
      description: "Tries all combinations",
      indicator: (p) => p.length < 8,
      severity: "medium"
    },
    PATTERN: {
      name: "Pattern",
      description: "Targets common sequences",
      indicator: (p) => /123|abc|qwerty|asdf|password/i.test(p),
      severity: "high"
    },
    REPEATING: {
      name: "Repeating",
      description: "Exploits repeated patterns",
      indicator: (p) => /(.)\1{2,}/.test(p),
      severity: "medium"
    },
    PERSONAL_INFO: {
      name: "Personal Info",
      description: "Uses names/birthdays",
      indicator: (p) => p.toLowerCase().includes('barclays'),
      severity: "high"
    },
    SPRAYING: {
      name: "Password Spraying",
      description: "Tries common passwords",
      indicator: (p) => ['password', '123456', 'welcome'].includes(p.toLowerCase()),
      severity: "critical"
    }
  };

  // Calculate vulnerabilities
  const vulnerabilities = Object.entries(attackTypes)
    .filter(([_, attack]) => attack.indicator(password))
    .map(([key, attack]) => ({
      id: key,
      name: attack.name,
      description: attack.description,
      severity: attack.severity
    }));

  // 8. Generate suggestions
  const suggestions = [];
  
  if (password.length < 12) {
    suggestions.push('Increase password length to at least 12 characters');
  }
  if (!charTypes.uppercase) {
    suggestions.push('Add uppercase letters');
  }
  if (!charTypes.lowercase) {
    suggestions.push('Add lowercase letters');
  }
  if (!charTypes.numbers) {
    suggestions.push('Add numbers');
  }
  if (!charTypes.symbols) {
    suggestions.push('Add special characters');
  }
  if (foundPatterns.length > 0) {
    suggestions.push('Avoid common patterns and sequences');
  }

  return {
    strength: strengthScore,
    strengthScore: normalizedEntropy,
    label,
    entropy: Math.round(entropy),
    entropyScore: Math.round(normalizedEntropy),
    crackTimes,
    crackTime: fastestCrack.time_readable,
    characterTypes: {
      ...charTypes,
      total: Object.values(charTypes).filter(Boolean).length
    },
    charCounts,
    patterns: foundPatterns,
    vulnerabilities,
    suggestions
  };
};

const MainPage = ({ password, setPassword, showPassword, setShowPassword }) => {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [strength, setStrength] = useState(0);
  const [strengthLabel, setStrengthLabel] = useState('');
  const [crackTime, setCrackTime] = useState('');
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [showMLAnalysis, setShowMLAnalysis] = useState(false);
  const [mlResults, setMLResults] = useState(null);
  const [isMLLoading, setIsMLLoading] = useState(false);
  const [showMLModal, setShowMLModal] = useState(false);
  const [showChatbot, setShowChatbot] = useState(false);
  const navigate = useNavigate();
  
  useEffect(() => {
    // Check if user has completed face authentication
    const checkAuthStatus = async () => {
      try {
        const token = localStorage.getItem('token');
        const facialId = localStorage.getItem('facialId');
        
        if (!token) {
          return; // Allow unauthenticated access to main page
        }
        
        // If no facialId exists but user is logged in, redirect to appropriate face auth
        if (token && !facialId) {
          try {
            const response = await fetch('/api/auth/check-face-auth', {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
            
            if (response.ok) {
              const data = await response.json();
              if (data.hasFaceAuth) {
                localStorage.setItem('facialId', data.facialId);
              } else {
                window.location.href = '/face-auth.html?action=enroll';
              }
            }
          } catch (error) {
            console.error('Error checking face auth status:', error);
          }
        }
      } catch (error) {
        console.error('Error in checkAuthStatus:', error);
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
      name: "Password Spraying",
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

  const handleGenerateSuggestions = () => {
    setShowChatbot(true);
  };

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
      sequential_chars: /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|rst|stu|tuv|uvw|vwx|wxy|xyz)/i,
      keyboard_patterns: /(?:qwerty|asdfgh|zxcvbn|qazwsx|qweasd)/i,
      common_words: /(?:password|admin|welcome|login|user|guest|123456|qwerty|letmein|dragon)/i,
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

  // Generate feedback based on analysis results
  const generateFeedback = useCallback((pwd, results, breachCount) => {
    return {
      main: results.label + (breachCount > 0 ? ` (Found in ${breachCount} breaches)` : ''),
      suggestions: results.suggestions,
      vulnerabilities: results.vulnerabilities
    };
  }, []);

  // Update the default analysis structure
  const defaultAnalysis = {
    entropyScore: 0,
    crackTime: 'instantly',
    breachCount: 0,
    weaknesses: [],
    vulnerabilities: [],
    suggestions: [],
    feedback: {
      main: '',
      suggestions: [],
      vulnerabilities: []
    }
  };

  // Update handleAnalyze to properly set all metrics
  const handleAnalyze = useCallback(async () => {
    if (!password.trim()) {
      setAnalysis(defaultAnalysis);
      return;
    }

    setIsLoading(true);
    try {
      const results = analyzePassword(password);
      const breachCount = await checkPasswordBreach(password);

      const analysisData = {
        ...defaultAnalysis,
        ...results,
        entropyScore: results.entropyScore,
        crackTime: results.crackTime,
        breachCount,
        isBreached: breachCount > 0,
        feedback: generateFeedback(password, results, breachCount)
      };

      setAnalysis(analysisData);
      setMLResults({
        score: results.strength,
        category: results.label,
        confidence: 0.95,
        details: {
          length: password.length,
          entropy: results.entropy,
          characterTypes: results.characterTypes
        },
        crackTimes: results.crackTimes
      });
    } catch (error) {
      console.error("Analysis error:", error);
      setAnalysis(defaultAnalysis);
    } finally {
      setIsLoading(false);
    }
  }, [password, generateFeedback]);

  const calculateStrengthFromCrackTime = (seconds) => {
    // Define thresholds for different strength levels
    const thresholds = [
      { score: 10, time: 31536000000000000 },    // 1 quadrillion years (Very Strong)
      { score: 9, time: 31536000000000 },        // 1 trillion years
      { score: 8, time: 31536000000 },           // 1 billion years
      { score: 7, time: 31536000 * 1000 },       // 1 million years
      { score: 6, time: 31536000 * 100 },        // 100 years
      { score: 5, time: 31536000 },              // 1 year
      { score: 4, time: 2592000 * 6 },           // 6 months
      { score: 3, time: 86400 * 30 },            // 30 days
      { score: 2, time: 3600 },                  // 1 hour
      { score: 1, time: 60 }                     // 1 minute
    ];

    for (const { score, time } of thresholds) {
      if (seconds >= time) {
        return score;
      }
    }
    return 0; // Less than 1 minute
  };

  const getStrengthCategory = (score) => {
    if (score >= 9) return "Very Strong";
    if (score >= 7) return "Strong";
    if (score >= 5) return "Moderate";
    if (score >= 3) return "Weak";
    return "Very Weak";
  };

  const handleMLAnalysis = async () => {
    if (!password) return;
    
    setIsMLLoading(true);
    setAnalysis(null);
    try {
      // Calculate metrics using the same function as main page
      const results = analyzePassword(password);
      
      // Get crack time in seconds
      const crackTimeInSeconds = (() => {
        const fastestCrack = Object.values(results.crackTimes || {})
          .reduce((fastest, current) => 
            current.seconds < fastest.seconds ? current : fastest
          );
        return fastestCrack.seconds;
      })();

      // Calculate strength score based on crack time
      const strengthScore = calculateStrengthFromCrackTime(crackTimeInSeconds);
      const category = getStrengthCategory(strengthScore);
      
      // Transform the data to match our UI expectations
      const processedData = {
        score: strengthScore,
        category: category,
        confidence: 0.95,
        details: {
          length: password.length,
          entropy: results.entropy,
          characterTypes: results.characterTypes
        },
        crackTimes: results.crackTimes
      };

      setMLResults(processedData);
      setShowMLModal(true);
    } catch (error) {
      console.error('ML Analysis error:', error);
      // Even on error, calculate and show local strength analysis
      const results = analyzePassword(password);
      const crackTimeInSeconds = (() => {
        const fastestCrack = Object.values(results.crackTimes || {})
          .reduce((fastest, current) => 
            current.seconds < fastest.seconds ? current : fastest
          );
        return fastestCrack.seconds;
      })();

      const strengthScore = calculateStrengthFromCrackTime(crackTimeInSeconds);
      const category = getStrengthCategory(strengthScore);

      setMLResults({
        error: true,
        message: error.message || 'Unable to analyze password. Please try again.',
        score: strengthScore,
        category: category,
        confidence: 0.95,
        details: {
          length: password.length,
          entropy: results.entropy,
          characterTypes: results.characterTypes
        },
        crackTimes: results.crackTimes
      });
      setShowMLModal(true);
    } finally {
      setIsMLLoading(false);
    }
  };

  // Update useEffect to handle real-time metrics updates
  useEffect(() => {
    if (password) {
      const results = analyzePassword(password);
      
      // Get crack time in seconds from the fastest attack method
      const fastestCrack = Object.values(results.crackTimes || {})
        .reduce((fastest, current) => 
          current.seconds < fastest.seconds ? current : fastest
        );
      
      // Calculate strength score based on crack time
      const strengthScore = calculateStrengthFromCrackTime(fastestCrack.seconds);
      const strengthCategory = getStrengthCategory(strengthScore);
      
      setStrength(strengthScore);
      setStrengthLabel(strengthCategory);
      setCrackTime(formatCrackTime(fastestCrack.seconds));
    } else {
      setStrength(0);
      setStrengthLabel('');
      setCrackTime('instantly');
    }
  }, [password]);

  // Helper function to determine strength class and width
  const getStrengthMeterProps = useCallback((score) => {
    if (score >= 9) return { class: 'very-strong', width: '100%' };
    if (score >= 7) return { class: 'strong', width: '80%' };
    if (score >= 5) return { class: 'moderate', width: '60%' };
    if (score >= 3) return { class: 'weak', width: '40%' };
    if (score > 0) return { class: 'very-weak', width: '20%' };
    return { class: 'empty', width: '0%' };
  }, []);

  const generateMemorable = (base) => {
    const adjectives = ["Secure", "Mighty", "Swift", "Brave", "Clever", "Noble", "Royal", "Wise", "Epic", "Grand"];
    const nouns = ["Dragon", "Knight", "Shield", "Castle", "Crown", "Guard", "Tower", "Sword", "Hero", "Legend"];
    const numbers = () => Math.floor(Math.random() * 900 + 100);
    const symbols = ["!", "@", "#", "$", "%", "&", "*"];
    
    const getRandomItem = (arr) => arr[Math.floor(Math.random() * arr.length)];
    
    const variations = [
      // Original pattern with base word
      `${base}${numbers()}${getRandomItem(symbols)}`,
      
      // Random adjective + base + numbers
      `${getRandomItem(adjectives)}${base}${numbers()}`,
      
      // Base + noun + symbol
      `${base}${getRandomItem(nouns)}${getRandomItem(symbols)}`,
      
      // Adjective + noun + numbers + symbol
      `${getRandomItem(adjectives)}${getRandomItem(nouns)}${numbers()}${getRandomItem(symbols)}`
    ];
    
    return variations;
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-content">
          <div className="logo-container">
            <img src={logo} alt="Barclays" className="app-logo" />
            <h1>Barclays</h1>
          </div>
          <div className="header-buttons">
            <button 
              className="login-btn"
              onClick={() => navigate('/login')}
            >
              Login
            </button>
            <button 
              className="signup-btn"
              onClick={() => navigate('/signup')}
            >
              Sign Up
            </button>
          </div>
        </div>
      </header>

      <div className="hero-section">
        <div className="tagline-container">
          <h2 className="main-tagline">Breach.AI</h2>
          <p className="sub-tagline">Fortify Before They Breach</p>
        </div>
        <h3 className="app-title">Password Strength Analyzer</h3>
      </div>

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
            aria-label={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? "Hide" : "Show"}
          </button>
        </div>

        {password && (
          <div className="strength-meter">
            <div 
              className={`strength-fill ${getStrengthMeterProps(strength).class}`}
              style={{ width: getStrengthMeterProps(strength).width }}
            />
          </div>
        )}

        {password && (
          <div className="strength-info">
            <div className="strength-label">Strength: {strengthLabel}</div>
            <div className="real-time-crack">Crack time: {crackTime}</div>
          </div>
        )}

        <div className="button-group">
          <button 
            onClick={handleAnalyze}
            disabled={isLoading}
            className={`analyze-btn ${isLoading ? 'loading' : ''}`}
          >
            Analyze Password
          </button>
          
          <div className="button-row">
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

            <button
              onClick={() => {
                // Pass the password with the correct structure
                const analysisData = {
                  password: password,
                  score: analysis?.strength || 0,
                  category: analysis?.label || 'Not Analyzed',
                  confidence: 0.95,
                  entropy: analysis?.entropy || 0,
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
                  patterns: analysis?.patterns || [],
                  crack_times: analysis?.crackTimes || {}
                };
                navigate('/vulnerability-analysis', { state: { analysisData } });
              }}
              className="vulnerability-btn"
              disabled={!password}
            >
              Vulnerability Analysis
            </button>
          </div>
        </div>

        {showSuggestions && analysis.suggestions && (
          <div className="suggestions-popup">
            <h4>Strong Password Suggestions:</h4>
            <ul>
              {analysis.suggestions.map((suggestion, index) => (
                <li key={index}>
                  <div className="suggestion-container">
                    <span className="suggestion-text">{suggestion}</span>
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

        {(analysis || password) && (
          <div className="results-container">
            <div className="metrics-section">
              <h3>Password Metrics</h3>
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-value">
                    {password ? Math.round(analysis?.entropyScore || analyzePassword(password).entropyScore || 0) : 0}/100
                  </div>
                  <div className="metric-label">Entropy</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value">
                    {password ? (analysis?.crackTime || analyzePassword(password).crackTime || 'instantly') : 'instantly'}
                  </div>
                  <div className="metric-label">Crack Time</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value">
                    {analysis?.breachCount || 0}
                  </div>
                  <div className="metric-label">Breaches</div>
                </div>
              </div>
            </div>

            <div className="attack-section">
              <h3>Attack Simulation</h3>
              <AttackSimulator 
                password={password}
                charsetSize={calculateCharsetSize(password)}
                entropyScore={password ? (analysis?.entropyScore || analyzePassword(password).entropyScore || 0) : 0}
              />
            </div>

            {password && (analysis?.weaknesses || []).length > 0 && (
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

            {/* Targeted Improvement Suggestions */}
            <div className="suggestions-section">
              <h3 className="suggestions-title">Targeted Improvement Suggestions</h3>
              <div className="suggestions-grid">
                {/* Enhanced Personal Info Detection */}
                {password && (
                  <div className="suggestion-card">
                    <div className="suggestion-header">
                      <div className="suggestion-icon">👤</div>
                      <h4 className="suggestion-title">
                        Avoid using personal information in your password.
                      </h4>
                    </div>
                    
                    <div className="impact-meter-container">
                      <span className="impact-label">Impact:</span>
                      <div className="impact-meter">
                        <div className="impact-fill" style={{ width: '75%' }} />
                      </div>
                    </div>

                    <div className="suggestion-actions">
                      <button 
                        className="primary-action"
                        onClick={() => {
                          let newPassword = password;
                          const names = password.match(/\b([A-Z][a-z]+)\b/g) || [];
                          names.forEach(name => {
                            newPassword = newPassword.replace(name, 
                              Math.random().toString(36).slice(2, 2 + name.length));
                          });
                          setPassword(newPassword);
                          handleAnalyze();
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                      >
                        Remove Personal Info
                      </button>
                      
                      <div className="alternative-section">
                        <span className="or-divider">or</span>
                        <p className="alternative-description">
                          Generate a memorable alternative that maintains security
                        </p>
                        <button 
                          className="secondary-action"
                          onClick={() => {
                            const variations = generateMemorable(password);
                            setPassword(variations[Math.floor(Math.random() * variations.length)]);
                            handleAnalyze();
                            window.scrollTo({ top: 0, behavior: 'smooth' });
                          }}
                        >
                          Generate Memorable Version
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Character Variety Suggestion */}
                {password && (
                  <div className="suggestion-card">
                    <div className="suggestion-header">
                      <div className="suggestion-icon">📊</div>
                      <h4 className="suggestion-title">
                        Increase character variety. Your password has {new Set(password).size} 
                        unique characters out of {password.length}.
                      </h4>
                    </div>

                    <div className="impact-meter-container">
                      <span className="impact-label">Impact:</span>
                      <div className="impact-meter">
                        <div className="impact-fill" style={{ width: '60%' }} />
                      </div>
                    </div>

                    <div className="suggestion-actions">
                      <button 
                        className="primary-action"
                        onClick={() => {
                          let newPassword = password;
                          const chars = '!@#$%^&*()_+-=[]{}|;:,.<>?~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                          for (let i = 0; i < 3; i++) {
                            const pos = Math.floor(Math.random() * newPassword.length);
                            const char = chars[Math.floor(Math.random() * chars.length)];
                            newPassword = newPassword.slice(0, pos) + char + newPassword.slice(pos + 1);
                          }
                          setPassword(newPassword);
                          handleAnalyze();
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                      >
                        Enhance Variety
                      </button>

                      <div className="alternative-section">
                        <span className="or-divider">or</span>
                        <p className="alternative-description">
                          Create a varied password that's easier to remember
                        </p>
                        <button 
                          className="secondary-action"
                          onClick={() => {
                            const variations = generateMemorable(password);
                            setPassword(variations[Math.floor(Math.random() * variations.length)]);
                            handleAnalyze();
                            window.scrollTo({ top: 0, behavior: 'smooth' });
                          }}
                        >
                          Generate Memorable Version
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Length Suggestion */}
                {password && password.length < 12 && (
                  <div className="suggestion-card">
                    <div className="suggestion-header">
                      <div className="suggestion-icon">📏</div>
                      <h4 className="suggestion-title">
                        Increase password length to at least 12 characters. Current length: {password.length}
                      </h4>
                    </div>

                    <div className="impact-meter-container">
                      <span className="impact-label">Impact:</span>
                      <div className="impact-meter">
                        <div className="impact-fill" style={{ width: '90%' }} />
                      </div>
                    </div>

                    <div className="suggestion-actions">
                      <button 
                        className="primary-action"
                        onClick={() => {
                          const chars = '!@#$%^&*()_+-=[]{}|;:,.<>?~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                          let newPassword = password;
                          while (newPassword.length < 12) {
                            newPassword += chars[Math.floor(Math.random() * chars.length)];
                          }
                          setPassword(newPassword);
                          handleAnalyze();
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                      >
                        Extend Length
                      </button>

                      <div className="alternative-section">
                        <span className="or-divider">or</span>
                        <p className="alternative-description">
                          Create a longer password that's structured for memorability
                        </p>
                        <button 
                          className="secondary-action"
                          onClick={() => {
                            const variations = generateMemorable(password);
                            setPassword(variations[Math.floor(Math.random() * variations.length)]);
                            handleAnalyze();
                            window.scrollTo({ top: 0, behavior: 'smooth' });
                          }}
                        >
                          Generate Memorable Version
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Pattern Detection */}
                {password && /(.)\1{2,}|123|abc|qwerty/.test(password) && (
                  <div className="suggestion-card">
                    <div className="suggestion-header">
                      <div className="suggestion-icon">🔄</div>
                      <h4 className="suggestion-title">
                        Avoid common patterns and repeated characters in your password.
                      </h4>
                    </div>

                    <div className="impact-meter-container">
                      <span className="impact-label">Impact:</span>
                      <div className="impact-meter">
                        <div className="impact-fill" style={{ width: '85%' }} />
                      </div>
                    </div>

                    <div className="suggestion-actions">
                      <button 
                        className="primary-action"
                        onClick={() => {
                          let newPassword = password;
                          const patterns = [/(.)\1{2,}/, /123/, /abc/, /qwerty/];
                          patterns.forEach(pattern => {
                            if (pattern.test(newPassword)) {
                              const chars = '!@#$%^&*()_+-=[]{}|;:,.<>?~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                              const match = newPassword.match(pattern)[0];
                              const replacement = Array(match.length).fill().map(() => 
                                chars[Math.floor(Math.random() * chars.length)]).join('');
                              newPassword = newPassword.replace(match, replacement);
                            }
                          });
                          setPassword(newPassword);
                          handleAnalyze();
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                      >
                        Break Patterns
                      </button>

                      <div className="alternative-section">
                        <span className="or-divider">or</span>
                        <p className="alternative-description">
                          Replace patterns with a memorable structured alternative
                        </p>
                        <button 
                          className="secondary-action"
                          onClick={() => {
                            const variations = generateMemorable(password);
                            setPassword(variations[Math.floor(Math.random() * variations.length)]);
                            handleAnalyze();
                            window.scrollTo({ top: 0, behavior: 'smooth' });
                          }}
                        >
                          Generate Memorable Version
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
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

              <div className="attack-scenarios">
                <h3>Attack Scenarios</h3>
                <div className="attack-grid">
                  <div className="attack-card">
                    <h4>Online Throttled Attack</h4>
                    <div className="attack-details">
                      <span className="speed">1,000 guesses/second</span>
                      <span className="time">{mlResults.crackTimes?.online_throttled?.time_readable || 'N/A'}</span>
                    </div>
                    <div className="description">Rate-limited online attack simulation</div>
                  </div>

                  <div className="attack-card">
                    <h4>Online No Throttling</h4>
                    <div className="attack-details">
                      <span className="speed">100,000 guesses/second</span>
                      <span className="time">{mlResults.crackTimes?.online_unthrottled?.time_readable || 'N/A'}</span>
                    </div>
                    <div className="description">Unrestricted online attack simulation</div>
                  </div>

                  <div className="attack-card">
                    <h4>Offline Slow Hash</h4>
                    <div className="attack-details">
                      <span className="speed">10M guesses/second</span>
                      <span className="time">{mlResults.crackTimes?.offline_slow_hash?.time_readable || 'N/A'}</span>
                    </div>
                    <div className="description">Slow hash function (bcrypt, PBKDF2)</div>
                  </div>

                  <div className="attack-card">
                    <h4>Offline Fast Hash</h4>
                    <div className="attack-details">
                      <span className="speed">10B guesses/second</span>
                      <span className="time">{mlResults.crackTimes?.offline_fast_hash?.time_readable || 'N/A'}</span>
                    </div>
                    <div className="description">Fast hash function (SHA-1, MD5)</div>
                  </div>

                  <div className="attack-card">
                    <h4>Massive GPU Farm</h4>
                    <div className="attack-details">
                      <span className="speed">1T guesses/second</span>
                      <span className="time">{mlResults.crackTimes?.offline_gpu_farm?.time_readable || 'N/A'}</span>
                    </div>
                    <div className="description">Distributed GPU-based attack</div>
                  </div>

                  <div className="attack-card">
                    <h4>Quantum Computer</h4>
                    <div className="attack-details">
                      <span className="speed">10T guesses/second</span>
                      <span className="time">{mlResults.crackTimes?.quantum?.time_readable || 'N/A'}</span>
                    </div>
                    <div className="description">Theoretical quantum computer attack</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <style jsx>{`
            .attack-scenarios {
              margin-top: 2rem;
              padding-top: 2rem;
              border-top: 1px solid rgba(255, 255, 255, 0.1);
            }

            .attack-grid {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
              gap: 1rem;
              margin-top: 1rem;
            }

            .attack-card {
              background: rgba(0, 0, 0, 0.2);
              border-radius: 8px;
              padding: 1rem;
              border: 1px solid rgba(255, 255, 255, 0.1);
            }

            .attack-card h4 {
              color: #00ffff;
              margin: 0 0 0.5rem 0;
              font-size: 1rem;
            }

            .attack-details {
              display: flex;
              justify-content: space-between;
              align-items: center;
              margin: 0.5rem 0;
            }

            .speed {
              color: rgba(255, 255, 255, 0.7);
              font-size: 0.875rem;
            }

            .time {
              color: #00ffff;
              font-weight: bold;
            }

            .description {
              color: rgba(255, 255, 255, 0.5);
              font-size: 0.875rem;
              margin-top: 0.5rem;
            }

            .ml-modal {
              max-width: 900px;
              width: 90%;
              max-height: 90vh;
              overflow-y: auto;
              background: #1a1f2e;
              border-radius: 12px;
              padding: 2rem;
              position: relative;
              color: white;
            }

            .ml-modal h2 {
              color: #00ffff;
              margin-bottom: 2rem;
            }

            .ml-modal h3 {
              color: #00ffff;
              margin: 1.5rem 0 1rem;
            }

            .feature-grid {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
              gap: 1rem;
              margin: 1rem 0;
            }

            .feature {
              background: rgba(0, 0, 0, 0.2);
              padding: 1rem;
              border-radius: 8px;
              display: flex;
              justify-content: space-between;
              align-items: center;
            }

            @media (max-width: 768px) {
              .attack-grid {
                grid-template-columns: 1fr;
              }

              .ml-modal {
                padding: 1rem;
                width: 95%;
              }
            }
          `}</style>
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