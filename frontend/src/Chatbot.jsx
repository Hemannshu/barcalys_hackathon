import React, { useState, useRef, useEffect } from 'react';
import './Chatbot.css';

const Chatbot = ({ onPasswordSelect }) => {
  const [messages, setMessages] = useState([
    { 
      role: 'assistant', 
      content: 'Welcome to your Password Security Assistant! I can help you with:\n\n' +
               '🔒 Password Generation & Analysis\n' +
               '📊 Security Score & Recommendations\n' +
               '📱 Multi-factor Authentication Setup\n' +
               '📝 Password History & Management\n' +
               '🎮 Interactive Learning & Quizzes\n' +
               '🚨 Security Alerts & Updates\n' +
               '🔍 Password Health Check\n' +
               '📋 Custom Password Policies\n\n' +
               'How can I assist you today?'
    }
  ]);
  const [input, setInput] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [activeFeature, setActiveFeature] = useState(null);
  const [featureState, setFeatureState] = useState({});
  const [passwordPurpose, setPasswordPurpose] = useState(null);
  const [userInfo, setUserInfo] = useState({});
  const [currentInfoField, setCurrentInfoField] = useState(null);
  const [securityScore, setSecurityScore] = useState(0);
  const [passwordHistory, setPasswordHistory] = useState([]);
  const [quizProgress, setQuizProgress] = useState(0);
  const [mfaStatus, setMfaStatus] = useState({});
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const features = {
    password_generation: {
      name: "Password Generation",
      description: "Generate secure passwords based on your needs",
      icon: "🔒",
      states: ['select_type', 'specify_requirements', 'generate', 'review']
    },
    security_score: {
      name: "Security Score",
      description: "Get your security score and recommendations",
      icon: "📊",
      states: ['analyze', 'calculate', 'recommend', 'improve']
    },
    mfa_setup: {
      name: "MFA Setup",
      description: "Set up multi-factor authentication",
      icon: "📱",
      states: ['select_method', 'setup', 'verify', 'backup']
    },
    password_history: {
      name: "Password History",
      description: "Manage your password history",
      icon: "📝",
      states: ['view', 'add', 'update', 'delete']
    },
    learning_quiz: {
      name: "Security Quiz",
      description: "Test your security knowledge",
      icon: "🎮",
      states: ['select_level', 'question', 'answer', 'result']
    },
    security_alerts: {
      name: "Security Alerts",
      description: "Get security updates and alerts",
      icon: "🚨",
      states: ['check', 'review', 'action', 'update']
    },
    health_check: {
      name: "Health Check",
      description: "Check your password health",
      icon: "🔍",
      states: ['analyze', 'identify', 'recommend', 'improve']
    },
    custom_policies: {
      name: "Custom Policies",
      description: "Set up custom password policies",
      icon: "📋",
      states: ['define', 'configure', 'test', 'apply']
    }
  };

  const handleFeatureSelect = (feature) => {
    setActiveFeature(feature);
    setFeatureState({ current: features[feature].states[0] });
    let response = '';
    
    switch(feature) {
      case 'password_generation':
        response = "Let's generate a secure password! Please select the type of account:\n\n" +
                  "1. Banking/Financial\n" +
                  "2. Social Media\n" +
                  "3. Email\n" +
                  "4. Work/Professional\n" +
                  "5. Other";
        break;
      case 'security_score':
        response = "Let's calculate your security score! First, I'll analyze your current security practices.\n\n" +
                  "Do you use different passwords for different accounts? (yes/no)";
        break;
      case 'mfa_setup':
        response = "Let's set up multi-factor authentication! Choose your preferred method:\n\n" +
                  "1. Authenticator App (Google/Microsoft)\n" +
                  "2. SMS Verification\n" +
                  "3. Security Key (YubiKey)\n" +
                  "4. Backup Codes";
        break;
      case 'password_history':
        response = "Password Management Dashboard:\n\n" +
                  "1. View all saved passwords\n" +
                  "2. Add new password\n" +
                  "3. Update existing password\n" +
                  "4. Delete password\n" +
                  "5. Export password list";
        break;
      case 'learning_quiz':
        response = "Let's test your security knowledge! Choose your level:\n\n" +
                  "1. Beginner (Basic concepts)\n" +
                  "2. Intermediate (Common practices)\n" +
                  "3. Advanced (Technical details)\n" +
                  "4. Expert (Security protocols)";
        break;
      case 'security_alerts':
        response = "Security Alerts Dashboard:\n\n" +
                  "1. Check for recent breaches\n" +
                  "2. Review security updates\n" +
                  "3. Get password recommendations\n" +
                  "4. Check MFA status\n" +
                  "5. View security timeline";
        break;
      case 'health_check':
        response = "Let's check your password health! First, enter a password to analyze:";
        break;
      case 'custom_policies':
        response = "Custom Password Policies:\n\n" +
                  "1. Set minimum length (8-32 characters)\n" +
                  "2. Configure character requirements\n" +
                  "3. Set password expiration\n" +
                  "4. Add special requirements\n" +
                  "5. Test policy strength";
        break;
    }

    setMessages(prev => [...prev, { role: 'assistant', content: response }]);
  };

  const handleFeatureInteraction = async (feature, state, userInput) => {
    let response = { role: 'assistant', content: '' };
    
    switch(feature) {
      case 'password_generation':
        if (state === 'select_type') {
          const accountType = userInput.toLowerCase();
          const length = accountType.includes('bank') ? 16 : 12;
          const specialChars = accountType.includes('bank') ? '!@#$%^&*()_+-=[]{}|;:,.<>?' : '!@#$%^&*';
          
          const password = generatePassword(length, specialChars);
          const memorizationTips = generateMemorizationTips(password.password);
          
          response = {
            role: 'assistant',
            content: `Here's a secure password for your ${accountType} account:`,
            suggestion: password,
            memorization: {
              tips: memorizationTips,
              message: "Let me help you remember this password using these memory techniques:"
            }
          };
          setFeatureState({ current: 'review' });
        }
        break;

      case 'security_score':
        if (state === 'analyze') {
          const usesDifferentPasswords = userInput.toLowerCase() === 'yes';
          const score = usesDifferentPasswords ? 30 : 0;
          setSecurityScore(score);
          response = {
            role: 'assistant',
            content: `Current score: ${score}/100\n\nNext question: Do you use multi-factor authentication? (yes/no)`,
            recommendations: usesDifferentPasswords ? [] : ["Use different passwords for each account"]
          };
          setFeatureState({ current: 'calculate' });
        }
        break;

      case 'mfa_setup':
        if (state === 'select_method') {
          const method = userInput.toLowerCase();
          let steps = [];
          if (method.includes('authenticator')) {
            steps = [
              "Download Google Authenticator or Microsoft Authenticator",
              "Open the app and scan the QR code",
              "Enter the 6-digit code to verify",
              "Save your backup codes in a secure location"
            ];
          } else if (method.includes('sms')) {
            steps = [
              "Enter your phone number",
              "Verify with the code sent via SMS",
              "Set up backup verification methods",
              "Save your backup codes"
            ];
          }
          response = {
            role: 'assistant',
            content: `Here's how to set up ${method}:`,
            steps: steps
          };
          setFeatureState({ current: 'setup' });
        }
        break;

      case 'learning_quiz':
        if (state === 'select_level') {
          const questions = {
            beginner: [
              "What is the minimum recommended password length?",
              "Should you use the same password for multiple accounts?",
              "What is multi-factor authentication?"
            ],
            intermediate: [
              "What makes a strong password?",
              "How often should you change your passwords?",
              "What are common password attack methods?"
            ]
          };
          const level = userInput.toLowerCase();
          response = {
            role: 'assistant',
            content: `Question 1: ${questions[level][0]}\n\nType your answer:`,
            quiz: { level, currentQuestion: 0, questions: questions[level] }
          };
          setFeatureState({ current: 'question' });
        }
        break;

      case 'health_check':
        if (state === 'analyze') {
          const strength = calculateStrength(userInput);
          const patterns = analyzePasswordPatterns(userInput);
          response = {
            role: 'assistant',
            content: "Password Analysis Results:",
            analysis: {
              strength,
              patterns,
              recommendations: generateRecommendations(patterns)
            }
          };
          setFeatureState({ current: 'recommend' });
        }
        break;
    }

    setMessages(prev => [...prev, response]);
  };

  const generatePassword = (length, specialChars) => {
    // Word lists for memorable password generation
    const adjectives = [
      'happy', 'brave', 'clever', 'quick', 'strong', 'wise', 'calm', 'bold',
      'smart', 'sharp', 'bright', 'clear', 'cool', 'deep', 'fast', 'free'
    ];
    
    const nouns = [
      'apple', 'beach', 'cloud', 'dream', 'earth', 'field', 'grass', 'house',
      'light', 'moon', 'ocean', 'peace', 'river', 'stone', 'tree', 'water'
    ];
    
    const verbs = [
      'jump', 'run', 'walk', 'swim', 'fly', 'sing', 'dance', 'play',
      'read', 'write', 'draw', 'paint', 'build', 'create', 'learn', 'teach'
    ];
    
    // Generate a memorable pattern
    const getRandomWord = (list) => list[Math.floor(Math.random() * list.length)];
    const getRandomNumber = () => Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    const getRandomSpecial = () => specialChars[Math.floor(Math.random() * specialChars.length)];
    
    // Create a memorable pattern: Adjective + Number + Verb + Special + Noun
    const adjective = getRandomWord(adjectives);
    const number = getRandomNumber();
    const verb = getRandomWord(verbs);
    const special = getRandomSpecial();
    const noun = getRandomWord(nouns);
    
    // Capitalize first letters for better memorability
    const capitalize = (word) => word.charAt(0).toUpperCase() + word.slice(1);
    
    const password = `${capitalize(adjective)}${number}${capitalize(verb)}${special}${capitalize(noun)}`;
    
    // Generate a memorable phrase to help remember the password
    const memorablePhrase = `Think of a ${adjective} ${noun} that ${verb}s with number ${number}`;
    
    return {
      password,
      strength: calculateStrength(password),
      explanation: "Generated using a memorable pattern of words and numbers",
      memorablePhrase
    };
  };

  const calculateStrength = (password) => {
    let score = 0;
    if (password.length >= 12) score += 30;
    if (/[A-Z]/.test(password)) score += 20;
    if (/[a-z]/.test(password)) score += 20;
    if (/[0-9]/.test(password)) score += 20;
    if (/[^A-Za-z0-9]/.test(password)) score += 20;
    if (!/(.)\1{2,}/.test(password)) score += 10;
    if (!/123|abc|qwerty/.test(password.toLowerCase())) score += 10;
    return Math.min(100, score);
  };

  const analyzePasswordPatterns = (password) => {
    return {
      length: password.length,
      hasUpper: /[A-Z]/.test(password),
      hasLower: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecial: /[^A-Za-z0-9]/.test(password),
      repeating: /(.)\1{2,}/.test(password),
      sequential: /123|abc|qwerty/.test(password.toLowerCase()),
      commonWords: /password|admin|welcome/.test(password.toLowerCase())
    };
  };

  const generateRecommendations = (patterns) => {
    const recommendations = [];
    if (patterns.length < 12) recommendations.push("Use a longer password (minimum 12 characters)");
    if (!patterns.hasUpper) recommendations.push("Include uppercase letters");
    if (!patterns.hasLower) recommendations.push("Include lowercase letters");
    if (!patterns.hasNumber) recommendations.push("Include numbers");
    if (!patterns.hasSpecial) recommendations.push("Include special characters");
    if (patterns.repeating) recommendations.push("Avoid repeating characters");
    if (patterns.sequential) recommendations.push("Avoid sequential patterns");
    if (patterns.commonWords) recommendations.push("Avoid common words");
    return recommendations;
  };

  const generateMemorizationTips = (password) => {
    // Split password into memorable chunks
    const chunks = password.match(/.{1,4}/g) || [];
    
    // Analyze patterns in the password
    const patterns = {
      words: password.match(/[A-Z][a-z]+/g) || [],
      numbers: password.match(/\d+/g) || [],
      specialChars: password.match(/[^A-Za-z0-9]/g) || []
    };

    // Create mnemonic phrases
    const mnemonics = chunks.map((chunk, index) => {
      if (chunk.match(/^\d+$/)) {
        // Convert numbers to memorable phrases
        const numberPhrases = {
          '000': 'triple zero',
          '111': 'triple one',
          '222': 'triple two',
          // ... add more number phrases
        };
        return numberPhrases[chunk] || `the number ${chunk}`;
      } else if (chunk.match(/^[A-Z][a-z]+$/)) {
        // Create memorable associations for words
        const wordAssociations = {
          'Happy': 'a happy face',
          'Apple': 'a red apple',
          'Beach': 'a sunny beach',
          // ... add more word associations
        };
        return wordAssociations[chunk] || `the word "${chunk}"`;
      } else if (chunk.match(/[^A-Za-z0-9]/)) {
        // Create visual associations for special characters
        const specialCharAssociations = {
          '!': 'an exclamation mark',
          '@': 'the at symbol',
          '#': 'a hash tag',
          '$': 'a dollar sign',
          '%': 'a percent sign',
          '^': 'a caret',
          '&': 'an ampersand',
          '*': 'a star'
        };
        return specialCharAssociations[chunk] || `the symbol "${chunk}"`;
      }
      return `"${chunk}"`;
    });

    // Generate memory techniques
    const techniques = [
      "Word Association: Link each word to a familiar image",
      "Number Patterns: Remember numbers as a sequence or date",
      "Visual Story: Create a mental picture with all elements",
      "Rhythm Method: Create a rhythm or song with the parts",
      "Personal Connection: Relate words to your experiences"
    ];

    return {
      chunks,
      patterns,
      mnemonics,
      techniques
    };
  };

  const handlePasswordPurposeSelect = (purpose) => {
    setPasswordPurpose(purpose);
    let requiredFields = [];
    
    if (purpose === 'work') {
      requiredFields = ['role', 'employeeId', 'department'];
    } else if (purpose === 'personal') {
      requiredFields = ['accountType', 'username', 'securityQuestion'];
    }
    
    setUserInfo({ purpose });
    setCurrentInfoField(requiredFields[0]);
    
    const fieldPrompts = {
      role: 'What is your work role?',
      employeeId: 'What is your employee ID?',
      department: 'Which department do you work in?',
      accountType: 'What type of account is this for? (e.g., email, social media, banking)',
      username: 'What username will you use with this password?',
      securityQuestion: 'What security question will you use with this account?'
    };
    
    setMessages(prev => [...prev, { 
      role: 'assistant', 
      content: `You've selected ${purpose === 'work' ? 'work' : 'personal'} password generation.\n\n${fieldPrompts[requiredFields[0]]}` 
    }]);
  };

  const handleUserInfoInput = (field, value) => {
    setUserInfo(prev => ({ ...prev, [field]: value }));
    
    const requiredFields = passwordPurpose === 'work' 
      ? ['role', 'employeeId', 'department']
      : ['accountType', 'username', 'securityQuestion'];
    
    const currentIndex = requiredFields.indexOf(field);
    const nextField = requiredFields[currentIndex + 1];
    
    if (nextField) {
      setCurrentInfoField(nextField);
      const fieldPrompts = {
        role: 'What is your work role?',
        employeeId: 'What is your employee ID?',
        department: 'Which department do you work in?',
        accountType: 'What type of account is this for? (e.g., email, social media, banking)',
        username: 'What username will you use with this password?',
        securityQuestion: 'What security question will you use with this account?'
      };
      
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: fieldPrompts[nextField] 
      }]);
    } else {
      // All information collected, proceed with password generation
      setCurrentInfoField(null);
      generatePasswordWithContext();
    }
  };

  const generatePasswordWithContext = () => {
    const context = passwordPurpose === 'work' 
      ? `Work password for ${userInfo.role} in ${userInfo.department}`
      : `Personal password for ${userInfo.accountType} account`;
    
    const password = generatePassword(16, '!@#$%^&*()_+-=[]{}|;:,.<>?');
    const memorizationTips = generateMemorizationTips(password.password);
    
    setMessages(prev => [...prev, {
      role: 'assistant',
      content: `Based on your ${passwordPurpose} context, here's a secure password:`,
      suggestion: {
        ...password,
        context
      },
      memorization: {
        tips: memorizationTips,
        message: "Let me help you remember this password using these memory techniques:"
      }
    }]);
  };

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');

    setIsGenerating(true);

    try {
      if (currentInfoField) {
        handleUserInfoInput(currentInfoField, input);
      } else if (activeFeature && featureState.current) {
        await handleFeatureInteraction(activeFeature, featureState.current, input);
      } else {
        setMessages(prev => [...prev, { 
          role: 'assistant', 
          content: "Please select a feature from the menu to get started." 
        }]);
      }
    } catch (error) {
      console.error('Error:', error);
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: "Sorry, I encountered an error. Please try again." 
      }]);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="chatbot-container">
      <div className="chatbot-messages">
        {messages.map((message, index) => (
          <div key={index} className={`message ${message.role}`}>
            <div className="message-content">
              {message.content}
              {message.suggestion && (
                <div className="suggestion-card">
                  <div className="password-display">{message.suggestion.password}</div>
                  <div className="strength-meter">
                    <div 
                      className="strength-fill" 
                      style={{ width: `${message.suggestion.strength}%` }}
                    />
                  </div>
                  <div className="explanation">{message.suggestion.explanation}</div>
                  {message.memorization && (
                    <div className="memorization-tips">
                      <h3>{message.memorization.message}</h3>
                      <div className="memory-techniques">
                        {message.memorization.tips.techniques.map((tech, i) => (
                          <div key={i} className="technique-item">
                            <span className="technique-icon">💡</span>
                            {tech}
                          </div>
                        ))}
                      </div>
                      <div className="password-chunks">
                        <h4>Break it down:</h4>
                        {message.memorization.tips.chunks.map((chunk, i) => (
                          <div key={i} className="chunk-item">
                            <span className="chunk">{chunk}</span>
                            <span className="mnemonic">{message.memorization.tips.mnemonics[i]}</span>
                          </div>
                        ))}
                      </div>
                      <div className="pattern-analysis">
                        <h4>Pattern Analysis:</h4>
                        {Object.entries(message.memorization.tips.patterns).map(([key, value]) => (
                          <div key={key} className="pattern-item">
                            <span className="pattern-label">{key}:</span>
                            <span className="pattern-value">{value.join(', ')}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <button 
                    className="use-password-btn"
                    onClick={() => onPasswordSelect(message.suggestion.password)}
                  >
                    Use This Password
                  </button>
                </div>
              )}
              {message.recommendations && (
                <div className="recommendations">
                  {message.recommendations.map((rec, i) => (
                    <div key={i} className="recommendation-item">
                      <span className="recommendation-icon">📌</span>
                      {rec}
                    </div>
                  ))}
                </div>
              )}
              {message.steps && (
                <div className="steps">
                  {message.steps.map((step, i) => (
                    <div key={i} className="step-item">
                      <span className="step-number">{i + 1}</span>
                      {step}
                    </div>
                  ))}
                </div>
              )}
              {message.analysis && (
                <div className="analysis">
                  <div className="strength-meter">
                    <div 
                      className="strength-fill" 
                      style={{ width: `${message.analysis.strength}%` }}
                    />
                  </div>
                  <div className="patterns">
                    {Object.entries(message.analysis.patterns).map(([key, value]) => (
                      <div key={key} className="pattern-item">
                        <span className="pattern-label">{key}:</span>
                        <span className={`pattern-value ${value ? 'good' : 'bad'}`}>
                          {value ? '✓' : '✗'}
                        </span>
                      </div>
                    ))}
                  </div>
                  <div className="recommendations">
                    {message.analysis.recommendations.map((rec, i) => (
                      <div key={i} className="recommendation-item">
                        <span className="recommendation-icon">📌</span>
                        {rec}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
        {isGenerating && (
          <div className="message assistant">
            <div className="message-content">
              <div className="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <div className="features-grid">
        {Object.entries(features).map(([key, feature]) => (
          <button 
            key={key}
            className={`feature-btn ${activeFeature === key ? 'active' : ''}`}
            onClick={() => handleFeatureSelect(key)}
          >
            <span className="feature-icon">{feature.icon}</span>
            <span className="feature-name">{feature.name}</span>
            <span className="feature-description">{feature.description}</span>
          </button>
        ))}
      </div>

      <div className="chatbot-input-container">
        {!passwordPurpose && !activeFeature && (
          <div className="purpose-selection">
            <h3>Select Password Purpose:</h3>
            <div className="purpose-buttons">
              <button 
                className="purpose-btn work"
                onClick={() => handlePasswordPurposeSelect('work')}
              >
                <span className="purpose-icon">💼</span>
                Work Password
              </button>
              <button 
                className="purpose-btn personal"
                onClick={() => handlePasswordPurposeSelect('personal')}
              >
                <span className="purpose-icon">👤</span>
                Personal Password
              </button>
            </div>
          </div>
        )}
        <div className="chatbot-input">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={activeFeature ? "Type your response..." : "Select a feature to get started..."}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
          />
          <button onClick={handleSend} disabled={isGenerating}>
            Send
          </button>
        </div>
      </div>
    </div>
  );
};

export default Chatbot; 