import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { collection, addDoc, query, where, getDocs } from 'firebase/firestore';
import { onAuthStateChanged } from 'firebase/auth';
import { pwnedPassword } from 'hibp';
import { db, auth } from './firebase';
import './PasswordHealthDashboard.css';

const PasswordHealthDashboard = () => {
  const [passwords, setPasswords] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddPassword, setShowAddPassword] = useState(false);
  const [newPassword, setNewPassword] = useState({
    service: '',
    username: '',
    password: '',
    notes: ''
  });
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  // Debugging logs
  useEffect(() => {
    console.log('Current user:', user);
    console.log('Passwords state:', passwords);
  }, [user, passwords]);

  // Check auth state
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      console.log('Auth state changed:', currentUser);
      if (currentUser) {
        setUser(currentUser);
        fetchPasswords(currentUser.uid);
      } else {
        console.log('No user, redirecting to login');
        navigate('/login');
      }
    });
    return () => unsubscribe();
  }, [navigate]);

  // Fetch passwords from Firestore with improved error handling
  const fetchPasswords = async (userId) => {
    setIsLoading(true);
    setError(null);
    
    try {
      if (!userId) {
        throw new Error('No user ID available');
      }

      const q = query(collection(db, 'passwords'), where('userId', '==', userId));
      const querySnapshot = await getDocs(q);
      
      if (querySnapshot.empty) {
        setPasswords([]);
        return;
      }
      
      const passwordsData = [];
      querySnapshot.forEach((doc) => {
        if (doc.exists()) {
          passwordsData.push({ id: doc.id, ...doc.data() });
        }
      });
      
      // Analyze each password
      const analyzedPasswords = await Promise.all(
        passwordsData.map(async (pwd) => {
          try {
            const analysis = await analyzePassword(pwd.password);
            const isPwned = await checkPwned(pwd.password);
            
            return {
              ...pwd,
              analysis,
              isPwned,
              daysToChange: calculateDaysToChange(analysis.strength_score)
            };
          } catch (err) {
            console.error(`Error analyzing password for ${pwd.service}:`, err);
            return {
              ...pwd,
              analysis: {
                strength_score: 0,
                strength_category: 'Error',
                suggestions: ['Unable to analyze password'],
                patterns: [],
                crack_times: {}
              },
              isPwned: false,
              daysToChange: 7
            };
          }
        })
      );
      
      setPasswords(analyzedPasswords);
    } catch (err) {
      console.error('Error fetching passwords:', err);
      setError('Failed to load passwords. Please try again or check your connection.');
    } finally {
      setIsLoading(false);
    }
  };

  // Password strength analysis
  const analyzePassword = async (password) => {
    try {
      if (!password) {
        return {
          strength_score: 0,
          strength_category: 'Empty',
          suggestions: ['Password cannot be empty'],
          patterns: [],
          crack_times: {}
        };
      }

      const score = calculatePasswordScore(password);
      const category = getStrengthCategory(score);
      const suggestions = getPasswordSuggestions(password);
      const patterns = detectPasswordPatterns(password);
      const crackTimes = estimateCrackTimes(password);
      
      return {
        strength_score: score,
        strength_category: category,
        suggestions,
        patterns,
        crack_times: crackTimes,
        details: {
          length: password.length,
          has_upper: /[A-Z]/.test(password),
          has_lower: /[a-z]/.test(password),
          has_number: /[0-9]/.test(password),
          has_special: /[^A-Za-z0-9]/.test(password),
          char_types: (
            (/[A-Z]/.test(password) ? 1 : 0) +
            (/[a-z]/.test(password) ? 1 : 0) +
            (/[0-9]/.test(password) ? 1 : 0) +
            (/[^A-Za-z0-9]/.test(password) ? 1 : 0)
          )
        }
      };
    } catch (err) {
      console.error('Error analyzing password:', err);
      return {
        strength_score: 0,
        strength_category: 'Error',
        suggestions: ['Unable to analyze password'],
        patterns: [],
        crack_times: {}
      };
    }
  };

  // Check if password has been pwned
  const checkPwned = async (password) => {
    try {
      if (!password) return false;
      const count = await pwnedPassword(password);
      return count > 0;
    } catch (err) {
      console.error('Error checking pwned status:', err);
      return false;
    }
  };

  // Calculate days until password should be changed
  const calculateDaysToChange = (score) => {
    if (score >= 80) return 90;
    if (score >= 60) return 60;
    if (score >= 40) return 30;
    return 7;
  };

  // Simplified password scoring
  const calculatePasswordScore = (password) => {
    if (!password) return 0;
    
    let score = 0;
    // Length contributes up to 50 points
    score += Math.min(50, password.length * 5);
    
    // Character variety contributes up to 30 points
    const charTypes = (
      (/[A-Z]/.test(password) ? 1 : 0) +
      (/[a-z]/.test(password) ? 1 : 0) +
      (/[0-9]/.test(password) ? 1 : 0) +
      (/[^A-Za-z0-9]/.test(password) ? 1 : 0)
    );
    score += charTypes * 7.5;
    
    // Penalties for common patterns
    if (/(.)\1{2,}/.test(password)) score -= 20;
    if (/123|abc|qwerty/.test(password)) score -= 30;
    if (password.length < 8) score -= 40;
    
    return Math.max(0, Math.min(100, score));
  };

  const getStrengthCategory = (score) => {
    if (score >= 80) return 'Very Strong';
    if (score >= 60) return 'Strong';
    if (score >= 40) return 'Moderate';
    if (score >= 20) return 'Weak';
    return 'Very Weak';
  };

  const getPasswordSuggestions = (password) => {
    const suggestions = [];
    
    if (!password) {
      return ['Password cannot be empty'];
    }
    
    if (password.length < 12) {
      suggestions.push('Use a longer password (at least 12 characters)');
    }
    
    if (!/[A-Z]/.test(password)) {
      suggestions.push('Add uppercase letters');
    }
    
    if (!/[0-9]/.test(password)) {
      suggestions.push('Add numbers');
    }
    
    if (!/[^A-Za-z0-9]/.test(password)) {
      suggestions.push('Add special characters');
    }
    
    if (/(.)\1{2,}/.test(password)) {
      suggestions.push('Avoid repeated characters');
    }
    
    if (/123|abc|qwerty/.test(password)) {
      suggestions.push('Avoid common sequences');
    }
    
    if (suggestions.length === 0) {
      suggestions.push('Great password!');
    }
    
    return suggestions;
  };

  const detectPasswordPatterns = (password) => {
    const patterns = [];
    
    if (!password) return patterns;
    
    if (/(.)\1{2,}/.test(password)) {
      patterns.push({
        type: 'Repetition',
        pattern: 'Repeated characters',
        severity: 'high'
      });
    }
    
    if (/[a-z]{4,}/.test(password)) {
      patterns.push({
        type: 'Dictionary',
        pattern: 'Common word pattern',
        severity: 'medium'
      });
    }
    
    if (/123|abc|qwerty/.test(password)) {
      patterns.push({
        type: 'Sequence',
        pattern: 'Common sequence',
        severity: 'high'
      });
    }
    
    if (password.length < 8) {
      patterns.push({
        type: 'Length',
        pattern: 'Too short (less than 8 characters)',
        severity: 'high'
      });
    }
    
    return patterns;
  };

  const estimateCrackTimes = (password) => {
    if (!password) {
      return {
        online: { seconds: 0, time_readable: 'instantly' },
        offline_fast: { seconds: 0, time_readable: 'instantly' },
        offline_slow: { seconds: 0, time_readable: 'instantly' }
      };
    }

    const charsetSize = (
      (/[a-z]/.test(password) ? 26 : 0) +
      (/[A-Z]/.test(password) ? 26 : 0) +
      (/[0-9]/.test(password) ? 10 : 0) +
      (/[^A-Za-z0-9]/.test(password) ? 32 : 0)
    );
    
    const possibleCombinations = Math.pow(charsetSize || 1, password.length || 1);
    
    return {
      online: {
        seconds: possibleCombinations / (2 * 100),
        time_readable: formatTime(possibleCombinations / (2 * 100))
      },
      offline_fast: {
        seconds: possibleCombinations / (2 * 1e10),
        time_readable: formatTime(possibleCombinations / (2 * 1e10))
      },
      offline_slow: {
        seconds: possibleCombinations / (2 * 1e4),
        time_readable: formatTime(possibleCombinations / (2 * 1e4))
      }
    };
  };

  const formatTime = (seconds) => {
    if (seconds < 1) return 'less than a second';
    if (seconds < 60) return `${seconds.toFixed(0)} seconds`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(0)} minutes`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`;
    if (seconds < 31536000) return `${(seconds / 86400).toFixed(1)} days`;
    if (seconds < 31536000 * 100) return `${(seconds / 31536000).toFixed(1)} years`;
    return 'centuries';
  };

  const handleAddPassword = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    
    try {
      if (!user || !user.uid) {
        throw new Error('User not authenticated');
      }
      
      // Validate required fields
      if (!newPassword.service.trim() || !newPassword.username.trim() || !newPassword.password.trim()) {
        throw new Error('Please fill in all required fields');
      }
  
      // Analyze the password before storing
      const analysis = await analyzePassword(newPassword.password);
      const isPwned = await checkPwned(newPassword.password);
      
      // Prepare the document data with all required fields
      const passwordData = {
        userId: user.uid,
        service: newPassword.service.trim(),
        username: newPassword.username.trim(),
        password: newPassword.password, // Note: In production, encrypt this first!
        notes: newPassword.notes.trim(),
        createdAt: new Date(),
        lastChanged: new Date(),
        isPwned,
        strengthScore: analysis.strength_score,
        daysToChange: calculateDaysToChange(analysis.strength_score)
      };
  
      // Debug: Log the data being sent to Firestore
      console.log('Attempting to save password:', passwordData);
      
      // Store in Firestore
      const docRef = await addDoc(collection(db, 'passwords'), passwordData);
      console.log('Password saved with ID:', docRef.id);
      
      // Refresh the list
      await fetchPasswords(user.uid);
      setShowAddPassword(false);
      setNewPassword({
        service: '',
        username: '',
        password: '',
        notes: ''
      });
    } catch (err) {
      console.error('Error adding password:', err);
      setError(err.message || 'Failed to add password. Please check your permissions and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewPassword(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleViewAnalysis = (password) => {
    navigate('/vulnerability-analysis', { state: { password } });
  };

  const getStrengthColor = (score) => {
    if (score >= 80) return '#4CAF50';
    if (score >= 60) return '#8BC34A';
    if (score >= 40) return '#FFC107';
    if (score >= 20) return '#FF9800';
    return '#F44336';
  };

  // Calculate statistics
  const totalPasswords = passwords.length;
  const strongPasswords = passwords.filter(pwd => pwd.analysis?.strength_score >= 60).length;
  const moderatePasswords = passwords.filter(pwd => 
    pwd.analysis?.strength_score >= 40 && pwd.analysis?.strength_score < 60
  ).length;
  const weakPasswords = passwords.filter(pwd => pwd.analysis?.strength_score < 40).length;
  const pwnedPasswords = passwords.filter(pwd => pwd.isPwned).length;

  return (
    <div className="dashboard-container">
      <h1>Password Health Dashboard</h1>
      
      {error && (
        <div className="error-message">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
          {error}
          <button 
            className="retry-btn"
            onClick={() => user?.uid && fetchPasswords(user.uid)}
          >
            Retry
          </button>
        </div>
      )}
      
      {isLoading ? (
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading password data...</p>
        </div>
      ) : (
        <>
          <div className="dashboard-header">
            <h2>Your Password Security Overview</h2>
            <button 
              className="add-password-btn"
              onClick={() => setShowAddPassword(true)}
              disabled={isLoading}
            >
              + Add New Password
            </button>
          </div>
          
          {showAddPassword && (
            <div className="add-password-modal">
              <div className="modal-content">
                <h3>Add New Password</h3>
                <button 
                  className="close-modal"
                  onClick={() => setShowAddPassword(false)}
                  disabled={isLoading}
                >
                  &times;
                </button>
                
                <form onSubmit={handleAddPassword}>
                  <div className="form-group">
                    <label>Service/Website</label>
                    <input
                      type="text"
                      name="service"
                      value={newPassword.service}
                      onChange={handleInputChange}
                      required
                      disabled={isLoading}
                    />
                  </div>
                  
                  <div className="form-group">
                    <label>Username/Email</label>
                    <input
                      type="text"
                      name="username"
                      value={newPassword.username}
                      onChange={handleInputChange}
                      required
                      disabled={isLoading}
                    />
                  </div>
                  
                  <div className="form-group">
                    <label>Password</label>
                    <input
                      type="password"
                      name="password"
                      value={newPassword.password}
                      onChange={handleInputChange}
                      required
                      disabled={isLoading}
                    />
                    <div className="password-strength-meter">
                      <div 
                        className="strength-bar"
                        style={{
                          width: `${calculatePasswordScore(newPassword.password)}%`,
                          backgroundColor: getStrengthColor(calculatePasswordScore(newPassword.password))
                        }}
                      ></div>
                    </div>
                    <div className="password-feedback">
                      {newPassword.password && (
                        <>
                          <p>Strength: {getStrengthCategory(calculatePasswordScore(newPassword.password))}</p>
                          <ul className="suggestions-list">
                            {getPasswordSuggestions(newPassword.password).map((suggestion, index) => (
                              <li key={index}>{suggestion}</li>
                            ))}
                          </ul>
                        </>
                      )}
                    </div>
                  </div>
                  
                  <div className="form-group">
                    <label>Notes (optional)</label>
                    <textarea
                      name="notes"
                      value={newPassword.notes}
                      onChange={handleInputChange}
                      disabled={isLoading}
                    />
                  </div>
                  
                  <button 
                    type="submit" 
                    className="submit-btn"
                    disabled={isLoading}
                  >
                    {isLoading ? 'Saving...' : 'Save Password'}
                  </button>
                </form>
              </div>
            </div>
          )}
          
          <div className="dashboard-summary">
            <div className="summary-card">
              <h3>Total Passwords</h3>
              <div className="summary-value">{totalPasswords}</div>
              <p>Accounts Secured</p>
            </div>
            
            <div className="summary-card">
              <h3>Strong Passwords</h3>
              <div className="summary-value" style={{ color: '#4CAF50' }}>
                {strongPasswords}
              </div>
              <p>Excellent security</p>
            </div>
            
            <div className="summary-card">
              <h3>Moderate Passwords</h3>
              <div className="summary-value" style={{ color: '#FFC107' }}>
                {moderatePasswords}
              </div>
              <p>Needs improvement</p>
            </div>
            
            <div className="summary-card">
              <h3>Weak Passwords</h3>
              <div className="summary-value" style={{ color: '#F44336' }}>
                {weakPasswords}
              </div>
              <p>Immediate action needed</p>
            </div>
            
            <div className="summary-card critical">
              <h3>Compromised</h3>
              <div className="summary-value" style={{ color: '#F44336' }}>
                {pwnedPasswords}
              </div>
              <p>Passwords found in breaches</p>
            </div>
          </div>
          
          {passwords.length > 0 ? (
            <>
              <div className="password-health-grid">
                <div className="health-metrics">
                  <h3>Password Health Metrics</h3>
                  <div className="metric">
                    <label>Average Password Strength</label>
                    <div className="metric-bar">
                      <div 
                        className="bar-fill"
                        style={{
                          width: `${passwords.reduce((sum, pwd) => sum + (pwd.analysis?.strength_score || 0), 0) / Math.max(1, passwords.length)}%`,
                          backgroundColor: getStrengthColor(
                            passwords.reduce((sum, pwd) => sum + (pwd.analysis?.strength_score || 0), 0) / Math.max(1, passwords.length)
                          )
                        }}
                      ></div>
                      <span>
                        {passwords.length > 0 ? 
                          Math.round(passwords.reduce((sum, pwd) => sum + (pwd.analysis?.strength_score || 0), 0) / passwords.length) : 
                          0}/100
                      </span>
                    </div>
                  </div>
                  
                  <div className="metric">
                    <label>Change Recommendations</label>
                    <div className="recommendation-tiles">
                      {passwords
                        .filter(pwd => pwd.daysToChange <= 30)
                        .sort((a, b) => a.daysToChange - b.daysToChange)
                        .slice(0, 3)
                        .map(pwd => (
                          <div key={pwd.id} className="recommendation-tile">
                            <div className="tile-header">
                              <span className="service">{pwd.service}</span>
                              <span className="urgency" style={{
                                color: pwd.daysToChange <= 7 ? '#F44336' : 
                                      pwd.daysToChange <= 14 ? '#FF9800' : '#FFC107'
                              }}>
                                {pwd.daysToChange <= 7 ? 'Urgent' : 
                                 pwd.daysToChange <= 14 ? 'Soon' : 'When possible'}
                              </span>
                            </div>
                            <p>Change in {pwd.daysToChange} days</p>
                            <p>Current strength: 
                              <span style={{
                                color: getStrengthColor(pwd.analysis?.strength_score || 0)
                              }}>
                                {' ' + (pwd.analysis?.strength_category || 'Unknown')}
                              </span>
                            </p>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>
                
                <div className="password-list-container">
                  <h3>Your Passwords</h3>
                  <div className="password-list">
                    {passwords.map(pwd => (
                      <div key={pwd.id} className="password-item">
                        <div className="service-info">
                          <div className="service-name">{pwd.service}</div>
                          <div className="username">{pwd.username}</div>
                        </div>
                        
                        <div className="security-info">
                          <div className="strength-indicator">
                            <div 
                              className="strength-dot"
                              style={{
                                backgroundColor: getStrengthColor(pwd.analysis?.strength_score || 0)
                              }}
                            ></div>
                            <span>{pwd.analysis?.strength_category || 'Unknown'}</span>
                          </div>
                          
                          {pwd.isPwned && (
                            <div className="breach-warning">
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                                <line x1="12" y1="9" x2="12" y2="13"></line>
                                <line x1="12" y1="17" x2="12.01" y2="17"></line>
                              </svg>
                              <span>Compromised</span>
                            </div>
                          )}
                        </div>
                        
                        <div className="action-buttons">
                          <button 
                            className="view-details-btn"
                            onClick={() => handleViewAnalysis(pwd.password)}
                          >
                            View Details
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              
              <div className="security-recommendations">
                <h3>Security Recommendations</h3>
                
                <div className="recommendation-cards">
                  {pwnedPasswords > 0 && (
                    <div className="recommendation-card critical">
                      <h4>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                          <line x1="12" y1="9" x2="12" y2="13"></line>
                          <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                        Change Compromised Passwords
                      </h4>
                      <p>
                        {pwnedPasswords} of your passwords have been found in data breaches. 
                        Change these immediately and enable two-factor authentication where available.
                      </p>
                    </div>
                  )}
                  
                  {weakPasswords > 0 && (
                    <div className="recommendation-card warning">
                      <h4>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                          <circle cx="12" cy="12" r="10"></circle>
                          <line x1="12" y1="8" x2="12" y2="12"></line>
                          <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                        Strengthen Weak Passwords
                      </h4>
                      <p>
                        You have {weakPasswords} weak passwords that are vulnerable to attacks. 
                        Consider using longer, more complex passwords or passphrases.
                      </p>
                    </div>
                  )}
                  
                  <div className="recommendation-card">
                    <h4>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5"></path>
                        <path d="M8.5 8.5v.01"></path>
                        <path d="M16 15.5v.01"></path>
                        <path d="M12 12v.01"></path>
                        <path d="M11 17v.01"></path>
                        <path d="M7 14v.01"></path>
                      </svg>
                      Use a Password Manager
                    </h4>
                    <p>
                      A password manager can generate and store strong, unique passwords for all your accounts.
                      This eliminates the need to remember multiple complex passwords.
                    </p>
                  </div>
                  
                  <div className="recommendation-card">
                    <h4>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                      </svg>
                      Enable Two-Factor Authentication
                    </h4>
                    <p>
                      Where available, enable two-factor authentication (2FA) for an extra layer of security.
                      This protects your accounts even if your password is compromised.
                    </p>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"></path>
              </svg>
              <h3>No Passwords Found</h3>
              <p>You haven't added any passwords yet. Click the button below to add your first password.</p>
              <button 
                className="add-first-password-btn"
                onClick={() => setShowAddPassword(true)}
              >
                + Add Your First Password
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default PasswordHealthDashboard;