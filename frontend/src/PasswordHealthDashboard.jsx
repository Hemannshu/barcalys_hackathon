import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './PasswordHealthDashboard.css';

const PasswordHealthDashboard = () => {
  const [passwords, setPasswords] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    // In a real app, you would fetch the user's passwords from the backend
    // For now, we'll use some sample passwords
    const samplePasswords = [
      { id: 1, service: 'Email', username: 'user@example.com', password: 'Summer2024', lastChanged: '2023-01-15' },
      { id: 2, service: 'Social Media', username: 'user123', password: 'qwerty123', lastChanged: '2022-11-30' },
      { id: 3, service: 'Banking', username: 'user456', password: 'P@ssw0rd!', lastChanged: '2023-03-10' },
      { id: 4, service: 'Shopping', username: 'user789', password: '12345678', lastChanged: '2022-09-05' },
      { id: 5, service: 'Work', username: 'user.work', password: 'Welcome2023!', lastChanged: '2023-02-20' }
    ];

    // Analyze each password
    const analyzePasswords = async () => {
      setIsLoading(true);
      setError(null);
      
      try {
        // Get token from localStorage
        const token = localStorage.getItem('token');
        if (!token) {
          setError('Authentication required. Please log in.');
          navigate('/login');
          return;
        }
        
        const analyzedPasswords = [];
        
        for (const pwd of samplePasswords) {
          try {
            const response = await fetch('http://localhost:5000/api/analyze-password', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
              },
              body: JSON.stringify({ password: pwd.password })
            });
            
            if (!response.ok) {
              if (response.status === 401) {
                setError('Authentication required. Please log in.');
                navigate('/login');
                return;
              }
              throw new Error(`Error: ${response.status}`);
            }
            
            const analysis = await response.json();
            
            analyzedPasswords.push({
              ...pwd,
              analysis: {
                strength_score: analysis.score,
                strength_category: analysis.strength,
                suggestions: analysis.suggestions,
                details: analysis.details
              }
            });
          } catch (err) {
            console.error(`Error analyzing password for ${pwd.service}:`, err);
            // Add the password without analysis
            analyzedPasswords.push({
              ...pwd,
              analysis: {
                strength_score: 0,
                strength_category: 'Unknown',
                patterns: [],
                attack_types: []
              }
            });
          }
        }
        
        setPasswords(analyzedPasswords);
      } catch (err) {
        console.error('Error analyzing passwords:', err);
        setError('Failed to analyze passwords. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };
    
    analyzePasswords();
  }, [navigate]);

  const handleViewAnalysis = (password) => {
    navigate('/vulnerability-analysis', { state: { password } });
  };

  const getStrengthColor = (score) => {
    if (score >= 80) return '#4CAF50'; // Green
    if (score >= 60) return '#8BC34A'; // Light Green
    if (score >= 40) return '#FFC107'; // Amber
    if (score >= 20) return '#FF9800'; // Orange
    return '#F44336'; // Red
  };

  const getRiskLevelColor = (level) => {
    if (level === 'High') return '#F44336'; // Red
    if (level === 'Medium') return '#FF9800'; // Orange
    return '#4CAF50'; // Green
  };

  return (
    <div className="dashboard-container">
      <h1>Password Health Dashboard</h1>
      
      {error && <div className="error-message">{error}</div>}
      
      {isLoading ? (
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Analyzing passwords...</p>
        </div>
      ) : (
        <>
          <div className="dashboard-summary">
            <div className="summary-card">
              <h3>Overall Health</h3>
              <div className="health-score">
                {passwords.length > 0 ? (
                  <>
                    <div className="score-circle" style={{ 
                      background: `conic-gradient(${getStrengthColor(
                        passwords.reduce((sum, pwd) => sum + (pwd.analysis?.strength_score || 0), 0) / passwords.length
                      )} ${passwords.reduce((sum, pwd) => sum + (pwd.analysis?.strength_score || 0), 0) / passwords.length}%, #f0f0f0 0%)`
                    }}>
                      <div className="score-inner">
                        {Math.round(passwords.reduce((sum, pwd) => sum + (pwd.analysis?.strength_score || 0), 0) / passwords.length)}
                      </div>
                    </div>
                    <p>Average Strength</p>
                  </>
                ) : (
                  <p>No passwords to analyze</p>
                )}
              </div>
            </div>
            
            <div className="summary-card">
              <h3>Critical Issues</h3>
              <div className="issue-count">
                {passwords.filter(pwd => pwd.analysis?.strength_score < 40).length}
              </div>
              <p>Weak Passwords</p>
            </div>
            
            <div className="summary-card">
              <h3>Warnings</h3>
              <div className="warning-count">
                {passwords.filter(pwd => pwd.analysis?.strength_score >= 40 && pwd.analysis?.strength_score < 60).length}
              </div>
              <p>Moderate Passwords</p>
            </div>
            
            <div className="summary-card">
              <h3>Secure</h3>
              <div className="secure-count">
                {passwords.filter(pwd => pwd.analysis?.strength_score >= 60).length}
              </div>
              <p>Strong Passwords</p>
            </div>
          </div>
          
          <div className="passwords-table-container">
            <h2>Your Passwords</h2>
            <table className="passwords-table">
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Username</th>
                  <th>Password</th>
                  <th>Strength</th>
                  <th>Last Changed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {passwords.map(pwd => (
                  <tr key={pwd.id}>
                    <td>{pwd.service}</td>
                    <td>{pwd.username}</td>
                    <td>
                      <span className="password-mask">••••••••</span>
                    </td>
                    <td>
                      <div className="strength-indicator">
                        <div 
                          className="strength-bar" 
                          style={{ 
                            width: `${pwd.analysis?.strength_score || 0}%`,
                            backgroundColor: getStrengthColor(pwd.analysis?.strength_score || 0)
                          }}
                        ></div>
                        <span>{pwd.analysis?.strength_category || 'Unknown'}</span>
                      </div>
                    </td>
                    <td>{pwd.lastChanged}</td>
                    <td>
                      <button 
                        className="view-analysis-btn"
                        onClick={() => handleViewAnalysis(pwd.password)}
                      >
                        View Analysis
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          <div className="recommendations-section">
            <h2>Recommendations</h2>
            <div className="recommendations-grid">
              {passwords
                .filter(pwd => pwd.analysis?.strength_score < 60)
                .map(pwd => (
                  <div key={pwd.id} className="recommendation-card">
                    <h3>{pwd.service}</h3>
                    <p>Current strength: <span style={{ color: getStrengthColor(pwd.analysis?.strength_score || 0) }}>
                      {pwd.analysis?.strength_category || 'Unknown'}
                    </span></p>
                    {pwd.analysis?.suggestions && pwd.analysis.suggestions.length > 0 && (
                      <ul className="suggestion-list">
                        {pwd.analysis.suggestions.slice(0, 3).map((suggestion, index) => (
                          <li key={index}>{suggestion}</li>
                        ))}
                      </ul>
                    )}
                    <button 
                      className="improve-btn"
                      onClick={() => handleViewAnalysis(pwd.password)}
                    >
                      Improve Password
                    </button>
                  </div>
                ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default PasswordHealthDashboard;
