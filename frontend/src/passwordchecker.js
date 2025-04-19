import { useState, useCallback } from 'react';
import './App.css';

function App() {
  const [password, setPassword] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzePassword = useCallback(async () => {
    if (!password.trim()) {
      setError('Please enter a password');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:5000/analyze', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password })
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();
      
      setAnalysis({
        strength: data.strength || data.strength, // Handle typo in response if any
        crackTime: data.crack_time || data.crack_time,
        entropy: data.entropy,
        suggestions: data.suggestions || []
      });

    } catch (err) {
      console.error('Analysis failed:', err);
      setError(err.message || 'Failed to analyze password');
      setAnalysis(null);
    } finally {
      setIsLoading(false);
    }
  }, [password]);

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      analyzePassword();
    }
  };

  const getStrengthColor = (strength) => {
    if (strength < 30) return '#ff4d4d';
    if (strength < 60) return '#ffa64d';
    if (strength < 80) return '#ffcc00';
    return '#4CAF50';
  };

  return (
    <div className="app">
      <header className="header">
        <h1>Password Strength Analyzer</h1>
        <p>Check how secure your password is against attacks</p>
      </header>

      <main className="main-content">
        <div className="password-input-container">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Enter your password..."
            className="password-input"
            disabled={isLoading}
          />
          <button
            onClick={analyzePassword}
            disabled={isLoading || !password}
            className="analyze-button"
          >
            {isLoading ? (
              <>
                <span className="spinner"></span> Analyzing...
              </>
            ) : (
              'Analyze'
            )}
          </button>
        </div>

        {error && (
          <div className="error-message">
            <span role="img" aria-label="warning">⚠️</span> {error}
          </div>
        )}

        {analysis && (
          <div className="analysis-results">
            <div className="strength-section">
              <h2>Strength Analysis</h2>
              <div className="strength-meter-container">
                <div className="strength-meter">
                  <div
                    className="strength-meter-fill"
                    style={{
                      width: `${analysis.strength}%`,
                      backgroundColor: getStrengthColor(analysis.strength)
                    }}
                  ></div>
                </div>
                <span className="strength-score">{analysis.strength}%</span>
              </div>
              <div className="strength-details">
                <div className="detail-item">
                  <span className="detail-label">Crack Time:</span>
                  <span className="detail-value">{analysis.crackTime}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Entropy:</span>
                  <span className="detail-value">{analysis.entropy} bits</span>
                </div>
              </div>
            </div>

            {analysis.suggestions && analysis.suggestions.length > 0 && (
              <div className="suggestions-section">
                <h2>Stronger Password Suggestions</h2>
                <ul className="suggestions-list">
                  {analysis.suggestions.map((suggestion, index) => (
                    <li key={index} className="suggestion-item">
                      <code>{suggestion}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="tips-section">
              <h2>Password Security Tips</h2>
              <ul className="tips-list">
                <li>Use at least 12 characters</li>
                <li>Include numbers, symbols, and both uppercase and lowercase letters</li>
                <li>Avoid common words and patterns</li>
                <li>Don't use personal information</li>
                <li>Consider using a passphrase</li>
              </ul>
            </div>
          </div>
        )}
      </main>

      <footer className="footer">
        <p>Note: This tool does not store your password. All analysis happens in your browser.</p>
      </footer>
    </div>
  );
}

export default App;