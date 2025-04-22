import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './AnimationPage.css';

const AnimationPage = ({ onComplete }) => {
  const navigate = useNavigate();
  const duration = 3000; // 3 seconds

  useEffect(() => {
    const timer = setTimeout(() => {
      onComplete();
      navigate('/');
    }, duration);

    return () => clearTimeout(timer);
  }, [navigate, onComplete]);

  return (
    <div className="animation-container">
      {/* Animated binary matrix background */}
      <div className="binary-matrix">
        {Array.from({ length: 150 }).map((_, i) => (
          <span 
            key={i} 
            className="binary-digit"
            style={{
              animationDelay: `${Math.random() * 2}s`,
              color: Math.random() > 0.7 ? '#00AEEF' : '#FFFFFF'
            }}
          >
            {Math.random() > 0.5 ? '1' : '0'}
          </span>
        ))}
      </div>

      {/* Cyber security shield animation */}
      <div className="cyber-shield">
        <div className="shield-core">
          <div className="shield-icon">🔒</div>
          <div className="shield-ring"></div>
          <div className="shield-ring delay-1"></div>
          <div className="shield-ring delay-2"></div>
        </div>
      </div>

      {/* Password strength visualization */}
      <div className="password-strength">
        {['W', 'E', 'A', 'K'].map((char, i) => (
          <div 
            key={i} 
            className="strength-char"
            style={{ animationDelay: `${i * 0.2}s` }}
          >
            {char}
          </div>
        ))}
        <div className="strength-transform">→</div>
        {['S', 'T', 'R', 'O', 'N', 'G'].map((char, i) => (
          <div 
            key={i+4} 
            className="strength-char strong"
            style={{ animationDelay: `${0.8 + i * 0.15}s` }}
          >
            {char}
          </div>
        ))}
      </div>

      {/* Main title */}
      <div className="cyber-title">
        <h1 className="title-main">Breach.ai</h1>
        <h2 className="title-sub">Password Strength Analyzer</h2>
      </div>
    </div>
  );
};

export default AnimationPage;