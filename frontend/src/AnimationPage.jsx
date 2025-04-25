import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './AnimationPage.css';

const AnimationPage = ({ onComplete }) => {
  const navigate = useNavigate();
  const duration = 1500; // 3 seconds

  useEffect(() => {
    const timer = setTimeout(() => {
      onComplete();
      navigate('/');
    }, duration);

    return () => clearTimeout(timer);
  }, [navigate, onComplete]);

  return (
    <div className="animation-container">
      {/* Dull binary matrix background */}
      <div className="binary-matrix">
        {Array.from({ length: 400 }).map((_, i) => (
          <span 
            key={i} 
            className="binary-digit"
            style={{
              animationDelay: `${Math.random() * 2}s`,
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              opacity: 0.08 + Math.random() * 0.07 // Very low opacity range
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

      {/* Main title */}
      <div className="cyber-title">
        <h1 className="title-main">Breach.ai</h1>
        <h2 className="title-sub">Password Strength Analyzer</h2>
      </div>
    </div>
  );
};

export default AnimationPage;