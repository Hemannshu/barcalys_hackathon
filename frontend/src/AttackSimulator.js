import { useState, useEffect, useCallback, useMemo } from 'react';
import './AttackSimulator.css';

const CHARACTER_SET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|;:,.<>?';

const AttackSimulator = ({ password = 'defaultPassword', charsetSize = CHARACTER_SET.length }) => {
  const [simulation, setSimulation] = useState({
    isRunning: false,
    speed: 1,
    activeAttack: null,
    attempts: 0,
    currentGuess: '',
    timeElapsed: 0,
    isCracked: false
  });

  // Expanded common passwords and patterns
  const COMMON_PASSWORDS = useMemo(() => [
    'password', '123456', '12345678', '1234', 'qwerty', 
    'letmein', 'admin', 'welcome', 'monkey', 'sunshine',
    'password1', '123456789', 'football', 'iloveyou', '1234567',
    'abc123', 'dragon', 'trustno1', 'master', 'superman'
  ], []);

  const DICTIONARY_PATTERNS = useMemo(() => [
    { base: '', suffix: '123' },
    { base: '', suffix: '!' },
    { base: '', suffix: '2023' },
    { base: '', suffix: '@123' },
    { base: 'qwerty', suffix: '123' },
    { base: 'admin', suffix: '123' },
    { base: '', suffix: '123!' },
    { base: '', suffix: '1234' },
    { base: '', suffix: '1' },
    { base: '', suffix: '00' }
  ], []);

  const ATTACK_SPEEDS = useMemo(() => ({
    bruteForce: 1000000,
    dictionary: 5000000,
    hybrid: 3000000
  }), []);

  const formatTime = useCallback((seconds) => {
    if (seconds < 60) return `${seconds.toFixed(1)} sec`;
    if (seconds < 3600) return `${(seconds/60).toFixed(1)} min`;
    if (seconds < 86400) return `${(seconds/3600).toFixed(1)} hrs`;
    return `${(seconds/86400).toFixed(1)} days`;
  }, []);

  const totalGuesses = useMemo(() => {
    if (!password || !charsetSize) return 0;
    return simulation.activeAttack === 'dictionary'
      ? COMMON_PASSWORDS.length * DICTIONARY_PATTERNS.length
      : Math.pow(charsetSize, password.length);
  }, [simulation.activeAttack, charsetSize, password, COMMON_PASSWORDS.length, DICTIONARY_PATTERNS.length]);

  const generateDictionaryGuess = useCallback(() => {
    if (Math.random() < 0.6) {
      return COMMON_PASSWORDS[
        Math.floor(Math.random() * COMMON_PASSWORDS.length)
      ];
    } else {
      const pattern = DICTIONARY_PATTERNS[
        Math.floor(Math.random() * DICTIONARY_PATTERNS.length)
      ];
      const base = pattern.base || 
                  COMMON_PASSWORDS[
                    Math.floor(Math.random() * COMMON_PASSWORDS.length)
                  ];
      return base + pattern.suffix;
    }
  }, [COMMON_PASSWORDS, DICTIONARY_PATTERNS]);

  const generateGuess = useCallback((type) => {
    const pwdLength = password?.length || 8;
    switch(type) {
      case 'dictionary':
        return generateDictionaryGuess();
      case 'hybrid':
        return COMMON_PASSWORDS[
          Math.floor(Math.random() * COMMON_PASSWORDS.length)
        ] + Math.floor(Math.random() * 1000);
      default:
        return Array.from({length: pwdLength}, 
          () => CHARACTER_SET[Math.floor(Math.random() * CHARACTER_SET.length)]).join('');
    }
  }, [generateDictionaryGuess, COMMON_PASSWORDS, password?.length]);

  const runSimulation = (type) => {
    setSimulation({
      isRunning: true,
      speed: simulation.speed,
      activeAttack: type,
      attempts: 0,
      timeElapsed: 0,
      currentGuess: '',
      isCracked: false
    });
  };

  useEffect(() => {
    let interval;
    
    if (simulation.isRunning && simulation.activeAttack) {
      interval = setInterval(() => {
        setSimulation(prev => {
          if (!prev.isRunning) {
            clearInterval(interval);
            return prev;
          }

          const newAttempts = prev.attempts + ATTACK_SPEEDS[prev.activeAttack] * prev.speed / 10;
          const currentGuess = generateGuess(prev.activeAttack);
          const isCracked = currentGuess === password;

          if (isCracked || newAttempts >= totalGuesses) {
            clearInterval(interval);
            return { 
              ...prev, 
              isRunning: false,
              isCracked,
              currentGuess: isCracked ? password : currentGuess
            };
          }

          return {
            ...prev,
            attempts: newAttempts,
            timeElapsed: prev.timeElapsed + 0.1,
            currentGuess
          };
        });
      }, 100);
    }

    return () => clearInterval(interval);
  }, [simulation.isRunning, simulation.speed, simulation.activeAttack, 
      password, generateGuess, ATTACK_SPEEDS, totalGuesses]);

  const estimatedTimes = useMemo(() => {
    if (!password || !charsetSize) return {
      bruteForce: 'N/A',
      dictionary: 'N/A',
      hybrid: 'N/A'
    };
    
    return {
      bruteForce: formatTime(Math.pow(charsetSize, password.length) / ATTACK_SPEEDS.bruteForce),
      dictionary: formatTime((COMMON_PASSWORDS.length * DICTIONARY_PATTERNS.length) / ATTACK_SPEEDS.dictionary),
      hybrid: formatTime((COMMON_PASSWORDS.length * 1000) / ATTACK_SPEEDS.hybrid)
    };
  }, [charsetSize, password, COMMON_PASSWORDS.length, DICTIONARY_PATTERNS.length, ATTACK_SPEEDS, formatTime]);

  return (
    <div className="attack-simulator">
      <h3>Attack Simulation</h3>
      
      <div className="simulation-controls">
        <button 
          onClick={() => runSimulation('dictionary')}
          disabled={simulation.isRunning}
          className={simulation.activeAttack === 'dictionary' ? 'active' : ''}
        >
          Dictionary Attack
        </button>
        
        <button 
          onClick={() => runSimulation('bruteForce')}
          disabled={simulation.isRunning}
          className={simulation.activeAttack === 'bruteForce' ? 'active' : ''}
        >
          Brute Force
        </button>
        
        <button 
          onClick={() => runSimulation('hybrid')}
          disabled={simulation.isRunning}
          className={simulation.activeAttack === 'hybrid' ? 'active' : ''}
        >
          Hybrid Attack
        </button>
        
        <select
          value={simulation.speed}
          onChange={(e) => setSimulation(prev => ({
            ...prev, 
            speed: Number(e.target.value)
          }))}
          disabled={simulation.isRunning}
        >
          <option value={1}>1x Speed</option>
          <option value={10}>10x Speed</option>
          <option value={100}>100x Speed</option>
        </select>
        
        {simulation.isRunning && (
          <button 
            onClick={() => setSimulation(prev => ({...prev, isRunning: false}))}
            className="stop-button"
          >
            Stop
          </button>
        )}
      </div>

      {simulation.activeAttack && (
        <div className="simulation-visualization">
          <div className="progress-container">
            <div 
              className={`progress-bar ${simulation.isCracked ? 'cracked' : ''}`}
              style={{ 
                width: `${Math.min(
                  100, 
                  (simulation.attempts / (
                    simulation.activeAttack === 'dictionary' 
                      ? COMMON_PASSWORDS.length * DICTIONARY_PATTERNS.length
                      : Math.pow(charsetSize, password?.length || 8)
                  )) * 100
                )}%` 
              }}
            />
            <div className="progress-text">
              {simulation.isCracked ? (
                <span className="cracked-message">CRACKED!</span>
              ) : (
                `Attempts: ${Math.floor(simulation.attempts).toLocaleString()}`
              )}
            </div>
          </div>
          
          <div className="guess-display">
            <p>Current attempt: <code>{simulation.currentGuess}</code></p>
            <p>Elapsed: {formatTime(simulation.timeElapsed)}</p>
            {simulation.isCracked && (
              <p className="warning">Your password was cracked!</p>
            )}
          </div>
        </div>
      )}

      <div className="time-estimates">
        <h4>Estimated Crack Times:</h4>
        <ul>
          <li>
            <strong>Dictionary:</strong> {estimatedTimes.dictionary}
          </li>
          <li>
            <strong>Brute Force:</strong> {estimatedTimes.bruteForce}
          </li>
          <li>
            <strong>Hybrid:</strong> {estimatedTimes.hybrid}
          </li>
        </ul>
      </div>
    </div>
  );
};

AttackSimulator.defaultProps = {
  password: 'defaultPassword',
  charsetSize: CHARACTER_SET.length
};

export default AttackSimulator;