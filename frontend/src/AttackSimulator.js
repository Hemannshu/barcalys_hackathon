import { useState, useEffect, useCallback, useMemo } from 'react';
import './AttackSimulator.css';

// Character sets for different password components
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()_-+=[]{}|;:,.<>?';

const AttackSimulator = ({ password = '' }) => {
  const [simulation, setSimulation] = useState({
    isRunning: false,
    speed: 1,
    activeAttack: null,
    attempts: 0,
    currentGuess: '',
    timeElapsed: 0,
    isCracked: false
  });

  // Calculate password entropy in bits
  const calculateEntropy = useCallback((pwd) => {
    if (!pwd || pwd.length === 0) return 0;
    
    // Determine character set used
    let charsetSize = 0;
    if (/[a-z]/.test(pwd)) charsetSize += LOWERCASE.length;
    if (/[A-Z]/.test(pwd)) charsetSize += UPPERCASE.length;
    if (/[0-9]/.test(pwd)) charsetSize += NUMBERS.length;
    if (/[^A-Za-z0-9]/.test(pwd)) charsetSize += SYMBOLS.length;
    
    // Base entropy calculation
    const entropy = Math.log2(Math.pow(charsetSize, pwd.length));
    
    // Common pattern reductions
    const patterns = {
      dictionaryWord: 30,       // Common word
      repeating: 20,            // Repeated patterns
      sequence: 25,             // Keyboard sequences
      shortLength: pwd.length < 8 ? 40 - (pwd.length * 5) : 0,
      yearSuffix: /(19|20)\d{2}$/.test(pwd) ? 15 : 0
    };
    
    // Check for patterns
    if (/^[a-zA-Z]+$/.test(pwd)) patterns.dictionaryWord = 40;
    if (/(.)\1{2,}/.test(pwd)) patterns.repeating = 30;
    if (/123|qwert|asdf/.test(pwd)) patterns.sequence = 35;
    
    const totalReduction = Object.values(patterns).reduce((a, b) => a + b, 0);
    return Math.max(0, entropy - totalReduction);
  }, []);

  // Determine if password is vulnerable to dictionary attack
  const isDictionaryVulnerable = useCallback((pwd) => {
    if (!pwd) return false;
    
    // Common password patterns
    const commonPatterns = [
      /^[a-z]+$/i,            // All letters
      /^[a-z]+\d+$/i,          // Letters + numbers
      /^\d+[a-z]+$/i,          // Numbers + letters
      /^.{1,7}$/,              // Very short
      /(password|qwerty|123)/i, // Common passwords
      /(.)\1{2,}/,             // Repeating characters
      /(19|20)\d{2}$/          // Year suffix
    ];
    
    return commonPatterns.some(pattern => pattern.test(pwd));
  }, []);

  // Generate dictionary variations
  const generateDictionaryVariations = useCallback((pwd) => {
    if (!isDictionaryVulnerable(pwd)) return [];
    
    const variations = new Set();
    const commonSuffixes = ['123', '!', '1', '1234', '2023', '2024'];
    
    // Base variations
    variations.add(pwd.toLowerCase());
    variations.add(pwd.toUpperCase());
    variations.add(pwd.charAt(0).toUpperCase() + pwd.slice(1).toLowerCase());
    
    // Common substitutions
    variations.add(pwd.replace(/a/gi, '@'));
    variations.add(pwd.replace(/e/gi, '3'));
    variations.add(pwd.replace(/i/gi, '1'));
    variations.add(pwd.replace(/o/gi, '0'));
    variations.add(pwd.replace(/s/gi, '$'));
    
    // Suffix variations
    commonSuffixes.forEach(suffix => {
      variations.add(pwd + suffix);
      variations.add(pwd.toLowerCase() + suffix);
    });
    
    return Array.from(variations);
  }, [isDictionaryVulnerable]);

  // Calculate attack times based on entropy and patterns
  const calculateAttackTimes = useCallback((pwd) => {
    if (!pwd) return { dictionary: Infinity, hybrid: Infinity, bruteForce: Infinity };
    
    const entropy = calculateEntropy(pwd);
    const variations = generateDictionaryVariations(pwd);
    const isWeak = isDictionaryVulnerable(pwd);
    
    // Attack speeds (guesses per second)
    const speeds = {
      dictionary: isWeak ? 1e7 : 0,      // 10M guesses/sec for dictionary
      hybrid: isWeak ? 1e6 : 0,          // 1M guesses/sec for hybrid
      bruteForce: 1e9                     // 1B guesses/sec for brute force
    };
    
    // Calculate times
    return {
      dictionary: isWeak ? variations.length / speeds.dictionary : Infinity,
      hybrid: isWeak ? (variations.length * 100) / speeds.hybrid : Infinity,
      bruteForce: Math.pow(2, entropy) / speeds.bruteForce
    };
  }, [calculateEntropy, generateDictionaryVariations, isDictionaryVulnerable]);

  const formatTime = useCallback((seconds) => {
    if (seconds === Infinity) return "centuries";
    if (seconds < 0.001) return "instantly";
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
    if (seconds < 60) return `${seconds.toFixed(2)} sec`;
    if (seconds < 3600) return `${(seconds/60).toFixed(1)} min`;
    if (seconds < 86400) return `${(seconds/3600).toFixed(1)} hrs`;
    if (seconds < 31536000) return `${(seconds/86400).toFixed(1)} days`;
    if (seconds < 31536000 * 100) return `${(seconds/31536000).toFixed(1)} years`;
    return "centuries";
  }, []);

  // Get estimated times
  const estimatedTimes = useMemo(() => {
    const { dictionary, hybrid, bruteForce } = calculateAttackTimes(password);
    return {
      dictionary: formatTime(dictionary),
      hybrid: formatTime(hybrid),
      bruteForce: formatTime(bruteForce)
    };
  }, [password, calculateAttackTimes, formatTime]);

  // Generate a guess based on attack type
  const generateGuess = useCallback((type) => {
    const variations = generateDictionaryVariations(password);
    const isWeak = isDictionaryVulnerable(password);
    
    switch(type) {
      case 'dictionary':
        return isWeak ? variations[Math.floor(Math.random() * variations.length)] : '';
      case 'hybrid':
        return isWeak ? variations[Math.floor(Math.random() * variations.length)] + 
               Math.floor(Math.random() * 100) : '';
      default: // Brute force
        const charset = [
          ...(/[a-z]/.test(password) ? LOWERCASE : ''),
          ...(/[A-Z]/.test(password) ? UPPERCASE : ''),
          ...(/[0-9]/.test(password) ? NUMBERS : ''),
          ...(/[^A-Za-z0-9]/.test(password) ? SYMBOLS : '')
        ].join('');
        
        return Array.from({length: password.length}, 
          () => charset[Math.floor(Math.random() * charset.length)]).join('');
    }
  }, [password, generateDictionaryVariations, isDictionaryVulnerable]);

  // Run simulation
  const runSimulation = (type) => {
    const variations = generateDictionaryVariations(password);
    const isWeak = isDictionaryVulnerable(password);
    
    // Don't run ineffective attacks
    if ((type === 'dictionary' || type === 'hybrid') && !isWeak) {
      return;
    }
    
    setSimulation({
      isRunning: true,
      speed: 1,
      activeAttack: type,
      attempts: 0,
      currentGuess: '',
      timeElapsed: 0,
      isCracked: false
    });
  };

  // Stop simulation
  const stopSimulation = () => {
    setSimulation(prev => ({ ...prev, isRunning: false }));
  };

  // Simulation effect
  useEffect(() => {
    let interval;
    
    if (simulation.isRunning && simulation.activeAttack) {
      const startTime = Date.now();
      
      interval = setInterval(() => {
        setSimulation(prev => {
          // Calculate attempts based on attack type and speed
          const attempts = {
            dictionary: 1e5 * prev.speed,
            hybrid: 1e4 * prev.speed,
            bruteForce: 1e3 * prev.speed
          }[prev.activeAttack];
          
          const newAttempts = prev.attempts + attempts;
          const currentGuess = generateGuess(prev.activeAttack);
          const isCracked = currentGuess === password;
          const elapsed = (Date.now() - startTime) / 1000;
          
          if (isCracked || newAttempts >= Math.pow(2, calculateEntropy(password))) {
            clearInterval(interval);
            return { 
              ...prev, 
              isRunning: false,
              isCracked,
              currentGuess: isCracked ? password : currentGuess,
              timeElapsed: elapsed
            };
          }

          return {
            ...prev,
            attempts: newAttempts,
            timeElapsed: elapsed,
            currentGuess
          };
        });
      }, 100);
    }

    return () => clearInterval(interval);
  }, [simulation.isRunning, simulation.activeAttack, simulation.speed, password, generateGuess, calculateEntropy]);

  return (
    <div className="attack-simulator">
      <div className="controls">
        <div className="attack-buttons">
          <button 
            onClick={() => runSimulation('dictionary')}
            disabled={simulation.isRunning || !isDictionaryVulnerable(password)}
            className={`btn ${simulation.activeAttack === 'dictionary' ? 'active' : ''}`}
          >
            Dictionary
          </button>
          <button 
            onClick={() => runSimulation('bruteForce')}
            disabled={simulation.isRunning}
            className={`btn ${simulation.activeAttack === 'bruteForce' ? 'active' : ''}`}
          >
            Brute Force
          </button>
          <button 
            onClick={() => runSimulation('hybrid')}
            disabled={simulation.isRunning || !isDictionaryVulnerable(password)}
            className={`btn ${simulation.activeAttack === 'hybrid' ? 'active' : ''}`}
          >
            Hybrid
          </button>
          {simulation.isRunning && (
            <button onClick={stopSimulation} className="btn stop-btn">
              Stop
            </button>
          )}
        </div>
        
        <select
          value={simulation.speed}
          onChange={(e) => setSimulation(prev => ({ ...prev, speed: Number(e.target.value) }))}
          disabled={simulation.isRunning}
          className="speed-select"
        >
          <option value={1}>1x Speed</option>
          <option value={10}>10x Speed</option>
          <option value={100}>100x Speed</option>
        </select>
      </div>

      {simulation.activeAttack && (
        <div className="simulation-results">
          <div className="progress-container">
            <div className="progress-text">
              {simulation.isCracked ? (
                <span className="cracked">CRACKED!</span>
              ) : (
                `Attempts: ${Math.floor(simulation.attempts).toLocaleString()}`
              )}
            </div>
            <div 
              className={`progress-bar ${simulation.isCracked ? 'cracked' : ''}`}
              style={{ 
                width: `${Math.min(
                  100, 
                  (simulation.attempts / Math.pow(2, calculateEntropy(password))) * 100
                )}%` 
              }}
            />
          </div>
          
          <div className="guess-info">
            <div className="guess">
              <span>Current attempt: </span>
              <strong>{simulation.currentGuess || 'N/A'}</strong>
            </div>
            <div className="time">
              <span>Time elapsed: </span>
              <strong>{formatTime(simulation.timeElapsed)}</strong>
            </div>
          </div>
        </div>
      )}

      <div className="time-estimates">
        <h4>Estimated Crack Times</h4>
        <div className="estimate-grid">
          <div className="estimate">
            <span>Dictionary:</span>
            <span className="time-value">{estimatedTimes.dictionary}</span>
          </div>
          <div className="estimate">
            <span>Brute Force:</span>
            <span className="time-value">{estimatedTimes.bruteForce}</span>
          </div>
          <div className="estimate">
            <span>Hybrid:</span>
            <span className="time-value">{estimatedTimes.hybrid}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AttackSimulator;