import React, { useState, useRef, useEffect } from 'react';
import './Chatbot.css';

const Chatbot = ({ password, onPasswordSelect }) => {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hi! I am Fix It AI, your password security assistant. I can help you generate secure passwords based on your preferences and provide security advice. Select one of the options below to generate a specific type of password.' }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [suggestions, setSuggestions] = useState([]);
  const [credentialMode, setCredentialMode] = useState(null);
  const [showCredentialForm, setShowCredentialForm] = useState(false);
  const [formData, setFormData] = useState({
    personal: {
      name: '',
      birthYear: '',
      hobby: '',
      petName: ''
    },
    work: {
      role: '',
      department: '',
      companyName: '',
      employeeId: ''
    }
  });
  const messagesEndRef = useRef(null);
  const initialMessageSent = useRef(false);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Effect to handle when password prop changes
  useEffect(() => {
    if (password && !initialMessageSent.current) {
      initialMessageSent.current = true;
      const suggestions = enhancePassword(password);
      setSuggestions(suggestions);
      setMessages(prev => [...prev,
        { role: 'assistant', content: `I see you've entered the password "${password}". I've analyzed it and created three secure variations that enhance its strength:\n\n1. L33t speak with special ending\n2. Mixed case with strategic numbers\n3. Special characters with uppercase mix\n\nClick any suggestion below to analyze its strength. Each variation:\n• Maintains similar pattern to original\n• Uses strategic character substitutions\n• Adds complexity with special chars\n• Ends with unique character combination` }
      ]);
    }
  }, [password]);

  // Reset initialMessageSent when password changes
  useEffect(() => {
    if (!password) {
      initialMessageSent.current = false;
    }
  }, [password]);

  const enhancePassword = (basePassword) => {
    try {
      const suggestions = [];
      const extraChars = ['!', '@', '#', '$', '%', '*', '&'];
      const extraLetters = ['Q', 'X', 'Z', 'K', 'J', 'V', 'W'];
      
      // First variation: L33t speak with special chars
      let variation1 = basePassword
        .replace(/s/g, '5')
        .replace(/a/g, '@')
        .replace(/e/g, '3')
        .replace(/i/g, '1')
        .replace(/o/g, '0');
      variation1 = variation1.slice(0, -1) + 
                  extraChars[Math.floor(Math.random() * extraChars.length)] +
                  extraLetters[Math.floor(Math.random() * extraLetters.length)];
      suggestions.push(variation1);

      // Second variation: Mixed case with strategic numbers
      let variation2 = basePassword
        .split('')
        .map((char, i) => {
          if (char.match(/[a-zA-Z]/)) {
            return i % 2 === 0 ? char.toUpperCase() : char.toLowerCase();
          }
          return char;
        })
        .join('')
        .replace(/i/g, '1')
        .replace(/o/g, '0');
      variation2 = variation2.slice(0, -1) + 
                  extraChars[Math.floor(Math.random() * extraChars.length)] +
                  extraLetters[Math.floor(Math.random() * extraLetters.length)];
      suggestions.push(variation2);

      // Third variation: Special chars and uppercase
      let variation3 = basePassword
        .replace(/[aA]/g, '@')
        .replace(/[sS]/g, '$')
        .replace(/[eE]/g, '3')
        .split('')
        .map((char, i) => {
          if (char.match(/[a-z]/)) {
            return Math.random() > 0.5 ? char.toUpperCase() : char;
          }
          return char;
        })
        .join('');
      variation3 = variation3.slice(0, -1) + 
                  extraChars[Math.floor(Math.random() * extraChars.length)] +
                  extraLetters[Math.floor(Math.random() * extraLetters.length)];
      suggestions.push(variation3);

      return suggestions;
    } catch (error) {
      console.error('Error generating password variations:', error);
      return [
        basePassword + '!Q',
        basePassword + '@W',
        basePassword + '#E'
      ];
    }
  };

  const handleOptionClick = (type) => {
    setCredentialMode(type);
    setShowCredentialForm(true);
    setMessages(prev => [...prev, 
      { role: 'user', content: `Generate ${type} email password` },
      { role: 'assistant', content: `Please fill in all the fields below to generate a secure ${type} email password:` }
    ]);
  };

  const handleFormSubmit = (e) => {
    e.preventDefault();
    const type = credentialMode;
    const credentials = formData[type];

    // Validate all fields are filled
    if (Object.values(credentials).some(value => !value.trim())) {
      setMessages(prev => [...prev, 
        { role: 'assistant', content: 'Please fill in all credential fields.' }
      ]);
      return;
    }

    const suggestions = generatePasswordFromCredentials(credentials, type);
    setSuggestions(suggestions);
    setShowCredentialForm(false);
    setMessages(prev => [...prev,
      { role: 'user', content: 'Credentials submitted' },
      { role: 'assistant', content: type === 'personal' 
        ? `Based on your personal information, I've created these easy-to-remember but secure password variations. Each one follows a simple pattern while maintaining security:\n\n1. First letter + Birth year + Hobby + Special character\n2. Hobby + Pet + Birth year + Special character\n3. Pet + First letter + Birth year + Special character\n\nClick any suggestion to use it. These passwords are designed to be both secure and memorable!`
        : `Based on your work credentials, I've generated these secure password variations. Each one is unique and incorporates elements of your work information in a secure way. Click any suggestion to use it:\n\n1. Enhanced with special characters\n2. Mixed case with numbers\n3. Strategic character replacements` }
    ]);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [credentialMode]: {
        ...prev[credentialMode],
        [name]: value
      }
    }));
  };

  const generatePasswordFromCredentials = (creds, type) => {
    try {
      let basePassword = '';
      if (type === 'personal') {
        // Create more memorable patterns for personal passwords
        const nameInit = creds.name.charAt(0).toUpperCase();
        const year = creds.birthYear.slice(-2);
        const hobby = creds.hobby.slice(0, 3).toLowerCase();
        const pet = creds.petName.slice(0, 2);
        
        // Generate three variations with different patterns
        const variations = [
          // Pattern 1: Name + Year + Hobby + Special
          `${nameInit}${year}${hobby}!`,
          // Pattern 2: Hobby + Pet + Year + Special
          `${hobby}${pet}${year}@`,
          // Pattern 3: Pet + Name + Year + Special
          `${pet}${nameInit}${year}#`
        ];

        return variations;
      } else {
        // Keep work passwords more complex
        const role = creds.role.slice(0, 3).toLowerCase();
        const dept = creds.department.slice(0, 2).toUpperCase();
        const company = creds.companyName.slice(0, 2);
        const id = creds.employeeId.slice(-3);
        basePassword = `${role}${dept}${company}${id}`;
        return enhancePassword(basePassword);
      }
    } catch (error) {
      console.error('Error generating credential-based password:', error);
      return [
        `Secure${type}Pass1!`,
        `Strong${type}Pass2@`,
        `Safe${type}Pass3#`
      ];
    }
  };

  const getAIResponse = async (message, context = []) => {
    const messageLC = message.toLowerCase();
    
    try {
      // Handle Barclays-specific questions
      const barclaysResponses = {
        'barclays': "Yes, I'm Fix It AI, a password security assistant created for Barclays. I can help you generate secure passwords for both personal and work email use. Select one of the options below to begin.",
        'about barclays': "Barclays is a British multinational bank with over 300 years of history. I'm Fix It AI, and I can help you create secure passwords that meet Barclays' standards. Select an option below to begin.",
        'who made you': "I'm Fix It AI, a password security assistant created for the Barclays Hackathon. I can help generate secure passwords based on your credentials. Select an option below to begin.",
        'what can you do': "As Fix It AI, your Barclays password security assistant, I can:\n\n• Generate secure passwords for personal email use\n• Generate secure passwords for work email use\n• Enhance password security using your credentials\n• Provide security recommendations\n\nSelect an option below to begin.",
        'security requirements': "Barclays password requirements include:\n\n• Minimum 8 characters length\n• Mix of uppercase and lowercase letters\n• At least one number\n• At least one special character\n• No commonly used passwords\n• No personal information\n\nSelect an option below to generate a secure password.",
        'bank': "Yes, I'm Fix It AI, associated with Barclays Bank. I can help you create secure passwords for both personal and work emails. Select an option below to begin.",
        'hackathon': "Yes, I'm Fix It AI, a password security assistant created for the Barclays Hackathon. Select an option below to generate a secure password."
      };

      // Check for Barclays-related queries
      for (const [key, response] of Object.entries(barclaysResponses)) {
        if (messageLC.includes(key)) {
          return response;
        }
      }

      // Handle greetings
      const greetings = ['hi', 'hello', 'hey', 'greetings', 'how are you'];
      if (greetings.some(g => messageLC.includes(g))) {
        return "Hello! I'm Fix It AI, your Barclays password security assistant. Select one of the options below to generate a secure password for your needs.";
      }

      // Default response
      return "I'm Fix It AI, and I can help you generate secure passwords for personal or work email use. Select one of the options below to begin.";

    } catch (error) {
      console.error('AI Response Error:', error);
      return "I apologize for the error. I'm Fix It AI. Please select one of the options below to generate a secure password.";
    }
  };

  const handleSendMessage = async () => {
    if (!input.trim()) return;

    const userMessage = input.trim();
    setInput('');
    
    // Add user message to history
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setIsLoading(true);

    try {
      // Get AI response
      const response = await getAIResponse(userMessage);
      
      // Add AI response to messages
      setMessages(prev => [...prev, { role: 'assistant', content: response }]);
    } catch (error) {
      console.error('Error:', error);
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: "I apologize for the error. How can I assist you with password security?" 
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="chatbot-container">
      <div className="chatbot-messages">
        {messages.map((message, index) => (
          <div key={index} className={`message ${message.role}`}>
            <div className="message-content">
              {message.content}
              {message.role === 'assistant' && suggestions.length > 0 && index === messages.length - 1 && (
                <div className="password-suggestions">
                  {suggestions.map((suggestion, i) => (
                    <button
                      key={i}
                      className="password-suggestion-btn"
                      onClick={() => onPasswordSelect(suggestion)}
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {showCredentialForm && (
          <div className="credential-form-container">
            <form onSubmit={handleFormSubmit} className="credential-form">
              {credentialMode === 'personal' ? (
                <>
                  <div className="form-group">
                    <input
                      type="text"
                      name="name"
                      placeholder="First Name"
                      value={formData.personal.name}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <input
                      type="text"
                      name="birthYear"
                      placeholder="Birth Year (YYYY)"
                      value={formData.personal.birthYear}
                      onChange={handleInputChange}
                      required
                      pattern="\d{4}"
                    />
                  </div>
                  <div className="form-group">
                    <input
                      type="text"
                      name="hobby"
                      placeholder="Favorite Hobby"
                      value={formData.personal.hobby}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <input
                      type="text"
                      name="petName"
                      placeholder="Pet Name (or favorite animal)"
                      value={formData.personal.petName}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                </>
              ) : (
                <>
                  <div className="form-group">
                    <input
                      type="text"
                      name="role"
                      placeholder="Job Role"
                      value={formData.work.role}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <input
                      type="text"
                      name="department"
                      placeholder="Department"
                      value={formData.work.department}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <input
                      type="text"
                      name="companyName"
                      placeholder="Company Name"
                      value={formData.work.companyName}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <input
                      type="text"
                      name="employeeId"
                      placeholder="Employee ID"
                      value={formData.work.employeeId}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                </>
              )}
              <button type="submit" className="submit-credentials-btn">
                Generate Password
              </button>
            </form>
          </div>
        )}
        {isLoading && (
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
      <div className="chatbot-controls">
        <div className="password-type-options">
          <button 
            className={`option-btn ${credentialMode === 'personal' ? 'active' : ''}`}
            onClick={() => handleOptionClick('personal')}
            disabled={showCredentialForm}
          >
            Personal Email Password
          </button>
          <button 
            className={`option-btn ${credentialMode === 'work' ? 'active' : ''}`}
            onClick={() => handleOptionClick('work')}
            disabled={showCredentialForm}
          >
            Work Email Password
          </button>
        </div>
        <div className="chatbot-input">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type your message..."
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage();
              }
            }}
            className="chatbot-textarea"
            rows={1}
          />
          <button onClick={handleSendMessage} disabled={isLoading}>
            Send
          </button>
        </div>
      </div>
    </div>
  );
};

export default Chatbot; 