import React, { useState, useRef, useEffect } from 'react';
import './Chatbot.css';

const Chatbot = ({ onPasswordSelect }) => {
  const [messages, setMessages] = useState([
    { 
      role: 'assistant', 
      content: 'Welcome to your AI Password Generator powered by Llama 2! I can help you create strong, memorable passwords based on your context.\n\n' +
               '🔒 Tell me about the account or service you need a password for\n' +
               '🔑 Share your current password (if you have one) for inspiration\n' +
               '🧠 I\'ll generate a secure, easy-to-remember password for you\n\n' +
               'What account or service do you need a password for?'
    }
  ]);
  const [input, setInput] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [context, setContext] = useState('');
  const [existingPassword, setExistingPassword] = useState('');
  const [hasProvidedContext, setHasProvidedContext] = useState(false);
  const [hasProvidedPassword, setHasProvidedPassword] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const generatePasswordWithOllama = async () => {
    setIsGenerating(true);
    
    try {
      const response = await fetch('http://localhost:5000/api/generate-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          context: context,
          existing_password: existingPassword
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to generate password');
      }
      
      const data = await response.json();
      
      // Add the generated password to the chat
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Here's a secure password based on your ${existingPassword ? 'existing password' : 'context'}:`,
        suggestion: {
          password: data.password,
          strength: data.strength_score,
          explanation: data.explanation
        },
        memorization: {
          tips: data.memorization_tips,
          message: "Here are some tips to help you remember this password:"
        }
      }]);
      
      // Reset the state for the next password generation
      setContext('');
      setExistingPassword('');
      setHasProvidedContext(false);
      setHasProvidedPassword(false);
      
    } catch (error) {
      console.error('Error generating password:', error);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Sorry, I encountered an error while generating your password. Please try again.'
      }]);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');

    // If we don't have context yet, use the input as context
    if (!hasProvidedContext) {
      setContext(input);
      setHasProvidedContext(true);
      
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Great! Now, do you have an existing password for this account that you\'d like me to use as inspiration? If so, please share it. If not, just type "no" and I\'ll generate a completely new password.'
      }]);
    } 
    // If we have context but no password yet
    else if (!hasProvidedPassword) {
      if (input.toLowerCase() !== 'no') {
        setExistingPassword(input);
        setHasProvidedPassword(true);
        
        // Add a message to acknowledge the existing password
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: `I'll use "${input}" as inspiration to create a more secure password.`
        }]);
      } else {
        setHasProvidedPassword(true);
        
        // Add a message to acknowledge the user doesn't have an existing password
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: 'I\'ll generate a completely new password for you.'
        }]);
      }
      
      // Generate the password
      await generatePasswordWithOllama();
      
      // Ask if they want to generate another password
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Would you like to generate another password? If so, just tell me what account or service you need it for.'
      }]);
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
                        {message.memorization.tips.map((tip, i) => (
                          <div key={i} className="technique-item">
                            <span className="technique-icon">💡</span>
                            {tip}
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

      <div className="chatbot-input-container">
        <div className="chatbot-input">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={hasProvidedContext ? "Share your existing password or type 'no'..." : "What account or service do you need a password for?"}
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