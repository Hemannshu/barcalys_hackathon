// Function to detect password fields
const detectPasswordFields = () => {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
        // Find the associated username field (usually the previous input field)
        const usernameField = findUsernameField(passwordFields[0]);
        if (usernameField) {
            setupAutofillButton(usernameField, passwordFields[0]);
        }
    }
};

// Function to find the username field
const findUsernameField = (passwordField) => {
    // Common username field types
    const usernameSelectors = [
        'input[type="email"]',
        'input[type="text"]',
        'input[name*="email"]',
        'input[name*="user"]',
        'input[name*="login"]'
    ];

    // Try to find the username field by looking at previous input fields
    let element = passwordField;
    while (element = element.previousElementSibling) {
        if (element.matches(usernameSelectors.join(','))) {
            return element;
        }
    }

    // If not found in siblings, try common selectors in the form
    const form = passwordField.closest('form');
    if (form) {
        for (const selector of usernameSelectors) {
            const field = form.querySelector(selector);
            if (field && field !== passwordField) {
                return field;
            }
        }
    }

    return null;
};

// Function to setup autofill button
const setupAutofillButton = (usernameField, passwordField) => {
    // Create autofill button
    const button = document.createElement('button');
    button.textContent = '🔑';
    button.style.cssText = `
        position: absolute;
        right: 5px;
        top: 50%;
        transform: translateY(-50%);
        background: none;
        border: none;
        cursor: pointer;
        font-size: 16px;
        z-index: 9999;
        padding: 5px;
    `;

    // Position the button
    const fieldRect = passwordField.getBoundingClientRect();
    const fieldStyles = window.getComputedStyle(passwordField);
    
    // Make the password field's parent relative if it isn't already
    const parentElement = passwordField.parentElement;
    if (window.getComputedStyle(parentElement).position === 'static') {
        parentElement.style.position = 'relative';
    }

    // Add click event to the button
    button.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();

        // Request credentials from background script
        chrome.runtime.sendMessage({ action: 'getCredentials' }, (response) => {
            if (response && response.credentials) {
                usernameField.value = response.credentials.username;
                passwordField.value = response.credentials.password;
                
                // Trigger input events
                usernameField.dispatchEvent(new Event('input', { bubbles: true }));
                passwordField.dispatchEvent(new Event('input', { bubbles: true }));
            }
        });
    });

    // Add the button next to the password field
    parentElement.appendChild(button);
};

// Run detection when page loads and when DOM changes
detectPasswordFields();

// Create a MutationObserver to watch for dynamically added password fields
const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
        if (mutation.addedNodes.length) {
            detectPasswordFields();
        }
    }
});

// Start observing the document with the configured parameters
observer.observe(document.body, { childList: true, subtree: true }); 