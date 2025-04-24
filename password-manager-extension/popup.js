// State management
let state = {
    currentProfile: 'personal',
    profiles: {
        personal: { name: 'Personal', color: '#2196F3' },
        work: { name: 'Work', color: '#4CAF50' }
    },
    generationType: 'random',
    passwordHealth: {
        score: 0,
        issues: []
    }
};

// Word lists for memorable passwords
const WORDS = {
    adjectives: ['happy', 'quick', 'clever', 'brave', 'calm', 'wise', 'bold', 'kind'],
    nouns: ['tiger', 'river', 'mountain', 'sunset', 'ocean', 'forest', 'eagle', 'star'],
    verbs: ['jumps', 'flows', 'shines', 'flies', 'runs', 'dreams', 'sings', 'dances']
};

// Password generation functionality
const generatePassword = () => {
    const length = document.getElementById('length').value;
    const hasUpper = document.getElementById('uppercase').checked;
    const hasLower = document.getElementById('lowercase').checked;
    const hasNumbers = document.getElementById('numbers').checked;
    const hasSymbols = document.getElementById('symbols').checked;

    let password = '';
    
    switch(state.generationType) {
        case 'memorable':
            password = generateMemorablePassword();
            break;
        case 'pin':
            password = generatePIN(length);
            break;
        default:
            password = generateRandomPassword(length, hasUpper, hasLower, hasNumbers, hasSymbols);
    }

    document.getElementById('generatedPassword').value = password;
    updateStrengthMeter(password);
};

const generateRandomPassword = (length, hasUpper, hasLower, hasNumbers, hasSymbols) => {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let chars = '';
    if (hasUpper) chars += upper;
    if (hasLower) chars += lower;
    if (hasNumbers) chars += numbers;
    if (hasSymbols) chars += symbols;

    if (!chars) {
        chars = lower;
        document.getElementById('lowercase').checked = true;
    }

    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return password;
};

const generateMemorablePassword = () => {
    const adjective = WORDS.adjectives[Math.floor(Math.random() * WORDS.adjectives.length)];
    const noun = WORDS.nouns[Math.floor(Math.random() * WORDS.nouns.length)];
    const verb = WORDS.verbs[Math.floor(Math.random() * WORDS.verbs.length)];
    const number = Math.floor(Math.random() * 1000);
    return `${adjective}${noun}${verb}${number}`;
};

const generatePIN = (length) => {
    let pin = '';
    for (let i = 0; i < length; i++) {
        pin += Math.floor(Math.random() * 10);
    }
    return pin;
};

// Password strength calculation
const calculatePasswordStrength = (password) => {
    let strength = 0;
    let issues = [];
    
    // Length check
    if (password.length < 8) {
        issues.push('Password is too short (minimum 8 characters)');
    } else {
        strength += password.length > 12 ? 2 : 1;
    }

    // Character type checks
    if (!/[A-Z]/.test(password)) {
        issues.push('Missing uppercase letters');
    } else {
        strength += 1;
    }

    if (!/[a-z]/.test(password)) {
        issues.push('Missing lowercase letters');
    } else {
        strength += 1;
    }

    if (!/[0-9]/.test(password)) {
        issues.push('Missing numbers');
    } else {
        strength += 1;
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
        issues.push('Missing special characters');
    } else {
        strength += 1;
    }

    // Check for common patterns
    if (/^[A-Za-z]+\d+$/.test(password)) {
        issues.push('Simple pattern: letters followed by numbers');
        strength -= 1;
    }

    if (/(.)\1{2,}/.test(password)) {
        issues.push('Repeated characters detected');
        strength -= 1;
    }

    const normalizedStrength = Math.max(0, Math.min(100, (strength / 6) * 100));
    return { strength: normalizedStrength, issues };
};

// Update strength meter
const updateStrengthMeter = (password) => {
    const { strength, issues } = calculatePasswordStrength(password);
    const bar = document.querySelector('.strength-bar');
    const text = document.querySelector('.strength-text');

    bar.style.setProperty('--strength', `${strength}%`);
    
    if (strength < 40) {
        bar.style.setProperty('--strength-color', 'var(--danger)');
        text.textContent = 'Weak Password';
    } else if (strength < 70) {
        bar.style.setProperty('--strength-color', 'var(--warning)');
        text.textContent = 'Moderate Password';
    } else {
        bar.style.setProperty('--strength-color', 'var(--success)');
        text.textContent = 'Strong Password';
    }

    // Update health check
    state.passwordHealth.issues = issues;
    updateHealthScore();
};

// Password Health
const updateHealthScore = () => {
    const passwords = Object.values(state.passwords || {});
    let totalScore = 0;
    let totalIssues = [];

    passwords.forEach(data => {
        const { strength, issues } = calculatePasswordStrength(data.password);
        totalScore += strength;
        totalIssues.push(...issues);
    });

    const averageScore = passwords.length ? Math.round(totalScore / passwords.length) : 0;
    state.passwordHealth.score = averageScore;
    state.passwordHealth.issues = [...new Set(totalIssues)];

    document.getElementById('healthScore').textContent = averageScore;
    
    const issuesList = document.getElementById('issuesList');
    issuesList.innerHTML = state.passwordHealth.issues.length ? 
        state.passwordHealth.issues.map(issue => `<div class="issue-item">${issue}</div>`).join('') :
        '<div class="no-issues">No security issues found</div>';
};

// Save password
const savePassword = async (url, username, password, notes, profile) => {
    const savedPasswords = await chrome.storage.sync.get('passwords') || {};
    const passwords = savedPasswords.passwords || {};
    
    passwords[url] = {
        username,
        password,
        notes,
        profile,
        timestamp: Date.now()
    };

    await chrome.storage.sync.set({ passwords });
    loadSavedPasswords();
    updateHealthScore();
};

// Load saved passwords
const loadSavedPasswords = async () => {
    const passwordsList = document.getElementById('passwordsList');
    const { passwords = {} } = await chrome.storage.sync.get('passwords');
    state.passwords = passwords;
    
    passwordsList.innerHTML = '';
    
    Object.entries(passwords).forEach(([url, data]) => {
        const item = document.createElement('div');
        item.className = 'password-item';
        item.innerHTML = `
            <div class="site-info">
                <div class="site-url">${url}</div>
                <div class="username">${data.username}</div>
            </div>
            <div class="actions">
                <button class="copy-btn" data-password="${data.password}">
                    <span class="material-icons">content_copy</span>
                </button>
                <button class="view-btn" data-url="${url}">
                    <span class="material-icons">visibility</span>
                </button>
                <button class="delete-btn" data-url="${url}">
                    <span class="material-icons">delete</span>
                </button>
            </div>
        `;
        
        const profileColor = state.profiles[data.profile || 'personal'].color;
        item.style.borderLeft = `4px solid ${profileColor}`;
        
        passwordsList.appendChild(item);
    });

    // Add event listeners
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            navigator.clipboard.writeText(e.target.closest('.copy-btn').dataset.password);
            const icon = e.target.closest('.copy-btn').querySelector('.material-icons');
            icon.textContent = 'check';
            setTimeout(() => {
                icon.textContent = 'content_copy';
            }, 1000);
        });
    });

    document.querySelectorAll('.view-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const url = e.target.closest('.view-btn').dataset.url;
            const data = passwords[url];
            showPasswordDetails(url, data);
        });
    });

    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const url = e.target.closest('.delete-btn').dataset.url;
            if (confirm('Are you sure you want to delete this password?')) {
                delete passwords[url];
                await chrome.storage.sync.set({ passwords });
                loadSavedPasswords();
                updateHealthScore();
            }
        });
    });
};

// Profile management
const initializeProfiles = async () => {
    const { profiles = {} } = await chrome.storage.sync.get('profiles');
    state.profiles = profiles;
    
    const profilesList = document.getElementById('profilesList');
    profilesList.innerHTML = Object.entries(profiles).map(([id, profile]) => `
        <div class="profile-item">
            <div class="profile-info">
                <div class="profile-color" style="background-color: ${profile.color}"></div>
                <div class="profile-details">
                    <div class="profile-name">${profile.name}</div>
                    <div class="profile-stats">
                        ${countPasswordsForProfile(id)} passwords
                    </div>
                </div>
            </div>
            <div class="profile-actions">
                <button class="profile-action-btn edit" data-profile-id="${id}" title="Edit Profile">
                    <span class="material-icons">edit</span>
                </button>
                <button class="profile-action-btn delete" data-profile-id="${id}" title="Delete Profile">
                    <span class="material-icons">delete</span>
                </button>
            </div>
        </div>
    `).join('') || '<div class="empty-state">No profiles yet. Add your first profile!</div>';

    // Add event listeners for profile actions
    document.querySelectorAll('.profile-action-btn.edit').forEach(btn => {
        btn.addEventListener('click', () => editProfile(btn.dataset.profileId));
    });

    document.querySelectorAll('.profile-action-btn.delete').forEach(btn => {
        btn.addEventListener('click', () => deleteProfile(btn.dataset.profileId));
    });
};

const countPasswordsForProfile = (profileId) => {
    return Object.values(state.passwords || {}).filter(p => p.profile === profileId).length;
};

const showAddProfileModal = () => {
    document.getElementById('addProfileModal').classList.add('active');
    document.querySelectorAll('.color-option').forEach(option => {
        option.addEventListener('click', () => {
            document.querySelectorAll('.color-option').forEach(opt => opt.classList.remove('selected'));
            option.classList.add('selected');
            document.getElementById('profileColor').value = option.dataset.color;
        });
    });
    // Select the first color by default
    document.querySelector('.color-option').click();
};

const hideAddProfileModal = () => {
    document.getElementById('addProfileModal').classList.remove('active');
    document.getElementById('addProfileForm').reset();
};

const createProfile = async (name, color) => {
    const id = 'profile_' + Date.now();
    const { profiles = {} } = await chrome.storage.sync.get('profiles');
    
    profiles[id] = {
        name,
        color,
        createdAt: Date.now()
    };

    await chrome.storage.sync.set({ profiles });
    state.profiles = profiles;
    initializeProfiles();
};

const editProfile = async (profileId) => {
    const profile = state.profiles[profileId];
    if (!profile) return;

    document.getElementById('profileName').value = profile.name;
    document.getElementById('profileColor').value = profile.color;
    document.querySelectorAll('.color-option').forEach(option => {
        if (option.dataset.color === profile.color) {
            option.click();
        }
    });

    showAddProfileModal();
    const form = document.getElementById('addProfileForm');
    form.dataset.editProfileId = profileId;
};

const deleteProfile = async (profileId) => {
    if (!confirm('Are you sure you want to delete this profile? All passwords will be moved to the Personal profile.')) {
        return;
    }

    const { profiles = {}, passwords = {} } = await chrome.storage.sync.get(['profiles', 'passwords']);
    
    // Move passwords to Personal profile
    Object.entries(passwords).forEach(([url, data]) => {
        if (data.profile === profileId) {
            passwords[url] = { ...data, profile: 'personal' };
        }
    });

    // Delete the profile
    delete profiles[profileId];
    
    await chrome.storage.sync.set({ profiles, passwords });
    state.profiles = profiles;
    state.passwords = passwords;
    
    initializeProfiles();
    loadSavedPasswords();
};

// Modal functionality
const showModal = (modalId) => {
    document.getElementById(modalId).classList.add('active');
};

const hideModal = (modalId) => {
    document.getElementById(modalId).classList.remove('active');
};

// Add Password button click
document.getElementById('addPassword').addEventListener('click', () => {
    showModal('addPasswordModal');
});

// Cancel Add Password button click
document.getElementById('cancelAdd').addEventListener('click', () => {
    hideModal('addPasswordModal');
});

// Add Password Form submission
document.getElementById('addPasswordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('websiteUrl').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const notes = document.getElementById('notes').value;
    const profile = document.getElementById('profileSelect').value;
    
    await savePassword(url, username, password, notes, profile);
    hideModal('addPasswordModal');
    e.target.reset();
});

// Password visibility toggle
document.querySelector('.toggle-password').addEventListener('click', function() {
    const passwordInput = document.getElementById('password');
    const icon = this.querySelector('.material-icons');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.textContent = 'visibility';
    } else {
        passwordInput.type = 'password';
        icon.textContent = 'visibility_off';
    }
});

// Close password modal when clicking outside
document.getElementById('addPasswordModal').addEventListener('click', (e) => {
    if (e.target.id === 'addPasswordModal') {
        hideModal('addPasswordModal');
    }
});

// Profile management
document.getElementById('addProfile').addEventListener('click', showAddProfileModal);
document.getElementById('cancelAddProfile').addEventListener('click', hideAddProfileModal);

document.getElementById('addProfileForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('profileName').value;
    const color = document.getElementById('profileColor').value;
    const editProfileId = e.target.dataset.editProfileId;

    if (editProfileId) {
        // Edit existing profile
        const { profiles = {} } = await chrome.storage.sync.get('profiles');
        profiles[editProfileId] = {
            ...profiles[editProfileId],
            name,
            color,
            updatedAt: Date.now()
        };
        await chrome.storage.sync.set({ profiles });
        state.profiles = profiles;
        delete e.target.dataset.editProfileId;
    } else {
        // Create new profile
        await createProfile(name, color);
    }

    hideAddProfileModal();
    initializeProfiles();
});

// Close profile modal when clicking outside
document.getElementById('addProfileModal').addEventListener('click', (e) => {
    if (e.target.id === 'addProfileModal') {
        hideAddProfileModal();
    }
});

// Update profile select in add password form when profiles change
const updateProfileSelect = () => {
    const profileSelect = document.getElementById('profileSelect');
    profileSelect.innerHTML = Object.entries(state.profiles).map(([id, profile]) => `
        <option value="${id}" ${id === state.currentProfile ? 'selected' : ''}>
            ${profile.name}
        </option>
    `).join('');
};

// Event Listeners
document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', () => {
        const tab = button.dataset.tab;
        
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        button.classList.add('active');

        document.querySelectorAll('.tab-content').forEach(content => {
            content.style.display = 'none';
        });
        document.getElementById(tab).style.display = 'block';

        if (tab === 'passwords') {
            loadSavedPasswords();
            updateProfileSelect();
        } else if (tab === 'profiles') {
            initializeProfiles();
        } else if (tab === 'health') {
            updateHealthScore();
        }
    });
});

document.querySelectorAll('.type-button').forEach(button => {
    button.addEventListener('click', () => {
        state.generationType = button.dataset.type;
        document.querySelectorAll('.type-button').forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        generatePassword();
    });
});

document.getElementById('regeneratePassword').addEventListener('click', generatePassword);
document.getElementById('copyPassword').addEventListener('click', () => {
    const password = document.getElementById('generatedPassword').value;
    navigator.clipboard.writeText(password);
    
    const button = document.getElementById('copyPassword');
    const icon = button.querySelector('.material-icons');
    icon.textContent = 'check';
    setTimeout(() => {
        icon.textContent = 'content_copy';
    }, 1000);
});

document.getElementById('length').addEventListener('input', (e) => {
    document.getElementById('lengthValue').textContent = e.target.value;
    generatePassword();
});

['uppercase', 'lowercase', 'numbers', 'symbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', generatePassword);
});

// Password breach check functionality
const sha1 = async (str) => {
    const msgBuffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
};

const checkPasswordBreach = async (password) => {
    try {
        const hash = await sha1(password);
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const text = await response.text();
        const breachData = text.split('\n').map(line => line.split(':'));
        const match = breachData.find(([hashSuffix]) => hashSuffix.trim() === suffix);
        
        return match ? parseInt(match[1]) : 0;
    } catch (error) {
        console.error('Error checking password breach:', error);
        return 0;
    }
};

const checkPasswordBreaches = async () => {
    const button = document.getElementById('checkBreaches');
    button.disabled = true;
    button.innerHTML = '<span class="material-icons">hourglass_empty</span> Checking...';

    try {
        const { passwords = {} } = await chrome.storage.sync.get('passwords');
        const issues = [];
        let totalBreaches = 0;

        // Check each password
        for (const [url, data] of Object.entries(passwords)) {
            const breachCount = await checkPasswordBreach(data.password);
            
            if (breachCount > 0) {
                issues.push(`Password for ${url} has been found in ${breachCount.toLocaleString()} data breaches`);
                totalBreaches += breachCount;
            }

            // Check password strength
            if (data.password.length < 12) {
                issues.push(`Password for ${url} is too short (minimum 12 characters recommended)`);
            }
            if (!/[A-Z]/.test(data.password)) {
                issues.push(`Password for ${url} is missing uppercase letters`);
            }
            if (!/[a-z]/.test(data.password)) {
                issues.push(`Password for ${url} is missing lowercase letters`);
            }
            if (!/[0-9]/.test(data.password)) {
                issues.push(`Password for ${url} is missing numbers`);
            }
            if (!/[^A-Za-z0-9]/.test(data.password)) {
                issues.push(`Password for ${url} is missing special characters`);
            }
        }

        // Update health score based on breaches and issues
        const passwordCount = Object.keys(passwords).length;
        if (passwordCount === 0) {
            state.passwordHealth.score = 0;
            state.passwordHealth.issues = ['No passwords stored yet'];
        } else {
            // Calculate health score (0-100)
            const baseScore = 100;
            const breachPenalty = Math.min(50, (totalBreaches > 0 ? 30 : 0) + (totalBreaches / 100));
            const issuePenalty = Math.min(50, (issues.length / passwordCount) * 10);
            state.passwordHealth.score = Math.max(0, Math.round(baseScore - breachPenalty - issuePenalty));
            state.passwordHealth.issues = issues.length > 0 ? issues : ['No security issues found'];
        }

        // Update UI
        document.getElementById('healthScore').textContent = state.passwordHealth.score;
        const issuesList = document.getElementById('issuesList');
        issuesList.innerHTML = state.passwordHealth.issues.map(issue => `
            <div class="issue-item">
                <span class="material-icons">${issue.includes('breach') ? 'warning' : 'info'}</span>
                <span>${issue}</span>
            </div>
        `).join('');

        // Add CSS classes based on score
        const scoreCircle = document.querySelector('.score-circle');
        scoreCircle.className = 'score-circle';
        if (state.passwordHealth.score >= 80) {
            scoreCircle.classList.add('good');
        } else if (state.passwordHealth.score >= 60) {
            scoreCircle.classList.add('moderate');
        } else {
            scoreCircle.classList.add('poor');
        }

    } catch (error) {
        console.error('Error in password health check:', error);
        state.passwordHealth.issues = ['Error checking password breaches. Please try again.'];
        updateHealthScore();
    } finally {
        button.disabled = false;
        button.innerHTML = '<span class="material-icons">security</span> Check for Breaches';
    }
};

// Add event listener for breach check button
document.getElementById('checkBreaches').addEventListener('click', checkPasswordBreaches);

// Initialize
generatePassword();
loadSavedPasswords();
initializeProfiles().then(() => {
    updateProfileSelect();
}); 