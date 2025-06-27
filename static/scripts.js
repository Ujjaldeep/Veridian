/* scripts.js */
console.log('scripts.js loaded');

document.addEventListener('DOMContentLoaded', () => {
    console.log('scripts.js: DOMContentLoaded fired');

    // Check authentication status for protected pages
    const protectedPages = ['/dashboard', '/update'];
    if (protectedPages.includes(window.location.pathname)) {
        fetch('/check-auth', {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            if (!data.authenticated) {
                console.log('scripts.js: User not authenticated, redirecting to login');
                window.location.replace('/login');
            }
        })
        .catch(error => {
            console.error('scripts.js: Error checking auth status:', error);
            window.location.replace('/login');
        });
    }

    // Theme toggle logic
    const body = document.body;
    const currentTheme = localStorage.getItem('theme') || 'light';
    body.setAttribute('theme', currentTheme);

    const themeToggleButton = document.getElementById('theme-toggle-button');

    if (themeToggleButton) {
        console.log('scripts.js: Theme toggle button found.');
        themeToggleButton.addEventListener('click', () => {
            console.log('scripts.js: Theme toggle button clicked.');
            const newTheme = body.getAttribute('theme') === 'dark' ? 'light' : 'dark';
            body.setAttribute('theme', newTheme);
            localStorage.setItem('theme', newTheme); // Save theme preference
            console.log('scripts.js: Theme set to', newTheme);
        });
    } else {
        console.error('scripts.js: Theme toggle button not found. Ensure an element with id="theme-toggle-button" exists.');
    }

    // Password generation function
    function generatePassword(length = 12) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%_+.-';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    }

    // Handle generate password buttons
    const generateButtons = document.querySelectorAll('.generate-btn');
    generateButtons.forEach(button => {
        const form = button.closest('form');
        if (!form) {
            console.error('Generate button not inside a form:', button);
            return;
        }
        const passwordInput = form.querySelector('input[type="password"]');
        if (!passwordInput) {
            console.error('Password input not found in form:', form);
            return;
        }
        button.addEventListener('click', () => {
            passwordInput.value = generatePassword();
            console.log('Generated password for:', passwordInput.id);
            const errorSpan = form.querySelector('.password-error');
            if (errorSpan) errorSpan.textContent = '';
            passwordInput.classList.remove('invalid');
        });
    });

    // Handle show password checkboxes in forms
    const showCheckboxes = document.querySelectorAll('.show-password input[type="checkbox"]');
    showCheckboxes.forEach(checkbox => {
        const form = checkbox.closest('form');
        if (!form) {
            console.error('Show password checkbox not inside a form:', checkbox);
            return;
        }
        const passwordInput = form.querySelector('input[type="password"]');
        if (!passwordInput) {
            console.error('Password input not found in form:', form);
            return;
        }
        checkbox.addEventListener('change', () => {
            passwordInput.type = checkbox.checked ? 'text' : 'password';
            console.log('Toggled password visibility for:', passwordInput.id);
        });
    });

    // Handle show password checkboxes in table
    const tableShowCheckboxes = document.querySelectorAll('.show-password-table-checkbox');
    tableShowCheckboxes.forEach(checkbox => {
        const row = checkbox.closest('tr');
        if (!row) {
            console.error('Checkbox not inside a table row:', checkbox);
            return;
        }
        const passwordSpan = row.querySelector('.password-hidden');
        if (!passwordSpan) {
            console.error('Password span not found in row:', row);
            return;
        }
        checkbox.addEventListener('change', () => {
            passwordSpan.textContent = checkbox.checked ? passwordSpan.dataset.password : '********';
            console.log('Toggled table password visibility for index:', checkbox.dataset.index);
        });
    });

    // Validate inputs
    const usernameInputs = document.querySelectorAll('input[name="Username"]');
    const emailInputs = document.querySelectorAll('input[name="email"]');
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const uniqueKeyInputs = document.querySelectorAll('input[name="unique_key"]');
    const validUsernameRegex = /^[a-zA-Z0-9_@.]*$/;
    const validEmailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const validEmailCharRegex = /[a-zA-Z0-9._%+-@.]/;
    const validPasswordRegex = /^[A-Za-z0-9!@#$%_+.\-]*$/;
    const validUniqueKeyRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
    const minLength = 6;

    // Email validation for signup and login pages
    emailInputs.forEach(input => {
        const form = input.closest('form');
        const errorSpan = form.querySelector('.email-error') || document.createElement('span');
        errorSpan.className = 'email-error';
        input.parentNode.appendChild(errorSpan);

        input.addEventListener('keypress', (e) => {
            const char = e.key;
            if (!validEmailCharRegex.test(char)) {
                e.preventDefault();
                errorSpan.textContent = 'Only letters, numbers, and ._%+-@ allowed (e.g., user@domain.com)';
                input.classList.add('invalid');
                console.log(`Blocked invalid keypress '${char}' in email:`, input.name);
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData('text');
            const sanitizedData = pastedData.split('').filter(char => validEmailCharRegex.test(char)).join('');
            input.value = sanitizedData;
            validateEmail(input, errorSpan);
            console.log(`Sanitized pasted email in ${input.name}:`, sanitizedData);
        });

        input.addEventListener('input', () => {
            let value = input.value;
            if (value.split('').some(char => !validEmailCharRegex.test(char))) {
                input.value = value.split('').filter(char => validEmailCharRegex.test(char)).join('');
                errorSpan.textContent = 'Only letters, numbers, and ._%+-@ allowed (e.g., user@domain.com)';
                input.classList.add('invalid');
            } else if (!validEmailRegex.test(value)) {
                errorSpan.textContent = 'Invalid email format';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        });

        input.addEventListener('blur', () => {
            validateEmail(input, errorSpan);
        });

        function validateEmail(input, errorSpan) {
            let value = input.value;
            if (!value) {
                errorSpan.textContent = 'Email is required';
                input.classList.add('invalid');
            } else if (value.split('').some(char => !validEmailCharRegex.test(char))) {
                input.value = value.split('').filter(char => validEmailCharRegex.test(char)).join('');
                errorSpan.textContent = 'Only letters, numbers, and ._%+-@ allowed (e.g., user@domain.com)';
                input.classList.add('invalid');
            } else if (!validEmailRegex.test(value)) {
                errorSpan.textContent = 'Please enter a valid email address (e.g., user@domain.com)';
                input.classList.add('invalid');
            } else if (!value.includes('@') || !value.includes('.') || value.split('@').length !== 2 || value.split('@')[1].indexOf('.') === -1) {
                errorSpan.textContent = 'Email must include @ and a valid domain (e.g., user@domain.com)';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        }
    });

    // Username validation
    usernameInputs.forEach(input => {
        const form = input.closest('form');
        const errorSpan = form.querySelector('.username-error') || document.createElement('span');
        errorSpan.className = 'username-error';
        input.parentNode.appendChild(errorSpan);

        input.addEventListener('keypress', (e) => {
            const char = e.key;
            if (!validUsernameRegex.test(char)) {
                e.preventDefault();
                errorSpan.textContent = 'Only letters, numbers, underscores, @, or . allowed';
                input.classList.add('invalid');
                console.log(`Blocked invalid keypress '${char}' in username:`, input.name);
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData('text');
            const sanitizedData = pastedData.replace(/[^a-zA-Z0-9_@.]/g, '');
            input.value = sanitizedData;
            validateUsername(input, errorSpan);
            console.log(`Sanitized pasted username in ${input.name}:`, sanitizedData);
        });

        input.addEventListener('input', () => {
            let value = input.value;
            if (!validUsernameRegex.test(value)) {
                value = value.replace(/[^a-zA-Z0-9_@.]/g, '');
                input.value = value;
                errorSpan.textContent = 'Only letters, numbers, underscores, @, or . allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        });

        input.addEventListener('blur', () => {
            validateUsername(input, errorSpan);
        });

        function validateUsername(input, errorSpan) {
            let value = input.value;
            if (!validUsernameRegex.test(value)) {
                value = value.replace(/[^a-zA-Z0-9_@.]/g, '');
                input.value = value;
                errorSpan.textContent = 'Only letters, numbers, underscores, @, or . allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        }
    });

    // Password validation
    passwordInputs.forEach(input => {
        const form = input.closest('form');
        const errorSpan = form.querySelector('.password-error') || document.createElement('span');
        errorSpan.className = 'password-error';
        input.parentNode.appendChild(errorSpan);

        input.addEventListener('keypress', (e) => {
            const char = e.key;
            if (!validPasswordRegex.test(char)) {
                e.preventDefault();
                errorSpan.textContent = 'Only letters, numbers, and !@#$%_+.- allowed';
                input.classList.add('invalid');
                console.log(`Blocked invalid keypress '${char}' in password:`, input.id);
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData('text');
            const sanitizedData = pastedData.replace(/[^A-Za-z0-9!@#$%_+.\-]/g, '');
            input.value = sanitizedData;
            validatePassword(input, errorSpan);
            console.log(`Sanitized pasted password in ${input.id}:`, sanitizedData);
        });

        input.addEventListener('input', () => {
            let value = input.value;
            if (!validPasswordRegex.test(value)) {
                value = value.replace(/[^A-Za-z0-9!@#$%_+.\-]/g, '');
                input.value = value;
                errorSpan.textContent = 'Only letters, numbers, and !@#$%_+.- allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        });

        input.addEventListener('blur', () => {
            validatePassword(input, errorSpan);
        });

        function validatePassword(input, errorSpan) {
            let value = input.value;
            if (!validPasswordRegex.test(value)) {
                value = value.replace(/[^A-Za-z0-9!@#$%_+.\-]/g, '');
                input.value = value;
                errorSpan.textContent = 'Only letters, numbers, and !@#$%_+.- allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        }
    });

    // Purpose validation
    const purposeInputs = document.querySelectorAll('input[name="Purpose"]');
    const validPurposeRegex = /^[a-zA-Z0-9 #\-_\/]*$/;

    purposeInputs.forEach(input => {
        const form = input.closest('form');
        const errorSpan = form.querySelector('.purpose-error') || document.createElement('span');
        errorSpan.className = 'purpose-error';
        input.parentNode.appendChild(errorSpan);

        input.addEventListener('keypress', (e) => {
            const char = e.key;
            if (!validPurposeRegex.test(char)) {
                e.preventDefault();
                errorSpan.textContent = 'Only letters, numbers, spaces, #, -, _, / allowed';
                input.classList.add('invalid');
            }
        });

        input.addEventListener('input', () => {
            const value = input.value;
            if (!validPurposeRegex.test(value)) {
                errorSpan.textContent = 'Only letters, numbers, spaces, #, -, _, / allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        });

        input.addEventListener('blur', () => {
            const value = input.value;
            if (!validPurposeRegex.test(value)) {
                input.value = value.replace(/[^a-zA-Z0-9 #\-_\/]/g, '');
                errorSpan.textContent = 'Only letters, numbers, spaces, #, -, _, / allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        });
    });

});