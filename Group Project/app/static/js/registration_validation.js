document.addEventListener('DOMContentLoaded', function () {
    const passwordInput = document.querySelector('input[name="password"]');
    const confirmPasswordInput = document.querySelector('input[name="confirm_password"]');
    const emailInput = document.querySelector('input[name="email"]');
    
    const criteria = {
        uppercase: document.getElementById('uppercase'),
        lowercase: document.getElementById('lowercase'),
        digit: document.getElementById('digit'),
        special: document.getElementById('special'),
        noSpaces: document.getElementById('no-spaces'),
        minLength: document.getElementById('min-length'),
        passwordMatch: document.getElementById('password-match')
    };

    passwordInput.addEventListener('input', validatePassword);
    confirmPasswordInput.addEventListener('input', validatePasswordMatch);
    emailInput.addEventListener('input', validateEmail);

    function validatePassword() {
        const password = passwordInput.value;

        criteria.uppercase.classList.toggle('valid', /[A-Z]/.test(password));
        criteria.uppercase.classList.toggle('invalid', !/[A-Z]/.test(password));

        criteria.lowercase.classList.toggle('valid', /[a-z]/.test(password));
        criteria.lowercase.classList.toggle('invalid', !/[a-z]/.test(password));

        criteria.digit.classList.toggle('valid', /\d/.test(password));
        criteria.digit.classList.toggle('invalid', !/\d/.test(password));

        criteria.special.classList.toggle('valid', /[!@
        criteria.special.classList.toggle('invalid', !/[!@

        criteria.noSpaces.classList.toggle('valid', !/\s/.test(password));
        criteria.noSpaces.classList.toggle('invalid', /\s/.test(password));

        criteria.minLength.classList.toggle('valid', password.length >= 8);
        criteria.minLength.classList.toggle('invalid', password.length < 8);

        validatePasswordMatch();
    }

    function validatePasswordMatch() {
        const passwordsMatch = passwordInput.value === confirmPasswordInput.value;
        criteria.passwordMatch.classList.toggle('valid', passwordsMatch);
        criteria.passwordMatch.classList.toggle('invalid', !passwordsMatch);
    }

    function validateEmail() {
        const email = emailInput.value;
        const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

        document.getElementById('email-validity').classList.toggle('valid', isValid);
        document.getElementById('email-validity').classList.toggle('invalid', !isValid);
    }
});
