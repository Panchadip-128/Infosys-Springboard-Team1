const form = document.querySelector('form');
const passwordField = document.getElementById('password');
const confirmPasswordField = document.getElementById('con-password');
form.addEventListener('submit', (event) => {
    event.preventDefault(); 
    const password = passwordField.value;
    const confirmPassword = confirmPasswordField.value;
    if (password === confirmPassword) {
        alert('Password changed successfully!');
        window.location.href = 'dashboard.html'; 
    } else {
        alert('Passwords do not match. Please try again.');
    }
});
