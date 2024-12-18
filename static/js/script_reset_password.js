document.querySelector('form').addEventListener('submit', function (e) {
    e.preventDefault();
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    const passwordFormat = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (newPassword && confirmPassword) {
        if (!passwordFormat.test(newPassword)) {
            alert('Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.');
        } else if (newPassword !== confirmPassword) {
            alert('Passwords do not match. Please try again.');
        } else {
            alert('Password reset successful!');
            // Add your form submission logic here
        }
    } else {
        alert('Please fill in both fields.');
    }
});