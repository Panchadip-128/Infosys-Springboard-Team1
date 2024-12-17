const validEmail = "user@gmail.com";
const validPassword = "1234";
document.querySelector("form").addEventListener("submit", function(event) {
    event.preventDefault(); 
    const email = document.getElementById("phone-email").value;
    const password = document.getElementById("password").value;
    if (email === validEmail && password === validPassword) {
        window.location.href = "successin.html";
    } else {
        alert("Invalid email or password. Please try again.");
    }
});
