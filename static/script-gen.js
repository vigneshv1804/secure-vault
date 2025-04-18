const passwordInput = document.getElementById("password");
const copyButton = document.getElementById("copy-btn");
const indicator = document.getElementById("indicator");
const lengthSlider = document.getElementById("length");
const lengthValue = document.getElementById("length-value");
const uppercaseCheckbox = document.getElementById("uppercase");
const lowercaseCheckbox = document.getElementById("lowercase");
const numbersCheckbox = document.getElementById("numbers");
const symbolsCheckbox = document.getElementById("symbols");
const generateButton = document.getElementById("generate");

// Character sets
const uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
const numberChars = "0123456789";
const symbolChars = "!@#$%^&*()_+=-`~[]{}|;':\",./<>?";

// Function to generate password
function generatePassword() {
  const length = lengthSlider.value;
  let chars = "";

  if (uppercaseCheckbox.checked) chars += uppercaseChars;
  if (lowercaseCheckbox.checked) chars += lowercaseChars;
  if (numbersCheckbox.checked) chars += numberChars;
  if (symbolsCheckbox.checked) chars += symbolChars;

  let password = "";
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  passwordInput.value = password;
  updateStrengthIndicator(password);
}

// Function to update strength indicator
function updateStrengthIndicator(password) {
  const strength = calculateStrength(password);

  if (strength > 80) {
    indicator.textContent = "Very strong";
    indicator.style.backgroundColor = "#4CAF50"; // Green
  } else if (strength > 50) {
    indicator.textContent = "Strong";
    indicator.style.backgroundColor = "#FFC107"; // Amber/Yellow
  } else {
    indicator.textContent = "Weak";
    indicator.style.backgroundColor = "#F44336"; // Red
  }
}

// Function to calculate password strength (basic example)
function calculateStrength(password) {
  let score = password.length * 4; // Base score: 4 points per character

  // Add points for different character types
  if (/[a-z]/.test(password)) score += 10; // Lowercase
  if (/[A-Z]/.test(password)) score += 10; // Uppercase
  if (/[0-9]/.test(password)) score += 10; // Numbers
  if (/[^a-zA-Z0-9]/.test(password)) score += 15; // Symbols

  return Math.min(score, 100); // Cap at 100
}

// Event listeners
copyButton.addEventListener("click", () => {
  passwordInput.select();
  document.execCommand("copy");
});

lengthSlider.addEventListener("input", () => {
  lengthValue.textContent = lengthSlider.value;
  generatePassword(); // Update password on length change
});

[
  uppercaseCheckbox,
  lowercaseCheckbox,
  numbersCheckbox,
  symbolsCheckbox,
].forEach((checkbox) => {
  checkbox.addEventListener("change", generatePassword);
});

generateButton.addEventListener("click", generatePassword);

// Initial password generation
generatePassword();
