# Advanced Password Strength Analyzer Dashboard

A modern cybersecurity-focused application that evaluates password strength using entropy calculation, pattern detection, and real-time feedback. The project features a responsive dashboard with dark/light mode, strength visualization, and intelligent suggestions to help users create secure passwords.

---

## Features

* Entropy-based password strength analysis
* Detection of common passwords and weak patterns
* Regex-based validation for:

  * Uppercase & lowercase letters
  * Numbers
  * Special characters
* Real-time strength indicator (Weak → Strong)
* Smart suggestions to improve password security
* Dark Mode / Light Mode toggle
* Responsive and user-friendly dashboard UI

---

## Tech Stack

**Frontend:**

* HTML
* CSS (Tailwind / Custom styles)
* JavaScript

**Backend:**

* Python

**Concepts Used:**

* Cybersecurity fundamentals
* Entropy calculation
* Pattern detection
* Regular Expressions (Regex)

---

## Project Structure

```
password-strength-analyzer/
│
├── backend/
│   └── main.py
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── README.md
└── requirements.txt
```

---

## How It Works

1. User enters a password in the dashboard
2. The system analyzes:

   * Length and character diversity
   * Presence of predictable patterns
   * Entropy score
3. Password is classified as:

   * Very Weak
   * Weak
   * Medium
   * Strong
   * Very Strong
4. Suggestions are provided to improve security

---

## Example Output

```
Password: hello123

Strength: Weak  
Entropy: 36.54 bits  

Suggestions:
- Add uppercase letters  
- Include special characters  
- Avoid predictable patterns  
```

---

## Installation & Setup

1. Clone the repository:

```
git clone https://github.com/shreyas-blr/password-strength-analyzer.git
```

2. Navigate to the project folder:

```
cd password-strength-analyzer
```

3. Run the Python backend:

```
python main.py
```

4. Open the frontend:

* Open `index.html` in your browser

---

## Future Enhancements

* Flask integration for full web application
* Database (SQLite) for storing password analysis logs
* Password generator feature
* Real-time API-based validation
* User authentication system

---

## Learning Outcomes

* Applied cybersecurity concepts in a real project
* Improved understanding of password vulnerabilities
* Built a responsive UI with modern design principles
* Integrated backend logic with frontend visualization

---

## Author

Developed as part of the SkillCraft Technology Cybersecurity Internship.

---

## License

This project is open-source and available under the MIT License.
