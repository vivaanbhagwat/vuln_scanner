# 🛡️ CyberShield - Automated Vulnerability Scanner

CyberShield is a premium, web-based vulnerability scanning platform designed for offensive security auditing. It combines a modern, high-performance glassmorphism interface with a modular backend focused on detecting critical security flaws.

---

## 🚀 How It Works

CyberShield operates as a multi-threaded auditing tool. Once a target URL is provided, the platform initiates a series of specialized security probes:

1.  **Passive Discovery**: Analyzes headers, robots.txt, and server fingerprints without intrusive interaction.
2.  **Active Probing**: Tests forms, inputs, and URL parameters for common injection points (SQLi, XSS, CSRF).
3.  **Advanced Auditing**: Utilizes specialized modules for AI-driven SQL Injection detection, brute-force simulations, and insecure CORS configurations.
4.  **Reporting**: Aggregates findings into a visual dashboard and generates downloadable PDF reports for stakeholders.

---

## 🛠️ Key Modules & Capabilities

The scanner is built on a modular architecture located in `modules/scanner/`:
- **Injection Audit**: `ai_sqli.py`, `sqli.py`, `xss.py`, `command_injection.py`.
- **Auth & Access**: `brute_force.py`, `csrf_analyzer.py`, `cookie_security.py`.
- **Infrastructure**: `dns_security.py`, `ports.py`, `https_check.py`, `headers.py`.
- **Configuration**: `insecure_cors.py`, `robots_analyzer.py`, `server_fingerprint.py`.

---

## 📂 Project Structure (Required Files)

To ensure the scanner functions correctly, the following directory structure must be maintained:
- `app.py`: Main application entry point.
- `routes/`: Blueprint definitions for Auth, Admin, and Scan logic.
- `models/`: Database schemas for Users, Scans, and Reports.
- `modules/`: The core engine, including `report_generator.py` and `scan_engine.py`.
- `static/`: CSS (Premium styles), JS, and Image assets.
- `templates/`: HTML structure for all pages (Dashboard, Auth, Admin).
- `requirements.txt`: Python dependencies.
- `start.bat`: Convenience script for Windows execution.

---

## 📦 Required Components

To run CyberShield, you need the following dependencies (detailed in `requirements.txt`):
- **Core**: Python 3.12.7, Flask (Web Framework)
- **Database**: SQLite with SQLAlchemy (ORM)
- **Security**: Bcrypt (Password Hashing)
- **Scanning**: Requests, BeautifulSoup4
- **Reporting**: fpdf2 (PDF Generation)
- **Deployment**: Waitress (WSGI Server)

---

## 🚦 How to Start the Project

### Windows (Recommended)
Simply run the provided batch script:
```bash
.\start.bat
```

### Manual Setup
1.  **Extract Files**: Ensure all project files are in the same directory.
2.  **Initialize Environment**:
    ```bash
    python -m venv .venv
    .\.venv\Scripts\activate
    ```
3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
4.  **Launch Dashboard**:
    ```bash
    python app.py
    ```
5.  **Access**: Open `http://localhost:8080` in your browser.

---

## ⚠️ Disclaimer & Limitations

> [!WARNING]
> **LEGAL NOTICE**: This tool is for **EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY**. 
> Running this tool against targets without explicit written permission is illegal and unethical. The developer assumes no liability for misuse.

### Current Project Status
- **Development Version**: This project is **not 100% functional** currently. It serves as a proof-of-concept for automated security auditing.
- **Limited Scope**: Some modules use simulated payloads and may not catch all variants of vulnerabilities in production environments.
- **Experimental Features**: The AI-driven modules are currently in early-stage development.

---

## 👤 Admin Access
For the submission demonstration, the administrative panel is restricted to the following identity:
- **Email**: `viv08.bhagwat@gmail.com`
- **Access Key**: `viv.bhagwat@040208`
