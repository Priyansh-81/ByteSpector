# ByteSpector  
**A Web-Based Toolkit for Data Manipulation, Steganography, and Forensic Analysis**

---

## Overview  
ByteSpector is a unified, web-based toolkit designed for security analysts, penetration testers, and digital forensics investigators.  
It integrates a CyberChef-style data transformation engine with advanced steganography and steganalysis capabilities, providing a single platform for a wide range of security tasks.

---

## Features  

### Data Transformation  
- Perform operations like Base64/Hex encoding and decoding.  
- Generate MD5 and SHA-256 hashes.  
- Execute XOR and other logical operations.  

### Steganography  
- Embed secret messages into image files (PNG, JPEG).  
- Extract hidden data using the Least Significant Bit (LSB) technique.  

### Forensic Analysis  
- Detect hidden data in images using an LSB Visualizer.  
- Identify true file types with a Magic Byte Analyzer.  

---

## Technology Stack  

### Backend  
- **Language:** Python 3.8+  
- **Framework:** Flask / FastAPI (as implied by `server.py`)  
- **Core Libraries:** Pillow, NumPy, PyCryptodome, piexif  

### Frontend  
- **Structure:** Vanilla HTML, CSS, and JavaScript  
- **Pages:** Separate static HTML files for each module (Cryptography, Forensics, Steganography) served directly to the browser.  

---

## Getting Started  

This guide will help you set up the project on your local machine.

### Prerequisites  
- Python 3.8 or higher  
- Git  
- A modern web browser (Google Chrome, Mozilla Firefox, etc.)

---

## Installation & Setup  

### 1. Clone the Repository  
```bash
git clone <YOUR_REPOSITORY_URL>
cd BYTESPECTOR
```

### 2. Set Up the Backend  
Navigate to the backend directory:
```bash
cd Backend
```

#### (Recommended) Create and Activate a Virtual Environment  

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

#### Install Dependencies  
If you have a `requirements.txt` file:
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install Flask Pillow Numpy PyCryptodome piexif
```

---

## Usage  

The project runs in two parts:  
1. The backend server must be running.  
2. The frontend file must be opened in a web browser.

### Run the Backend Server  
From the `Backend` folder:
```bash
python server.py
```
This will start the backend server, typically on **http://127.0.0.1:5000**.

### Launch the Frontend  
1. Navigate to the `Frontend` directory.  
2. Open `home (1).html` directly in your browser  
   (Right-click → "Open with" → "Google Chrome").  

The web interface will load, and the JavaScript on the page will make API calls to your local backend server running at `127.0.0.1:5000`.

---

## Project Structure  
```
BYTESPECTOR/
├── .vscode/
├── App/
├── Backend/
│   ├── temp_uploads/
│   ├── uploads/
│   ├── venv/
│   └── server.py
├── Frontend/
│   ├── CSS/
│   │   ├── about.css
│   │   ├── cryptography.css
│   │   ├── forensics.css
│   │   ├── home.css
│   │   └── steganography.css
│   ├── JS/
│   │   ├── cryptography.js
│   │   ├── forensics.js
│   │   └── steganography.js
│   ├── pages/
│   │   ├── about.html
│   │   ├── cryptography.html
│   │   ├── forensics.html
│   │   └── steganography.html
│   └── home (1).html
├── Documentation/
└── README.md
```

---

## Authors  
- Yukti Bhatia  
- Priyansh Nandan  

---

## Acknowledgments  
This project was submitted to the **Manipal Institute of Technology (MAHE)** for the **Bachelor of Technology in Computer and Communication Engineering**,  
guided by **Dr. Raviraj Holla** and **Mr. Yogesh Ganapati Chandavakar**.
