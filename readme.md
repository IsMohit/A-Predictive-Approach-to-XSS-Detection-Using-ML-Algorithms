# 🛡️ A Predictive Approach to XSS Detection Using ML Algorithms

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.13%2B-orange.svg)](https://www.tensorflow.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3%2B-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Ongoing-red.svg)]()

> **Note**: This project is currently under active development. Features and documentation are being continuously updated.

An intelligent Cross-Site Scripting (XSS) detection and prevention system powered by a hybrid CNN-LSTM deep learning architecture. This system provides real-time detection of malicious XSS payloads with 98%+ accuracy, offering robust protection against both standard and obfuscated attacks.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Training the Model](#training-the-model)
- [Running the Server](#running-the-server)
- [Using the Web Interface](#using-the-web-interface)
- [API Usage](#api-usage)
- [Testing Examples](#testing-examples)
- [Project Structure](#project-structure)
- [Model Performance](#model-performance)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)


## 🎯 Overview

Cross-Site Scripting (XSS) remains one of the most prevalent web security vulnerabilities. Traditional rule-based detection systems struggle with:
- Encoded and obfuscated payloads
- Novel attack vectors
- Context-aware attacks
- High false positive rates

Our solution leverages a **CNN-LSTM hybrid neural network** that:
- ✅ Learns patterns automatically from data
- ✅ Detects obfuscated and encoded attacks
- ✅ Adapts to new attack vectors through retraining
- ✅ Provides real-time detection with millisecond latency
- ✅ Achieves 98%+ accuracy with low false positive rate

### Why CNN-LSTM?

- **CNN (Convolutional Neural Network)**: Extracts local patterns like `<script>`, `onerror=`, `alert(`
- **LSTM (Long Short-Term Memory)**: Understands sequential context and relationships between patterns
- **Hybrid Approach**: Combines spatial pattern recognition with temporal sequence understanding

## ✨ Features

### Core Capabilities
- 🎯 **Real-time XSS Detection**: Sub-20ms inference time
- 🧠 **Deep Learning Powered**: CNN-LSTM hybrid architecture
- 🔒 **Input Sanitization**: Automatic cleaning of malicious content
- 🌐 **REST API**: Easy integration with any web application
- 📊 **Detailed Analytics**: Confidence scores and probability breakdown
- 📝 **Request Logging**: Track and analyze malicious attempts
- 🔄 **Batch Processing**: Check multiple inputs simultaneously

### Detection Capabilities
- Standard XSS patterns (`<script>alert(1)</script>`)
- Event handler injections (`<img onerror=alert(1)>`)
- Protocol-based attacks (`javascript:alert(1)`)
- Encoded payloads (URL encoding, HTML entities, Unicode)
- Obfuscated attacks (case mixing, whitespace injection)
- DOM-based XSS patterns
- Framework-specific injections

## 🏗️ Architecture

```
User Input → Flask API → Preprocessing → CNN-LSTM Model → Sanitization → Response
                ↓                              ↓
           Validation                    2.1M Parameters
                                        (Character-level)
```

### Model Architecture

```
Input (300 chars)
    ↓
Embedding (256D)
    ↓
┌─────────────────────┐
│  Parallel CNNs      │
│  - Kernel 3, 5, 7   │  ← Pattern Detection
│  - 128 filters each │
└──────────┬──────────┘
    ↓
Concatenate
    ↓
┌─────────────────────┐
│  Bidirectional LSTM │  ← Sequence Understanding
│  - 128 units        │
│  - 64 units         │
└──────────┬──────────┘
    ↓
Dense Layers (256→128→64)
    ↓
Output (Sigmoid)
[0=Safe, 1=Malicious]
```

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- 4GB RAM minimum (8GB recommended)
- 2GB free disk space

### Step 1: Clone Repository

```bash
git clone https://github.com/IsMohit/A-Predictive-Approach-to-XSS-Detection-Using-ML-Algorithms.git
cd A-Predictive-Approach-to-XSS-Detection-Using-ML-Algorithms
```

### Step 2: Create Virtual Environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
# Install all required packages
pip install -r requirements_cnn_lstm.txt
```

**Core Dependencies:**
- `tensorflow>=2.13.0` - Deep learning framework
- `scikit-learn>=1.3.0` - Machine learning utilities
- `flask>=2.3.0` - Web server
- `flask-cors>=4.0.0` - CORS support
- `pandas>=2.0.0` - Data manipulation
- `numpy>=1.24.0` - Numerical computing
- `bleach>=6.0.0` - HTML sanitization

## ⚡ Quick Start

### Complete Setup (5 minutes)

```bash
# 1. Activate virtual environment
source venv/bin/activate  # or venv\Scripts\activate on Windows


# 2. Train the model (takes 3-5 minutes)
python xss_cnn_lstm_trainer.py

# 3. Start the API server
python app_cnn_lstm.py

# 6. Open the web interface
# Open index.html in your browser
```

The API will be available at `http://localhost:5000`

## 🎓 Training the Model


### Option 1: Using Your Own Dataset

**Required Format:** CSV with two columns: `input` and `label`

```csv
input,label
Hello world,0
<script>alert(1)</script>,1
Welcome to our website,0
<img src=x onerror=alert(1)>,1
```

### Training Process

```bash
# Train the CNN-LSTM model
python xss_cnn_lstm_trainer.py
```


**Output Files:**
- `xss_cnn_lstm_model.h5` - Trained model (~80-100 MB)
- `tokenizer.pkl` - Character tokenizer (~1-5 MB)
- `xss_cnn_lstm_best.h5` - Best model checkpoint

## 🌐 Running the Server

### Development Server

```bash
# Start Flask development server
python app_cnn_lstm.py
```

**Output:**
```
🛡️  ML-Based XSS Detection API Server (CNN-LSTM)
================================================================================
📥 Loading CNN-LSTM model...
✅ CNN-LSTM model loaded successfully!

🚀 Starting Flask server...
📡 API will be available at: http://localhost:5000

 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

### Production Server

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn (production-ready)
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 app_cnn_lstm:app
```

**Server Configuration:**
- Workers: 4 (adjust based on CPU cores)
- Timeout: 120 seconds (for model loading)
- Host: 0.0.0.0 (accessible from all interfaces)
- Port: 5000

## 🖥️ Using the Web Interface

### Opening the Interface

1. **Start the API server** (see above)
2. **Open `index.html`** in your web browser
3. **Enter text** in the input field
4. **Click "Check for XSS"**


### Interface Sections

1. **Input Area**: Enter or paste text to check
2. **Action Buttons**: 
   - 🔍 Check for XSS
   - 🗑️ Clear input
3. **Results Display**:
   - Prediction (Safe/Malicious)
   - Confidence percentage
   - Probability breakdown
   - Sanitized output
   - Risk level (for malicious inputs)
4. **Example Buttons**: Quick test cases

## 📡 API Usage

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API documentation |
| `/health` | GET | Health check |
| `/check` | POST | Check single input |
| `/batch-check` | POST | Check multiple inputs |
| `/stats` | GET | View statistics |
| `/model-info` | GET | Model information |

### Examples

#### 1. Check Single Input

**Request:**
```bash
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"input": "<script>alert(1)</script>"}'
```

**Response:**
```json
{
  "prediction": "malicious",
  "confidence": 98.5,
  "sanitized": "",
  "probabilities": {
    "safe": 1.5,
    "malicious": 98.5
  },
  "warning": "Potential XSS attack detected by CNN-LSTM model!",
  "risk_level": "high",
  "model_used": "CNN-LSTM",
  "timestamp": "2025-10-26T12:00:00Z"
}
```

#### 2. Safe Input

**Request:**
```bash
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"input": "Hello, this is a normal comment"}'
```

**Response:**
```json
{
  "prediction": "safe",
  "confidence": 99.2,
  "sanitized": "Hello, this is a normal comment",
  "probabilities": {
    "safe": 99.2,
    "malicious": 0.8
  },
  "model_used": "CNN-LSTM",
  "timestamp": "2025-10-26T12:00:00Z"
}
```

#### 3. Batch Check

**Request:**
```bash
curl -X POST http://localhost:5000/batch-check \
  -H "Content-Type: application/json" \
  -d '{"inputs": ["Hello world", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]}'
```

**Response:**
```json
{
  "total": 3,
  "malicious_detected": 2,
  "safe_detected": 1,
  "model_used": "CNN-LSTM",
  "results": [
    {
      "index": 0,
      "prediction": "safe",
      "confidence": 99.1,
      "sanitized": "Hello world"
    },
    {
      "index": 1,
      "prediction": "malicious",
      "confidence": 98.5,
      "sanitized": ""
    },
    {
      "index": 2,
      "prediction": "malicious",
      "confidence": 97.8,
      "sanitized": ""
    }
  ]
}
```

#### 4. Python Integration

```python
import requests

def check_xss(user_input):
    """Check if input contains XSS"""
    response = requests.post(
        'http://localhost:5000/check',
        json={'input': user_input}
    )
    result = response.json()
    
    if result['prediction'] == 'malicious':
        print(f"⚠️ XSS Detected! Confidence: {result['confidence']}%")
        return False
    else:
        print(f"✅ Input is safe. Confidence: {result['confidence']}%")
        return True

# Example usage
user_comment = input("Enter your comment: ")
if check_xss(user_comment):
    # Save comment to database
    save_comment(user_comment)
else:
    print("Comment rejected due to security concerns")
```

#### 5. JavaScript Integration

```javascript
async function validateInput(input) {
    try {
        const response = await fetch('http://localhost:5000/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ input: input })
        });
        
        const data = await response.json();
        
        if (data.prediction === 'malicious') {
            alert(`⚠️ XSS Detected! Confidence: ${data.confidence}%`);
            return false;
        }
        
        return true;
    } catch (error) {
        console.error('Validation error:', error);
        return false; // Fail-safe
    }
}

// Usage in form validation
document.getElementById('submitBtn').addEventListener('click', async (e) => {
    e.preventDefault();
    const userInput = document.getElementById('commentField').value;
    
    if (await validateInput(userInput)) {
        document.getElementById('commentForm').submit();
    } else {
        showError('Your input contains potentially malicious content');
    }
});
```

## 🧪 Testing Examples

### Safe Inputs (Should NOT be flagged)

```python
safe_inputs = [
    "Hello, how are you today?",
    "Welcome to our website! Feel free to explore.",
    "Check out this article: https://example.com/article",
    "My email is contact@example.com",
    "The price is $50 < $100 for premium users",
    "Use the formula: (x < 5) && (y > 10)",
    "I love <3 your product!",
    "Our store: Bed & Breakfast Inn",
    "Code snippet: if (x) { console.log('done'); }",
    "Rating: 4.5/5 stars ⭐⭐⭐⭐"
]
```

### Basic Malicious Inputs (Should be flagged)

```python
basic_malicious = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<object data='javascript:alert(1)'>"
]
```

### Obfuscated/Advanced Attacks (Should be flagged)

```python
advanced_malicious = [
    # Mixed case
    "<ScRiPt>alert(1)</ScRiPt>",
    "<ImG sRc=x oNeRrOr=alert(1)>",
    
    # HTML entity encoding
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<img src=x onerror='&#97;&#108;&#101;&#114;&#116;(1)'>",
    
    # URL encoding
    "%3Cscript%3Ealert(1)%3C/script%3E",
    
    # Unicode encoding
    "<script>\\u0061lert(1)</script>",
    "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
    
    # Null byte injection
    "<scr\\x00ipt>alert(1)</scr\\x00ipt>",
    
    # Event handler variations
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    
    # JavaScript protocol variations
    "<a href='jaVasCript:alert(1)'>Click</a>",
    "<iframe src='jAvAsCrIpT:alert(1)'>",
    
    # Data protocol
    "<object data='data:text/html,<script>alert(1)</script>'>",
    "<iframe src='data:text/html,<script>alert(1)</script>'>",
    
    # Template literals
    "<img src=`x`onerror=`alert(1)`>",
    
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"
]
```

## 📊 Model Performance

### Metrics on Test Set

| Metric | Score | Details |
|--------|-------|---------|
| **Accuracy** | 98.46% | Overall correctness |
| **Precision** | 100.00% | True positives / All positives |
| **Recall** | 97.84% | True positives / All actual malicious |
| **F1-Score** | 0.9891 | Harmonic mean of precision and recall |
| **AUC** | 0.9964 | Area under ROC curve |

## 🔧 Troubleshooting

### Common Issues

#### 1. TensorFlow Installation Failed

**Problem:** `pip install tensorflow` fails

**Solutions:**
```bash
# Option 1: Use CPU-only version (smaller, faster install)
pip install tensorflow-cpu

# Option 2: Specific version
pip install tensorflow==2.13.0

# Option 3: Check Python version (must be 3.8-3.11)
python --version
```

#### 2. Model Not Loading

**Problem:** `Model files not found`

**Solution:**
```bash
# Train the model first
python xss_cnn_lstm_trainer.py

# Verify files exist
ls -lh xss_cnn_lstm_model.h5 tokenizer.pkl
```

#### 3. CORS Errors

**Problem:** Browser shows CORS error

**Solution:** Already configured in `app_cnn_lstm.py`:
```python
CORS(app, resources={r"/*": {"origins": "*"}})
```

For production, restrict origins:
```python
CORS(app, resources={r"/*": {"origins": ["https://yourdomain.com"]}})
```

### Getting Help

- 📧 **Email**: mohit@example.com
- 💬 **Issues**: [GitHub Issues](https://github.com/IsMohit/A-Predictive-Approach-to-XSS-Detection-Using-ML-Algorithms/issues)
- 📚 **Documentation**: See `/docs` folder

## 🤝 Contributing

This project is currently under active development. Contributions are welcome!

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to branch**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Areas for Contribution

- 🐛 Bug fixes
- ✨ New features
- 📝 Documentation improvements
- 🧪 Additional test cases
- 🎨 UI/UX enhancements
- 🚀 Performance optimizations
- 🌐 Multi-language support

### Code of Conduct

- Be respectful and inclusive
- Write clear, documented code
- Test before submitting
- Follow existing code style

### 🚧 In Progress
- [ ] Enhanced obfuscation detection
- [ ] Model optimization (TensorFlow Lite)
- [ ] Comprehensive test suite
- [ ] Docker containerization

## 📚 References

1. OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
2. Understanding LSTM Networks: https://colah.github.io/posts/2015-08-Understanding-LSTMs/
3. CNN for Text Classification: https://arxiv.org/abs/1408.5882
4. Web Application Security Best Practices: https://owasp.org/www-project-top-ten/

## 📞 Contact

**Project Maintainer:** Mohit

- GitHub: [@IsMohit](https://github.com/IsMohit)
- Project Link: [https://github.com/IsMohit/A-Predictive-Approach-to-XSS-Detection-Using-ML-Algorithms](https://github.com/IsMohit/A-Predictive-Approach-to-XSS-Detection-Using-ML-Algorithms)

---


<p align="center">
  <sub>Last updated: Dec 2025</sub>
</p>
