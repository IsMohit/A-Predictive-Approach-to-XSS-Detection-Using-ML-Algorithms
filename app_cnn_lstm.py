from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import html
import re
import bleach
from datetime import datetime
import json
import os

# Deep Learning imports
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    import numpy as np
    print("✅ TensorFlow loaded successfully")
except ImportError:
    print("❌ TensorFlow not installed!")
    print("Run: pip install tensorflow")
    exit(1)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins for development

# Log file for malicious attempts
MALICIOUS_LOG_FILE = 'malicious_attempts.jsonl'


class XSSCNNLSTMDetector:
    def __init__(self, model_path='xss_cnn_lstm_model.h5', tokenizer_path='tokenizer.pkl'):
        """
        Initialize the CNN-LSTM XSS detector
        """
        self.model = None
        self.tokenizer = None
        self.max_length = None
        self.vocab_size = None
        self.load_model(model_path, tokenizer_path)
    
    def load_model(self, model_path, tokenizer_path):
        """
        Load the trained CNN-LSTM model and tokenizer
        """
        try:
            print(f"📥 Loading CNN-LSTM model from {model_path}...")
            self.model = keras.models.load_model(model_path)
            
            print(f"📥 Loading tokenizer from {tokenizer_path}...")
            with open(tokenizer_path, 'rb') as f:
                data = pickle.load(f)
                self.tokenizer = data['tokenizer']
                self.max_length = data['max_length']
                self.vocab_size = data['vocab_size']
            
            print("✅ CNN-LSTM model loaded successfully!")
            print(f"   Max sequence length: {self.max_length}")
            print(f"   Vocabulary size: {self.vocab_size}")
            return True
        except FileNotFoundError as e:
            print(f"❌ Error: Model files not found - {e}")
            print("Please run xss_cnn_lstm_trainer.py first to train the model!")
            return False
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
    
    def preprocess_text(self, text):
        """
        Preprocess input text
        """
        if not text or text.strip() == "":
            return ""
        
        text = str(text)
        text = html.unescape(text)
        text = text.lower()
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def predict(self, user_input):
        """
        Predict if input is malicious using CNN-LSTM
        """
        if not self.model or not self.tokenizer:
            raise Exception("Model not loaded!")
        
        # Preprocess
        processed = self.preprocess_text(user_input)
        
        # Convert to sequence
        sequence = self.tokenizer.texts_to_sequences([processed])
        padded = pad_sequences(sequence, maxlen=self.max_length, padding='post')
        
        # Predict
        prediction_proba = self.model.predict(padded, verbose=0)[0][0]
        prediction = 1 if prediction_proba > 0.5 else 0
        confidence = prediction_proba * 100 if prediction == 1 else (1 - prediction_proba) * 100
        
        return {
            'prediction': int(prediction),
            'confidence': float(confidence),
            'safe_probability': float((1 - prediction_proba) * 100),
            'malicious_probability': float(prediction_proba * 100)
        }
    
    def sanitize_input(self, user_input):
        """
        Sanitize user input using Bleach library
        """
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li']
        allowed_attributes = {'a': ['href', 'title']}
        allowed_protocols = ['http', 'https', 'mailto']
        
        sanitized = bleach.clean(
            user_input,
            tags=allowed_tags,
            attributes=allowed_attributes,
            protocols=allowed_protocols,
            strip=True
        )
        
        return sanitized


# Initialize detector
print("\n" + "="*80)
print("🛡️  Initializing CNN-LSTM XSS Detector...")
print("="*80 + "\n")

detector = XSSCNNLSTMDetector()


def log_malicious_attempt(ip_address, user_input, prediction_result):
    """
    Log malicious attempts for future analysis
    """
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': ip_address,
        'input': user_input,
        'prediction': prediction_result['prediction'],
        'confidence': prediction_result['confidence'],
        'model_type': 'CNN-LSTM'
    }
    
    try:
        with open(MALICIOUS_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"Warning: Could not log malicious attempt - {e}")


@app.route('/')
def home():
    """
    API home endpoint with documentation
    """
    return jsonify({
        'service': 'ML-Based XSS Detection API (CNN-LSTM)',
        'version': '2.0',
        'model': 'CNN-LSTM Hybrid',
        'status': 'running',
        'features': [
            'Deep learning-based detection',
            'Sequential pattern recognition',
            'Character-level analysis',
            'Real-time input sanitization'
        ],
        'endpoints': {
            '/check': {
                'method': 'POST',
                'description': 'Check if input contains XSS payload',
                'payload': {'input': 'string (required)'}
            },
            '/health': {
                'method': 'GET',
                'description': 'Check API health status'
            },
            '/batch-check': {
                'method': 'POST',
                'description': 'Check multiple inputs at once',
                'payload': {'inputs': ['string1', 'string2', '...']}
            },
            '/stats': {
                'method': 'GET',
                'description': 'Get statistics about logged attempts'
            },
            '/model-info': {
                'method': 'GET',
                'description': 'Get information about the CNN-LSTM model'
            }
        }
    })


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    model_loaded = detector.model is not None and detector.tokenizer is not None
    
    return jsonify({
        'status': 'healthy' if model_loaded else 'degraded',
        'model_type': 'CNN-LSTM',
        'model_loaded': model_loaded,
        'tensorflow_version': tf.__version__,
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/model-info', methods=['GET'])
def model_info():
    """
    Get information about the CNN-LSTM model
    """
    if not detector.model:
        return jsonify({'error': 'Model not loaded'}), 503
    
    # Get model summary
    total_params = detector.model.count_params()
    
    return jsonify({
        'model_type': 'CNN-LSTM Hybrid',
        'architecture': 'Embedding → CNN → MaxPool → BiLSTM → Dense',
        'total_parameters': int(total_params),
        'max_sequence_length': detector.max_length,
        'vocabulary_size': detector.vocab_size,
        'tokenization': 'Character-level',
        'advantages': [
            'Better pattern recognition',
            'Captures sequential dependencies',
            'Handles obfuscated payloads',
            'Lower false positive rate'
        ]
    })


@app.route('/check', methods=['POST'])
def check_input():
    """
    Main endpoint for XSS detection using CNN-LSTM
    """
    try:
        # Parse request
        data = request.get_json()
        
        if not data or 'input' not in data:
            return jsonify({
                'error': 'Missing required field: input',
                'usage': 'POST /check with JSON body: {"input": "text to check"}'
            }), 400
        
        user_input = data['input']
        
        # Validate input
        if not user_input or user_input.strip() == '':
            return jsonify({
                'prediction': 'safe',
                'message': 'Empty input',
                'sanitized': '',
                'confidence': 100.0
            })
        
        # Check if model is loaded
        if not detector.model or not detector.tokenizer:
            return jsonify({
                'error': 'Model not loaded. Please train the CNN-LSTM model first.',
                'status': 'error'
            }), 503
        
        # FIRST CHECK: Get prediction on original input
        result = detector.predict(user_input)
        
        # Sanitize input
        sanitized = detector.sanitize_input(user_input)
        
        # SECOND CHECK: Validate sanitized output if original was malicious
        is_sanitized_safe = True
        sanitization_effective = True
        
        if result['prediction'] == 1 and sanitized and sanitized.strip():
            # Re-check the sanitized version
            sanitized_result = detector.predict(sanitized)
            
            if sanitized_result['prediction'] == 1:
                # Sanitization failed! Still malicious
                is_sanitized_safe = False
                sanitization_effective = False
                # Return empty string if still malicious
                sanitized = ""
        
        # Determine prediction label
        prediction_label = 'malicious' if result['prediction'] == 1 else 'safe'
        
        # Log malicious attempts
        if result['prediction'] == 1:
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            log_malicious_attempt(client_ip, user_input, result)
        
        # Build response
        response = {
            'prediction': prediction_label,
            'confidence': round(result['confidence'], 2),
            'sanitized': sanitized,
            'probabilities': {
                'safe': round(result['safe_probability'], 2),
                'malicious': round(result['malicious_probability'], 2)
            },
            'model_used': 'CNN-LSTM',
            'original_length': len(user_input),
            'sanitized_length': len(sanitized),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add sanitization status
        if result['prediction'] == 1:
            response['warning'] = 'Potential XSS attack detected by CNN-LSTM model!'
            response['risk_level'] = 'high' if result['confidence'] > 90 else 'medium'
            response['recommendation'] = 'Input has been sanitized. Do not trust this input.'
            response['sanitization_effective'] = sanitization_effective
            
            if not sanitization_effective:
                response['sanitization_warning'] = 'Could not sanitize input safely - still contains malicious patterns'
                response['sanitized'] = ""  # Force empty
                response['action_required'] = 'Input must be completely rejected'
        
        return jsonify(response)
    
    except Exception as e:
        print(f"Error in /check endpoint: {e}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/batch-check', methods=['POST'])
def batch_check():
    """
    Check multiple inputs at once using CNN-LSTM
    """
    try:
        data = request.get_json()
        
        if not data or 'inputs' not in data:
            return jsonify({
                'error': 'Missing required field: inputs (array)',
                'usage': 'POST /batch-check with JSON body: {"inputs": ["text1", "text2"]}'
            }), 400
        
        inputs = data['inputs']
        
        if not isinstance(inputs, list):
            return jsonify({'error': 'inputs must be an array'}), 400
        
        # Limit batch size to prevent overload
        if len(inputs) > 100:
            return jsonify({
                'error': 'Batch size too large. Maximum 100 inputs per request.'
            }), 400
        
        results = []
        for idx, user_input in enumerate(inputs):
            try:
                result = detector.predict(user_input)
                sanitized = detector.sanitize_input(user_input)
                
                results.append({
                    'index': idx,
                    'prediction': 'malicious' if result['prediction'] == 1 else 'safe',
                    'confidence': round(result['confidence'], 2),
                    'sanitized': sanitized,
                    'probabilities': {
                        'safe': round(result['safe_probability'], 2),
                        'malicious': round(result['malicious_probability'], 2)
                    }
                })
            except Exception as e:
                results.append({
                    'index': idx,
                    'error': str(e)
                })
        
        # Count predictions
        malicious_count = sum(1 for r in results if r.get('prediction') == 'malicious')
        safe_count = len(results) - malicious_count
        
        return jsonify({
            'total': len(inputs),
            'malicious_detected': malicious_count,
            'safe_detected': safe_count,
            'model_used': 'CNN-LSTM',
            'results': results
        })
    
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/stats', methods=['GET'])
def get_stats():
    """
    Get statistics about logged malicious attempts
    """
    try:
        if not os.path.exists(MALICIOUS_LOG_FILE):
            return jsonify({
                'total_attempts': 0,
                'message': 'No malicious attempts logged yet'
            })
        
        attempts = []
        with open(MALICIOUS_LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    attempts.append(json.loads(line))
                except:
                    continue
        
        # Filter CNN-LSTM attempts
        cnn_lstm_attempts = [a for a in attempts if a.get('model_type') == 'CNN-LSTM']
        
        total = len(cnn_lstm_attempts)
        high_confidence = len([a for a in cnn_lstm_attempts if a['confidence'] > 90])
        
        recent = cnn_lstm_attempts[-10:] if len(cnn_lstm_attempts) > 10 else cnn_lstm_attempts
        
        return jsonify({
            'model_type': 'CNN-LSTM',
            'total_attempts': total,
            'high_confidence_attempts': high_confidence,
            'average_confidence': sum(a['confidence'] for a in cnn_lstm_attempts) / total if total > 0 else 0,
            'recent_attempts': recent,
            'log_file': MALICIOUS_LOG_FILE
        })
    
    except Exception as e:
        return jsonify({
            'error': 'Could not retrieve stats',
            'message': str(e)
        }), 500


if __name__ == '__main__':
    print("="*80)
    print("🛡️  ML-Based XSS Detection API Server (CNN-LSTM)")
    print("="*80)
    print("\n🚀 Starting Flask server with CNN-LSTM model...")
    print("📡 API will be available at: http://localhost:5000")
    print("\n📚 Endpoints:")
    print("   GET  /              - API documentation")
    print("   GET  /health        - Health check")
    print("   GET  /model-info    - CNN-LSTM model information")
    print("   POST /check         - Check single input")
    print("   POST /batch-check   - Check multiple inputs")
    print("   GET  /stats         - View statistics")
    print("\n💡 Model: CNN-LSTM Hybrid (Deep Learning)")
    print("   - Better pattern recognition")
    print("   - Sequential context understanding")
    print("   - Character-level tokenization")
    print("\n" + "="*80 + "\n")
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)