import pandas as pd
import numpy as np
import pickle
import html
import re
import json
import os
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
import warnings
warnings.filterwarnings('ignore')

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    print("✅ TensorFlow loaded successfully")
except ImportError:
    print("❌ TensorFlow not installed!")
    exit(1)


class ModelTester:    
    def __init__(self, model_path='xss_cnn_lstm_model.h5', tokenizer_path='tokenizer.pkl'):
        """Initialize the tester"""
        self.model = None
        self.tokenizer = None
        self.max_length = None
        self.vocab_size = None
        self.test_results = {}
        self.load_model(model_path, tokenizer_path)
    
    def load_model(self, model_path, tokenizer_path):
        """Load the trained model and tokenizer"""
        try:
            print(f"📥 Loading model from {model_path}...")
            self.model = keras.models.load_model(model_path)
            
            print(f"📥 Loading tokenizer from {tokenizer_path}...")
            with open(tokenizer_path, 'rb') as f:
                data = pickle.load(f)
                self.tokenizer = data['tokenizer']
                self.max_length = data['max_length']
                self.vocab_size = data['vocab_size']
            
            print("✅ Model loaded successfully!")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
    
    def preprocess_text(self, text):
        if pd.isna(text):
            return ""
        
        text = str(text)
        text = html.unescape(text)
        text = text.lower()
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def predict(self, user_input):
        processed = self.preprocess_text(user_input)
        sequence = self.tokenizer.texts_to_sequences([processed])
        padded = pad_sequences(sequence, maxlen=self.max_length, padding='post')
        prediction_proba = self.model.predict(padded, verbose=0)[0][0]
        return prediction_proba
    
    def prepare_tough_test_data(self):
        tough_malicious = [
            # Modern framework injections
            "{{constructor.constructor('alert(1)')()}}",
            "{{_c.constructor('alert(1)')()}}",
            "${alert(document.domain)}",
            
            # Advanced obfuscation
            "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            
            # Unicode tricks
            "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
            "<img src=x onerror='\\u0061lert(1)'>",
            
            # Rare tags
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<isindex type=image src=1 onerror=alert(1)>",
            
            # Protocol variations
            "data:text/html,<script>alert(1)</script>",
            "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            
            # CSS-based
            "<style>@import'data:,*%7bx:expression(alert(1))%7d';</style>",
            "<div style='background:url(javascript:alert(1))'>",
            
            # Mutation XSS
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            "<form><math><mtext></form><form><mglyph><svg><mtext><textarea>",
            
            # Event handler variations
            "<input onblur=alert(1) autofocus><input autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            
            # Rare javascript: variants
            "<a href='javas\\x09cript:alert(1)'>",
            "<iframe src='javas&#99;ript:alert(1)'>",
            
            # Comment-based attacks
            "<!--<script>alert(1)</script>-->",
            "<script>/*<!-- comment -->alert(1)</script>",
            
            # Null byte injection
            "<img src=x oner\\0ror=alert(1)>",
            "<script\\0>alert(1)</script>",
            
            # Case mixing
            "<ScRiPt>alert(1)</sCrIpT>",
            "<IMG SRC=X OnErRoR=alert(1)>",
            
            # Whitespace tricks
            "<script \\n >alert(1)</script>",
            "<img\\tsrc=x\\tonerror=alert(1)>",
            
            # SVG attacks
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            
            # Form-based
            "<form action=javascript:alert(1)><input type=submit>",
            "<form><button formaction=javascript:alert(1)>",
            
            # HTML5 attributes
            "<input autofocus onfocus=alert(1)>",
            "<body onload=alert(1)>",
            
            # Encoding attacks
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        ]
        
        # Tricky safe patterns (Label: 0)
        tricky_safe = [
            # Technical discussions about XSS
            "How do I prevent script tags in user input?",
            "The XSS payload img src=x onerror=alert(1) was blocked",
            "Check if input contains patterns like onerror or onload",
            "Example: script alert test /script should be escaped",
            
            # Code in documentation
            "function sanitize(input) { return input.replace(/script/gi, ''); }",
            "Remove dangerous tags: script, iframe, object",
            "Regex pattern: /(script|onerror|javascript:)/gi",
            
            # Academic/Educational
            "XSS Tutorial: Try injecting script console.log test /script",
            "Common attack vectors include: javascript, onerror, and iframe",
            "OWASP recommends blocking: eval, alert, and prompt",
            
            # Legitimate special characters
            "if (x < 10 && y > 5) { console.log('valid'); }",
            "Price: $50 <discount> $40 (save 20%!)",
            "Expression: (a < b) && (c > d) || (e != f)",
            
            # JSON/Config format
            '{"event": "onclick", "action": "alert", "data": "test"}',
            '<meta name="description" content="Best product ever!">',
            '<div class="warning">Check this content</div>',
            
            # HTML-like but safe
            "Temperature: 25C to 30C",
            "Mathematical: a > b > c",
            "File paths: C:\\Users\\Documents\\file.txt",
            
            # Names and regular text
            "John Smith attended the conference",
            "Alice Johnson works in IT",
            "Bob is learning web development",
            "Charlie uses Python and JavaScript",
            
            # Safe HTML entities
            "&lt;script&gt; in HTML entities is safe",
            "Use &amp; for ampersand in HTML",
            "Quote marks: &quot; and &apos;",
            
            # Search queries
            "How to validate email addresses?",
            "Best practices for secure coding",
            "Learn cybersecurity in 30 days",
            
            # Email addresses
            "contact@example.com",
            "support.team@company.org",
            "webmaster+news@domain.co.uk",
            
            # URLs (not malicious)
            "Visit https://example.com for more info",
            "Check https://docs.python.org/3/library",
            "https://github.com/user/repo/issues",
        ]
        
        malicious_df = pd.DataFrame({
            'input': tough_malicious,
            'label': [1] * len(tough_malicious)
        })
        
        safe_df = pd.DataFrame({
            'input': tricky_safe,
            'label': [0] * len(tricky_safe)
        })
        
        test_df = pd.concat([malicious_df, safe_df], ignore_index=True)
        test_df = test_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        return test_df
    
    def load_dataset_samples(self, csv_path='Xss_SafeInput_Dataset.csv', num_samples=1000):
        try:
            df = pd.read_csv(csv_path)
            class_0 = df[df['label'] == 0].sample(min(num_samples//2, len(df[df['label'] == 0])), random_state=42)
            class_1 = df[df['label'] == 1].sample(min(num_samples//2, len(df[df['label'] == 1])), random_state=42)
            return pd.concat([class_0, class_1], ignore_index=True).sample(frac=1, random_state=42)
        except Exception as e:
            print(f"⚠️  Could not load dataset: {e}")
            return None
    
    def test_on_tough_data(self):
        print("\n" + "="*80)
        print("🧪 TESTING ON TOUGH DATA (Mixed Malicious & Tricky Safe)")
        print("="*80)
        
        test_df = self.prepare_tough_test_data()
        print(f"\n📊 Tough Test Dataset Stats:")
        print(f"   Total samples: {len(test_df)}")
        print(f"   Malicious (1): {(test_df['label'] == 1).sum()}")
        print(f"   Safe (0): {(test_df['label'] == 0).sum()}")
        
        predictions_proba = []
        for idx, row in test_df.iterrows():
            proba = self.predict(row['input'])
            predictions_proba.append(proba)
        
        predictions_proba = np.array(predictions_proba)
        predictions = (predictions_proba > 0.5).astype(int)
        
        return {
            'name': 'Tough Test Data',
            'test_data': test_df,
            'predictions': predictions,
            'predictions_proba': predictions_proba,
            'true_labels': test_df['label'].values
        }
    
    def test_on_dataset_samples(self):
        print("\n" + "="*80)
        print("🧪 TESTING ON DATASET SAMPLES (1000 samples from Xss_SafeInput_Dataset)")
        print("="*80)
        
        test_df = self.load_dataset_samples()
        if test_df is None:
            return None
        
        print(f"\n📊 Dataset Test Stats:")
        print(f"   Total samples: {len(test_df)}")
        print(f"   Malicious (1): {(test_df['label'] == 1).sum()}")
        print(f"   Safe (0): {(test_df['label'] == 0).sum()}")
        
        # Get predictions
        predictions_proba = []
        for idx, row in test_df.iterrows():
            proba = self.predict(row['input'])
            predictions_proba.append(proba)
        
        predictions_proba = np.array(predictions_proba)
        predictions = (predictions_proba > 0.5).astype(int)
        
        return {
            'name': 'Dataset Samples',
            'test_data': test_df,
            'predictions': predictions,
            'predictions_proba': predictions_proba,
            'true_labels': test_df['label'].values
        }
    
    def compute_metrics(self, true_labels, predictions, predictions_proba):
        """Compute comprehensive metrics"""
        accuracy = accuracy_score(true_labels, predictions)
        precision = precision_score(true_labels, predictions, zero_division=0)
        recall = recall_score(true_labels, predictions, zero_division=0)
        f1 = f1_score(true_labels, predictions, zero_division=0)
        conf_matrix = confusion_matrix(true_labels, predictions)
        
        # ROC-AUC score
        try:
            roc_auc = roc_auc_score(true_labels, predictions_proba)
        except:
            roc_auc = 0.0
        
        class_report = classification_report(
            true_labels, predictions, 
            target_names=['Safe (0)', 'Malicious (1)'],
            zero_division=0
        )
        
        tn, fp, fn, tp = conf_matrix.ravel() if conf_matrix.size == 4 else (0, 0, 0, 0)
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': roc_auc,
            'sensitivity': sensitivity,
            'specificity': specificity,
            'confusion_matrix': conf_matrix,
            'classification_report': class_report,
            'tp': tp,
            'tn': tn,
            'fp': fp,
            'fn': fn
        }
    
    def display_metrics(self, test_result, metrics):
        """Display metrics in a formatted way"""
        print(f"\n{'='*80}")
        print(f"📊 METRICS FOR: {test_result['name']}")
        print(f"{'='*80}")
        
        print(f"\n🎯 PRIMARY METRICS:")
        print(f"   Accuracy:    {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"   Precision:   {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"   Recall:      {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"   F1-Score:    {metrics['f1_score']:.4f}")
        print(f"   ROC-AUC:     {metrics['roc_auc']:.4f}")
        
        print(f"\n📈 ADDITIONAL METRICS:")
        print(f"   Sensitivity: {metrics['sensitivity']:.4f} ({metrics['sensitivity']*100:.2f}%)")
        print(f"   Specificity: {metrics['specificity']:.4f} ({metrics['specificity']*100:.2f}%)")
        
        print(f"\n🔢 CONFUSION MATRIX:")
        print(f"   {'':>15} {'Predicted Safe':>20} {'Predicted Malicious':>20}")
        print(f"   {'Actual Safe':>15} {metrics['tn']:>20} {metrics['fp']:>20}")
        print(f"   {'Actual Malicious':>15} {metrics['fn']:>20} {metrics['tp']:>20}")
        
        print(f"\n📋 DETAILED CLASSIFICATION REPORT:")
        print(metrics['classification_report'])
    
    def save_results_to_json(self, all_results):
        """Save test results to JSON for dashboard"""
        results_data = {
            'timestamp': datetime.now().isoformat(),
            'model_info': {
                'model_path': 'xss_cnn_lstm_model.h5',
                'max_length': self.max_length,
                'vocab_size': self.vocab_size
            },
            'test_results': []
        }
        
        for test_name, metrics in all_results.items():
            results_data['test_results'].append({
                'test_name': test_name,
                'metrics': {
                    'accuracy': float(metrics['accuracy']),
                    'precision': float(metrics['precision']),
                    'recall': float(metrics['recall']),
                    'f1_score': float(metrics['f1_score']),
                    'roc_auc': float(metrics['roc_auc']),
                    'sensitivity': float(metrics['sensitivity']),
                    'specificity': float(metrics['specificity']),
                    'confusion_matrix': metrics['confusion_matrix'].tolist(),
                    'tp': int(metrics['tp']),
                    'tn': int(metrics['tn']),
                    'fp': int(metrics['fp']),
                    'fn': int(metrics['fn'])
                }
            })
        
        # Save to admin_panel folder
        output_path = os.path.join('admin_panel', 'test_results.json')
        os.makedirs('admin_panel', exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"\n💾 Results saved to {output_path}")
        return output_path
    
    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "="*80)
        print("🚀 STARTING COMPREHENSIVE MODEL TESTING")
        print("="*80)
        
        all_results = {}
        
        test_result_1 = self.test_on_tough_data()
        metrics_1 = self.compute_metrics(
            test_result_1['true_labels'],
            test_result_1['predictions'],
            test_result_1['predictions_proba']
        )
        self.display_metrics(test_result_1, metrics_1)
        all_results['Tough Test Data'] = metrics_1
        
        test_result_2 = self.test_on_dataset_samples()
        if test_result_2 is not None:
            metrics_2 = self.compute_metrics(
                test_result_2['true_labels'],
                test_result_2['predictions'],
                test_result_2['predictions_proba']
            )
            self.display_metrics(test_result_2, metrics_2)
            all_results['Dataset Samples'] = metrics_2
        
        self.save_results_to_json(all_results)
        
        print("\n" + "="*80)
        print("✅ TESTING COMPLETE!")
        print("="*80)
        
        return all_results


def main():
    tester = ModelTester()
    if not tester.model:
        print("❌ Failed to load model. Exiting.")
        return
    
    results = tester.run_all_tests()


if __name__ == '__main__':
    main()
