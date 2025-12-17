"""
Improved XSS Detection using CNN-LSTM Hybrid Model
This version has better architecture and training for higher accuracy
"""

import pandas as pd
import numpy as np
import pickle
import html
import re
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')


try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import (
        Embedding, Conv1D, MaxPooling1D, LSTM, Dense, 
        Dropout, Bidirectional, GlobalMaxPooling1D, 
        Concatenate, Input, BatchNormalization, Activation,
        SpatialDropout1D, GlobalAveragePooling1D
    )
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
    from tensorflow.keras.regularizers import l2
    print("TensorFlow imported successfully")
except ImportError:
    print("TensorFlow not installed. Installing...")
    print("Run: pip install tensorflow")
    exit(1)


class XSSCNNLSTMDetector:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.max_length = 300  
        self.vocab_size = 5000 
        
    def preprocess_text(self, text):
        """
        Preprocess input text - keep more information for detection
        """
        if pd.isna(text):
            return ""
        
        text = str(text)
       
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def load_and_prepare_data(self, csv_path):
        """
        Load and preprocess dataset
        """
        print("Loading dataset...")
        df = pd.read_csv(csv_path)
        
        print(f"Loaded {len(df)} samples")
        print(f"Safe samples: {len(df[df['label'] == 0])}")
        print(f"Malicious samples: {len(df[df['label'] == 1])}")
        
        # Preprocess inputs
        print("\nPreprocessing text...")
        df['processed_input'] = df['input'].apply(self.preprocess_text)
        
        return df
    
    def prepare_sequences(self, texts, fit_tokenizer=True):
        """
        Convert text to sequences using character-level tokenization
        """
        if fit_tokenizer:
            print("\n Creating tokenizer (character-level)...")
            self.tokenizer = Tokenizer(
                num_words=self.vocab_size,
                char_level=True,  
                oov_token='<OOV>',
                lower=False 
            )
            self.tokenizer.fit_on_texts(texts)
            print(f"   Vocabulary size: {min(len(self.tokenizer.word_index), self.vocab_size)}")
        
        sequences = self.tokenizer.texts_to_sequences(texts)
        
        padded_sequences = pad_sequences(
            sequences,
            maxlen=self.max_length,
            padding='post',
            truncating='post'
        )
        
        return padded_sequences
    
    def build_improved_cnn_lstm_model(self):
        """
        Build improved CNN-LSTM architecture with better detection capabilities
        
        Key improvements:
        1. Deeper embedding layer
        2. Multiple parallel CNN branches (different kernel sizes)
        3. Stronger LSTM layers
        4. Better regularization
        5. Proper activation functions
        """
        print("\nBuilding Improved CNN-LSTM Model...")
        
        input_layer = Input(shape=(self.max_length,), name='input')
        
        embedding = Embedding(
            input_dim=self.vocab_size,
            output_dim=256,  
            input_length=self.max_length,
            name='embedding'
        )(input_layer)
        
        embedding = SpatialDropout1D(0.2)(embedding)
        
        conv1 = Conv1D(filters=128, kernel_size=3, padding='same', activation='relu')(embedding)
        conv1 = BatchNormalization()(conv1)
        conv1 = MaxPooling1D(pool_size=2)(conv1)
        
        conv2 = Conv1D(filters=128, kernel_size=5, padding='same', activation='relu')(embedding)
        conv2 = BatchNormalization()(conv2)
        conv2 = MaxPooling1D(pool_size=2)(conv2)
        
        conv3 = Conv1D(filters=128, kernel_size=7, padding='same', activation='relu')(embedding)
        conv3 = BatchNormalization()(conv3)
        conv3 = MaxPooling1D(pool_size=2)(conv3)
        
        conv_concat = Concatenate()([conv1, conv2, conv3])
        conv_concat = Dropout(0.3)(conv_concat)
        
        conv4 = Conv1D(filters=256, kernel_size=3, padding='same', activation='relu')(conv_concat)
        conv4 = BatchNormalization()(conv4)
        conv4 = MaxPooling1D(pool_size=2)(conv4)
        conv4 = Dropout(0.3)(conv4)
        
        lstm1 = Bidirectional(LSTM(128, return_sequences=True, dropout=0.2, recurrent_dropout=0.2))(conv4)
        lstm1 = BatchNormalization()(lstm1)
        
        lstm2 = Bidirectional(LSTM(64, return_sequences=False, dropout=0.2, recurrent_dropout=0.2))(lstm1)
        lstm2 = BatchNormalization()(lstm2)
        lstm2 = Dropout(0.4)(lstm2)
        
        dense1 = Dense(256, activation='relu', kernel_regularizer=l2(0.01))(lstm2)
        dense1 = BatchNormalization()(dense1)
        dense1 = Dropout(0.5)(dense1)
        
        dense2 = Dense(128, activation='relu', kernel_regularizer=l2(0.01))(dense1)
        dense2 = BatchNormalization()(dense2)
        dense2 = Dropout(0.4)(dense2)
        
        dense3 = Dense(64, activation='relu')(dense2)
        dense3 = Dropout(0.3)(dense3)
        
        output = Dense(1, activation='sigmoid', name='output')(dense3)
        
        model = Model(inputs=input_layer, outputs=output, name='XSS_CNN_LSTM')
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.0005, clipnorm=1.0),
            loss='binary_crossentropy',
            metrics=[
                'accuracy',
                keras.metrics.Precision(name='precision'),
                keras.metrics.Recall(name='recall'),
                keras.metrics.AUC(name='auc')
            ]
        )
        
        self.model = model
        
        print("\nModel Architecture:")
        model.summary()
        
        return model
    
    def train_model(self, df, epochs=30, batch_size=32, validation_split=0.15):
        """
        Train the improved CNN-LSTM model
        """
        print("\nTraining Improved CNN-LSTM Model...")
        
        X = df['processed_input'].values
        y = df['label'].values
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"   Training samples: {len(X_train)}")
        print(f"   Testing samples: {len(X_test)}")
        
        X_train_seq = self.prepare_sequences(X_train, fit_tokenizer=True)
        X_test_seq = self.prepare_sequences(X_test, fit_tokenizer=False)
        
        if self.model is None:
            self.build_improved_cnn_lstm_model()
        
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=8,
                restore_best_weights=True,
                verbose=1,
                min_delta=0.001
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=4,
                min_lr=0.00001,
                verbose=1
            ),
            ModelCheckpoint(
                'xss_cnn_lstm_best.h5',
                monitor='val_auc',
                save_best_only=True,
                mode='max',
                verbose=1
            )
        ]
        
        from sklearn.utils.class_weight import compute_class_weight
        class_weights = compute_class_weight(
            'balanced',
            classes=np.unique(y_train),
            y=y_train
        )
        class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
        
        print(f"\nClass weights: {class_weight_dict}")
        print(f"\nStarting training for {epochs} epochs...")
        print("   (Training will stop early if no improvement)\n")
        
        history = self.model.fit(
            X_train_seq, y_train,
            validation_split=validation_split,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            class_weight=class_weight_dict,
            verbose=1
        )
        
        print("\nEvaluating Model on Test Set...")
        test_results = self.model.evaluate(X_test_seq, y_test, verbose=0)
        test_loss, test_acc, test_precision, test_recall, test_auc = test_results
        
        y_pred_proba = self.model.predict(X_test_seq, verbose=0)
        y_pred = (y_pred_proba > 0.5).astype(int).flatten()
        
        f1 = f1_score(y_test, y_pred)
        
        print(f"\nModel Performance Metrics:")
        print(f"{'='*60}")
        print(f"   Test Loss:      {test_loss:.4f}")
        print(f"   Test Accuracy:  {test_acc:.4f} ({test_acc*100:.2f}%)")
        print(f"   Test Precision: {test_precision:.4f} ({test_precision*100:.2f}%)")
        print(f"   Test Recall:    {test_recall:.4f} ({test_recall*100:.2f}%)")
        print(f"   Test F1-Score:  {f1:.4f}")
        print(f"   Test AUC:       {test_auc:.4f}")
        print(f"{'='*60}")
        
        print("\n📋 Detailed Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))
        
        print("\n🔢 Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(f"   True Negatives:  {cm[0][0]} (correctly identified safe)")
        print(f"   False Positives: {cm[0][1]} (safe marked as malicious)")
        print(f"   False Negatives: {cm[1][0]} (malicious marked as safe) ⚠️")
        print(f"   True Positives:  {cm[1][1]} (correctly identified malicious)")
        
        fnr = cm[1][0] / (cm[1][0] + cm[1][1]) if (cm[1][0] + cm[1][1]) > 0 else 0
        print(f"\nFalse Negative Rate: {fnr*100:.2f}% (lower is better)")
        
        return history, (test_acc, test_precision, test_recall, f1, test_auc)
    
    def save_model(self, model_path='xss_cnn_lstm_model.h5', tokenizer_path='tokenizer.pkl'):
        """
        Save trained model and tokenizer
        """
        print(f"\nSaving model to {model_path}...")
        self.model.save(model_path)
        
        print(f"Saving tokenizer to {tokenizer_path}...")
        with open(tokenizer_path, 'wb') as f:
            pickle.dump({
                'tokenizer': self.tokenizer,
                'max_length': self.max_length,
                'vocab_size': self.vocab_size
            }, f)
        
        print("Model and tokenizer saved successfully!")
    
    def load_model(self, model_path='xss_cnn_lstm_model.h5', tokenizer_path='tokenizer.pkl'):
        """
        Load saved model and tokenizer
        """
        print(f"Loading model from {model_path}...")
        self.model = keras.models.load_model(model_path)
        
        print(f"Loading tokenizer from {tokenizer_path}...")
        with open(tokenizer_path, 'rb') as f:
            data = pickle.load(f)
            self.tokenizer = data['tokenizer']
            self.max_length = data['max_length']
            self.vocab_size = data['vocab_size']
        
        print("Model and tokenizer loaded successfully!")
    
    def predict(self, text):
        """
        Predict if input is malicious
        """
        processed = self.preprocess_text(text)
        
        sequence = self.tokenizer.texts_to_sequences([processed])
        padded = pad_sequences(sequence, maxlen=self.max_length, padding='post')
        
        prediction_proba = self.model.predict(padded, verbose=0)[0][0]
        prediction = 1 if prediction_proba > 0.5 else 0
        
        return {
            'prediction': int(prediction),
            'confidence': float(prediction_proba * 100 if prediction == 1 else (1 - prediction_proba) * 100),
            'safe_probability': float((1 - prediction_proba) * 100),
            'malicious_probability': float(prediction_proba * 100),
            'raw_score': float(prediction_proba)
        }
    
    def test_sample_predictions(self, test_samples):
        """
        Test model with sample inputs
        """
        print("\nTesting Sample Predictions:")
        print("="*80)
        
        for sample in test_samples:
            result = self.predict(sample)
            
            label = "MALICIOUS" if result['prediction'] == 1 else "SAFE"
            confidence = result['confidence']
            mal_prob = result['malicious_probability']
            
            print(f"\nInput: {sample[:70]}{'...' if len(sample) > 70 else ''}")
            print(f"Prediction: {label} (Confidence: {confidence:.2f}%)")
            print(f"Malicious Probability: {mal_prob:.2f}%")


if __name__ == "__main__":
    print("="*80)
    print("ML-Based XSS Detection - Improved CNN-LSTM Model")
    print("="*80)
    
    np.random.seed(42)
    tf.random.set_seed(42)
    
    detector = XSSCNNLSTMDetector()
    
    try:
        # df = detector.load_and_prepare_data('xss_dataset.csv')
        df = detector.load_and_prepare_data('Xss_SafeInput_Dataset.csv')
    except FileNotFoundError:
        print("\nError: Dataset file 'xss_dataset.csv' not found!")
        print("Please run generate_dataset.py first!")
        exit(1)
    
    history, metrics = detector.train_model(
        df,
        epochs=30,  
        batch_size=32,  
        validation_split=0.15
    )
    
    detector.save_model()
    
    test_samples = [
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(document.cookie)",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<body onload=alert('test')>",
        "<input onfocus=alert(1) autofocus>",
        "<img src=x onerror=\\u0061lert(1)>",
        "<script>eval('alert(1)')</script>",
        "Hello, this is a normal comment!",
        "Welcome to my profile page",
        "Check out this link: https://example.com",
        "My email is test@example.com",
        "This is perfectly safe text",
        "Contact me for more information",
        "Great product! Highly recommended.",
        "Thanks for your help!",
    ]
    
    detector.test_sample_predictions(test_samples)
    
    print("\n" + "="*80)
    print("Training Complete! Improved CNN-LSTM model is ready.")
    print("Files saved:")
    print("   - xss_cnn_lstm_model.h5 (Main model)")
    print("   - tokenizer.pkl (Tokenizer & config)")
    print("   - xss_cnn_lstm_best.h5 (Best checkpoint)")
    print("\nThis model should now have much better accuracy!")
    print("="*80)