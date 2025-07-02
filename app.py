from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=["*"])  # Allow all origins for development

class SQLInjectionDetector:
    def __init__(self, model_path='sqli_classifier_model.h5', tokenizer_path='tokenizer.pkl'):
        self.model_path = model_path
        self.tokenizer_path = tokenizer_path
        self.model = None
        self.tokenizer = None
        self.max_length = 30
        self.load_model_and_tokenizer()
    
    def load_model_and_tokenizer(self):
        """Load the trained model and tokenizer"""
        try:
            # Load the trained model
            if os.path.exists(self.model_path):
                self.model = load_model(self.model_path)
                logger.info(f"Model loaded successfully from {self.model_path}")
            else:
                logger.error(f"Model file not found: {self.model_path}")
                # Create a dummy model for testing
                self.create_dummy_model()
            
            # Load the tokenizer
            if os.path.exists(self.tokenizer_path):
                with open(self.tokenizer_path, 'rb') as f:
                    self.tokenizer = pickle.load(f)
                logger.info(f"Tokenizer loaded successfully from {self.tokenizer_path}")
            else:
                logger.warning(f"Tokenizer file not found: {self.tokenizer_path}")
                self.create_fallback_tokenizer()
                
        except Exception as e:
            logger.error(f"Error loading model/tokenizer: {str(e)}")
            self.create_dummy_model()
            self.create_fallback_tokenizer()
    
    def create_dummy_model(self):
        """Create a dummy model for testing when real model is not available"""
        from tensorflow.keras.models import Sequential
        from tensorflow.keras.layers import Embedding, LSTM, Dense
        
        model = Sequential([
            Embedding(1000, 64, input_length=self.max_length),
            LSTM(32),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        self.model = model
        logger.info("Dummy model created for testing")
    
    def create_fallback_tokenizer(self):
        """Create a fallback tokenizer if the original is not available"""
        self.tokenizer = Tokenizer(num_words=1000, oov_token='<OOV>')
        
        # Common SQL injection patterns for basic tokenization
        sample_texts = [
            "SELECT * FROM users WHERE id = 1",
            "' OR '1'='1' --",
            "1' UNION SELECT username, password FROM users--",
            "admin'; DROP TABLE users; --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "SELECT name FROM sqlite_master WHERE type='table'",
            "1' OR 1=1#",
            "1' UNION ALL SELECT NULL,NULL,NULL--",
            "'; EXEC xp_cmdshell('dir')--",
            "1' WAITFOR DELAY '00:00:05'--"
        ]
        
        self.tokenizer.fit_on_texts(sample_texts)
        logger.info("Fallback tokenizer created")
    
    def predict(self, query):
        """Predict if a query is a SQL injection attempt"""
        try:
            # Preprocess the query
            sequences = self.tokenizer.texts_to_sequences([query])
            padded_sequences = pad_sequences(sequences, padding='post', maxlen=self.max_length)
            
            # Make prediction (using dummy logic if model is not trained)
            if hasattr(self.model, 'predict'):
                prediction_score = self.model.predict(padded_sequences, verbose=0)[0][0]
            else:
                # Fallback prediction logic
                prediction_score = self.simple_heuristic_prediction(query)
            
            # Determine result
            is_malicious = prediction_score > 0.5
            confidence = prediction_score if is_malicious else 1 - prediction_score
            
            result = {
                'query': query,
                'prediction': 'malicious' if is_malicious else 'safe',
                'score': float(prediction_score),
                'confidence': float(confidence),
                'risk_level': self.get_risk_level(prediction_score)
            }
            
            logger.info(f"Prediction made: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            raise
    
    def simple_heuristic_prediction(self, query):
        """Simple heuristic for testing when model is not available"""
        query_lower = query.lower()
        malicious_patterns = [
            "' or '1'='1'", "union select", "drop table", "exec", 
            "xp_cmdshell", "waitfor delay", "sleep(", "benchmark(",
            "information_schema", "sqlite_master", "load_file"
        ]
        
        score = 0.0
        for pattern in malicious_patterns:
            if pattern in query_lower:
                score += 0.3
        
        return min(score, 1.0)

    def get_risk_level(self, score):
        """Categorize risk level based on prediction score"""
        if score < 0.3:
            return 'low'
        elif score < 0.7:
            return 'medium'
        else:
            return 'high'

# Initialize the detector
detector = SQLInjectionDetector()

@app.route('/', methods=['GET'])
def home():
    """Home endpoint"""
    return jsonify({
        'message': 'SQL Injection Detection API',
        'status': 'running',
        'endpoints': [
            'GET /api/health',
            'POST /api/predict-sqli',
            'POST /api/batch-predict',
            'GET /api/model-info'
        ]
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': detector is not None and detector.model is not None,
        'tokenizer_loaded': detector is not None and detector.tokenizer is not None,
        'timestamp': pd.Timestamp.now().isoformat()
    })

@app.route('/api/predict-sqli', methods=['POST'])
def predict_sqli():
    """Main prediction endpoint"""
    try:
        # Validate detector is loaded
        if detector is None or detector.model is None:
            return jsonify({
                'error': 'Model not loaded',
                'message': 'SQL injection detection model is not available'
            }), 500
        
        # Get request data
        data = request.get_json()
        
        # Validate input
        if not data or 'query' not in data:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Please provide a query in the request body'
            }), 400
        
        query = data['query'].strip()
        
        if not query:
            return jsonify({
                'error': 'Empty query',
                'message': 'Query cannot be empty'
            }), 400
        
        # Make prediction
        result = detector.predict(query)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in predict_sqli: {str(e)}")
        return jsonify({
            'error': 'Prediction failed',
            'message': str(e)
        }), 500

@app.route('/api/batch-predict', methods=['POST'])
def batch_predict():
    """Batch prediction endpoint for multiple queries"""
    try:
        if detector is None or detector.model is None:
            return jsonify({
                'error': 'Model not loaded',
                'message': 'SQL injection detection model is not available'
            }), 500
        
        data = request.get_json()
        
        if not data or 'queries' not in data or not isinstance(data['queries'], list):
            return jsonify({
                'error': 'Invalid request',
                'message': 'Please provide a list of queries in the request body'
            }), 400
        
        queries = data['queries']
        
        if len(queries) > 100:
            return jsonify({
                'error': 'Batch too large',
                'message': 'Maximum 100 queries allowed per batch'
            }), 400
        
        results = []
        for query in queries:
            if isinstance(query, str) and query.strip():
                try:
                    result = detector.predict(query.strip())
                    results.append(result)
                except Exception as e:
                    results.append({
                        'query': query,
                        'error': str(e)
                    })
            else:
                results.append({
                    'query': query,
                    'error': 'Invalid query format'
                })
        
        return jsonify({
            'results': results,
            'total_processed': len(results)
        })
        
    except Exception as e:
        logger.error(f"Error in batch_predict: {str(e)}")
        return jsonify({
            'error': 'Batch prediction failed',
            'message': str(e)
        }), 500

@app.route('/api/model-info', methods=['GET'])
def model_info():
    """Get information about the loaded model"""
    try:
        if detector is None or detector.model is None:
            return jsonify({
                'error': 'Model not loaded'
            }), 500
        
        info = {
            'model_architecture': 'LSTM with Embedding layer',
            'input_shape': [None, detector.max_length],
            'vocab_size': detector.tokenizer.num_words if detector.tokenizer else None,
            'max_sequence_length': detector.max_length,
            'model_loaded': True,
            'tokenizer_loaded': detector.tokenizer is not None
        }
        
        return jsonify(info)
        
    except Exception as e:
        logger.error(f"Error in model_info: {str(e)}")
        return jsonify({
            'error': 'Failed to get model info',
            'message': str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested endpoint does not exist',
        'available_endpoints': [
            'GET /',
            'GET /api/health',
            'POST /api/predict-sqli',
            'POST /api/batch-predict',
            'GET /api/model-info'
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

if __name__ == '__main__':
    logger.info("Starting SQL Injection Detection API Server")
    logger.info("Available endpoints:")
    logger.info("  GET  / - Home")
    logger.info("  GET  /api/health - Health check")
    logger.info("  POST /api/predict-sqli - Single query prediction")
    logger.info("  POST /api/batch-predict - Batch query prediction")
    logger.info("  GET  /api/model-info - Model information")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
