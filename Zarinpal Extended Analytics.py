# 🟢 Zarinpal Python Analytics & Management - Ultra Secure Edition 🟢
# Version: 1.2
# --------------------------------------------------------
# Author: Adapted for integration with Zarinpal Dart SDK v3.8
# Enhancements (Version 1.2):
# - Added fraud detection using Isolation Forest for anomaly detection
# - Optimized XGBoost model with feature engineering, early stopping, and Bayesian optimization
# - Implemented model persistence for faster deployment
# - Enhanced REST API with fraud detection endpoint and performance metrics
# - Improved data validation and scalability for large datasets
# Dependencies: cryptography, pandas, matplotlib, seaborn, xgboost, scikit-learn, fastapi, uvicorn, optuna, joblib

import json
import base64
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging
from fastapi import FastAPI, HTTPException
import uvicorn
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
import numpy as np
from typing import List, Dict, Optional
import os
import io
import base64 as b64
import joblib
import optuna

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('zarinpal_analytics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Encryption key (must match Dart SDK's encryption key)
ENCRYPTION_KEY = os.getenv("ZARINPAL_ENCRYPTION_KEY", "your-secure-key-here").encode('utf-8')  # Use env variable
HISTORY_FILE = "zarinpal_history.json"
MODEL_FILE = "zarinpal_xgboost_model.joblib"

# Zarinpal API endpoints
ZARINPAL_API = {
    "production": "https://api.zarinpal.com/pg/v4/payment",
    "sandbox": "https://sandbox.zarinpal.com/pg/v4/payment"
}

# Zarinpal data models (mirroring Dart SDK)
class PaymentVerify:
    def __init__(self, code: int, message: str, ref_id: int, card_pan: str, authority: str, timestamp: Optional[datetime] = None):
        self.code = code
        self.message = message
        self.ref_id = ref_id
        self.card_pan = card_pan
        self.authority = authority
        self.timestamp = timestamp or datetime.now()

class TransactionAnalysis:
    def __init__(self):
        self.transactions: List[PaymentVerify] = []
        self.model = None
        self.is_trained = False
        self.fraud_detector = IsolationForest(contamination=0.05, random_state=42)

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data using AES (matching Dart SDK's encryption)."""
        try:
            parts = encrypted_data.split(':')
            if len(parts) != 2:
                raise ValueError("Invalid encrypted data format")
            iv = base64.b64decode(parts[0])
            encrypted = base64.b64decode(parts[1])
            cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted) + decryptor.finalize()
            padding_length = padded_data[-1]
            return padded_data[:-padding_length].decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

    def load_transaction_history(self) -> None:
        """Load and decrypt transaction history from file."""
        if not os.path.exists(HISTORY_FILE):
            logger.warning("Transaction history file not found.")
            return
        try:
            with open(HISTORY_FILE, 'r') as f:
                encrypted_data = f.read()
            json_str = self.decrypt_data(encrypted_data)
            data = json.loads(json_str)
            self.transactions = [
                PaymentVerify(
                    code=tx.get('code', 0),
                    message=tx.get('message', ''),
                    ref_id=tx.get('ref_id', 0),
                    card_pan=self.decrypt_data(tx.get('card_pan', '')),
                    authority=tx.get('authority', ''),
                    timestamp=datetime.fromisoformat(tx.get('timestamp', datetime.now().isoformat())) if tx.get('timestamp') else None
                )
                for tx in data
            ]
            logger.info(f"Loaded {len(self.transactions)} transactions from history.")
        except Exception as e:
            logger.error(f"Failed to load transaction history: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to load history: {str(e)}")

    def analyze_transactions(self, amount_data: List[Dict]) -> Dict:
        """Analyze transaction data and return detailed insights."""
        if not self.transactions:
            logger.warning("No transactions available for analysis.")
            return {"error": "No transactions available"}

        # Combine transaction and amount data
        df = pd.DataFrame([
            {
                'code': tx.code,
                'ref_id': tx.ref_id,
                'authority': tx.authority,
                'is_success': tx.code in [100, 101],
                'timestamp': tx.timestamp,
                'card_prefix': tx.card_pan[:6] if tx.card_pan else 'Unknown',
                'failure_reason': tx.message if tx.code not in [100, 101] else None,
                'amount': data['amount'],
                'is_toman': data['currency'] == 'toman'
            }
            for tx, data in zip(self.transactions, amount_data)
        ])

        # Basic statistics
        total_transactions = len(df)
        success_rate = df['is_success'].mean() * 100
        failed_transactions = total_transactions - df['is_success'].sum()
        median_amount = df['amount'].median()

        # Time-based analysis
        df['hour'] = df['timestamp'].apply(lambda x: x.hour)
        df['day'] = df['timestamp'].apply(lambda x: x.day)
        df['month'] = df['timestamp'].apply(lambda x: x.month)
        hourly_success = df.groupby('hour')['is_success'].mean() * 100
        daily_success = df.groupby('day')['is_success'].mean() * 100

        # Card usage patterns
        card_usage = df['card_prefix'].value_counts().to_dict()

        # Failure reason analysis
        failure_reasons = df[df['failure_reason'].notnull()]['failure_reason'].value_counts().to_dict()

        # Transaction frequency (per card)
        transaction_frequency = df.groupby('card_prefix')['timestamp'].count().to_dict()

        # Visualizations
        # 1. Success rate pie chart
        plt.figure(figsize=(6, 6))
        plt.pie(
            [success_rate / 100, 1 - success_rate / 100],
            labels=['Successful', 'Failed'],
            colors=['#4CAF50', '#F44336'],
            autopct='%1.1f%%'
        )
        plt.title('Transaction Success Rate')
        success_rate_path = 'success_rate.png'
        plt.savefig(success_rate_path)
        plt.close()

        # 2. Hourly success rate line plot
        plt.figure(figsize=(10, 6))
        sns.lineplot(x=hourly_success.index, y=hourly_success.values, marker='o')
        plt.title('Success Rate by Hour')
        plt.xlabel('Hour of Day')
        plt.ylabel('Success Rate (%)')
        hourly_success_path = 'hourly_success.png'
        plt.savefig(hourly_success_path)
        plt.close()

        # 3. Amount distribution histogram
        plt.figure(figsize=(10, 6))
        sns.histplot(df['amount'], bins=30, kde=True)
        plt.title('Transaction Amount Distribution')
        plt.xlabel('Amount')
        plt.ylabel('Frequency')
        amount_distribution_path = 'amount_distribution.png'
        plt.savefig(amount_distribution_path)
        plt.close()

        # Convert plots to base64
        def plot_to_base64(plot_path: str) -> str:
            with open(plot_path, 'rb') as f:
                return b64.b64encode(f.read()).decode('utf-8')

        logger.info(f"Analysis completed: {total_transactions} transactions, {success_rate:.1f}% success rate")
        return {
            "total_transactions": total_transactions,
            "success_rate": round(success_rate, 1),
            "failed_transactions": failed_transactions,
            "median_amount": median_amount,
            "hourly_success": hourly_success.to_dict(),
            "daily_success": daily_success.to_dict(),
            "card_usage": card_usage,
            "failure_reasons": failure_reasons,
            "transaction_frequency": transaction_frequency,
            "plots": {
                "success_rate": plot_to_base64(success_rate_path),
                "hourly_success": plot_to_base64(hourly_success_path),
                "amount_distribution": plot_to_base64(amount_distribution_path)
            }
        }

    def detect_fraud(self, amount_data: List[Dict]) -> List[Dict]:
        """Detect potential fraud using Isolation Forest."""
        if not self.transactions:
            logger.warning("No transactions available for fraud detection.")
            return []

        df = pd.DataFrame([
            {
                'amount': data['amount'],
                'is_toman': data['currency'] == 'toman',
                'hour': tx.timestamp.hour,
                'card_prefix': tx.card_pan[:6] if tx.card_pan else 'Unknown',
                'transaction_count': len([t for t in self.transactions if t.card_pan[:6] == tx.card_pan[:6]]),
                'time_since_last': (
                    (tx.timestamp - min([t.timestamp for t in self.transactions if t.card_pan[:6] == tx.card_pan[:6] and t.timestamp < tx.timestamp], default=tx.timestamp)).total_seconds() / 60
                    if any(t.card_pan[:6] == tx.card_pan[:6] and t.timestamp < tx.timestamp for t in self.transactions)
                    else 1000
                ),
                'is_success': tx.code in [100, 101],
                'authority': tx.authority
            }
            for tx, data in zip(self.transactions, amount_data)
        ])

        # Features for fraud detection
        features = df[['amount', 'is_toman', 'hour', 'transaction_count', 'time_since_last']]
        self.fraud_detector.fit(features)
        df['is_anomaly'] = self.fraud_detector.predict(features) == -1  # -1 indicates anomaly
        fraud_cases = df[df['is_anomaly']][['authority', 'amount', 'hour', 'transaction_count', 'time_since_last']].to_dict('records')
        logger.info(f"Detected {len(fraud_cases)} potential fraud cases.")
        return fraud_cases

    def train_model(self, amount_data: List[Dict]) -> Dict:
        """Train an optimized XGBoost model to predict transaction success."""
        if not self.transactions:
            logger.error("Cannot train model: No transaction data available.")
            raise HTTPException(status_code=400, detail="No transaction data for training")

        # Feature engineering
        df = pd.DataFrame([
            {
                'amount': data['amount'],
                'is_toman': data['currency'] == 'toman',
                'hour': tx.timestamp.hour,
                'card_prefix': tx.card_pan[:6] if tx.card_pan else 'Unknown',
                'transaction_count': len([t for t in self.transactions if t.card_pan[:6] == tx.card_pan[:6]]),
                'time_since_last': (
                    (tx.timestamp - min([t.timestamp for t in self.transactions if t.card_pan[:6] == tx.card_pan[:6] and t.timestamp < tx.timestamp], default=tx.timestamp)).total_seconds() / 60
                    if any(t.card_pan[:6] == tx.card_pan[:6] and t.timestamp < tx.timestamp for t in self.transactions)
                    else 1000
                ),
                'is_success': tx.code in [100, 101]
            }
            for tx, data in zip(self.transactions, amount_data)
        ])

        # Encode card_prefix as categorical
        df['card_prefix'] = df['card_prefix'].astype('category').cat.codes

        X = df[['amount', 'is_toman', 'hour', 'card_prefix', 'transaction_count', 'time_since_last']]
        y = df['is_success']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Bayesian optimization with Optuna
        def objective(trial):
            params = {
                'n_estimators': trial.suggest_int('n_estimators', 50, 300),
                'max_depth': trial.suggest_int('max_depth', 3, 10),
                'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3),
                'subsample': trial.suggest_float('subsample', 0.5, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.5, 1.0)
            }
            model = XGBClassifier(**params, random_state=42, early_stopping_rounds=10)
            model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
            return model.score(X_test, y_test)

        study = optuna.create_study(direction='maximize')
        study.optimize(objective, n_trials=20)
        best_params = study.best_params

        # Train final model with early stopping
        self.model = XGBClassifier(**best_params, random_state=42, early_stopping_rounds=10)
        self.model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
        self.is_trained = True

        # Save model
        joblib.dump(self.model, MODEL_FILE)
        logger.info(f"Model saved to {MODEL_FILE}")

        # Evaluate model
        predictions = self.model.predict(X_test)
        report = classification_report(y_test, predictions, output_dict=True)

        # Feature importance
        feature_importance = dict(zip(X.columns, self.model.feature_importances_))
        logger.info(f"Model trained. Best params: {best_params}, Report: {report}")
        return {
            "status": "success",
            "best_params": best_params,
            "classification_report": report,
            "feature_importance": feature_importance
        }

    def load_model(self) -> None:
        """Load a trained model from file."""
        if os.path.exists(MODEL_FILE):
            self.model = joblib.load(MODEL_FILE)
            self.is_trained = True
            logger.info(f"Model loaded from {MODEL_FILE}")
        else:
            logger.warning("No trained model found.")
            self.is_trained = False

    def predict_transaction(self, amount: int, currency: str, card_pan: str = "Unknown", timestamp: Optional[datetime] = None) -> Dict:
        """Predict transaction success probability."""
        if not self.is_trained:
            logger.error("Model not trained.")
            raise HTTPException(status_code=400, detail="Model not trained")

        hour = (timestamp or datetime.now()).hour
        is_toman = currency == 'toman'
        card_prefix = card_pan[:6] if card_pan else "Unknown"
        card_prefix_code = hash(card_prefix) % 1000
        transaction_count = len([t for t in self.transactions if t.card_pan[:6] == card_prefix])
        time_since_last = 1000  # Default for single transaction
        if transaction_count > 1:
            last_timestamp = max([t.timestamp for t in self.transactions if t.card_pan[:6] == card_prefix and t.timestamp < (timestamp or datetime.now())], default=timestamp or datetime.now())
            time_since_last = ((timestamp or datetime.now()) - last_timestamp).total_seconds() / 60

        features = np.array([[amount, is_toman, hour, card_prefix_code, transaction_count, time_since_last]])
        probability = self.model.predict_proba(features)[0][1]
        logger.info(f"Prediction for amount={amount}, currency={currency}, card_prefix={card_prefix}: {probability:.2f}")
        return {"success_probability": round(probability * 100, 2)}

    def suggest_retries(self) -> List[Dict]:
        """Suggest transactions for retry based on failure patterns."""
        df = pd.DataFrame([
            {
                'authority': tx.authority,
                'code': tx.code,
                'message': tx.message,
                'timestamp': tx.timestamp
            }
            for tx in self.transactions if tx.code not in [100, 101]
        ])
        if df.empty:
            return []

        recent_failures = df[df['timestamp'] > datetime.now() - timedelta(hours=1)]
        retry_suggestions = recent_failures[['authority', 'message']].to_dict('records')
        logger.info(f"Suggested {len(retry_suggestions)} transactions for retry.")
        return retry_suggestions

# FastAPI setup
app = FastAPI(title="Zarinpal Analytics API")

analysis = TransactionAnalysis()

@app.get("/load_history")
async def load_history():
    """Load transaction history from file."""
    try:
        analysis.load_transaction_history()
        return {"status": "success", "message": f"Loaded {len(analysis.transactions)} transactions"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error loading history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analyze")
async def analyze_transactions():
    """Analyze transaction data and return insights."""
    try:
        # Placeholder: Update with actual amount_data from API or Dart SDK
        amount_data = [{"amount": 10000, "currency": "toman"}] * len(analysis.transactions)
        results = analysis.analyze_transactions(amount_data)
        return results
    except Exception as e:
        logger.error(f"Error analyzing transactions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/train_model")
async def train_model(amount_data: List[Dict]):
    """Train the machine learning model with transaction amounts and currencies."""
    try:
        results = analysis.train_model(amount_data)
        return results
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error training model: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict")
async def predict_transaction(amount: int, currency: str, card_pan: Optional[str] = "Unknown"):
    """Predict transaction success probability."""
    try:
        result = analysis.predict_transaction(amount, currency, card_pan)
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error predicting transaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/retry_suggestions")
async def get_retry_suggestions():
    """Get suggestions for retrying failed transactions."""
    try:
        suggestions = analysis.suggest_retries()
        return {"status": "success", "retry_suggestions": suggestions}
    except Exception as e:
        logger.error(f"Error getting retry suggestions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/detect_fraud")
async def detect_fraud():
    """Detect potential fraud cases."""
    try:
        # Placeholder: Update with actual amount_data
        amount_data = [{"amount": 10000, "currency": "toman"}] * len(analysis.transactions)
        fraud_cases = analysis.detect_fraud(amount_data)
        return {"status": "success", "fraud_cases": fraud_cases}
    except Exception as e:
        logger.error(f"Error detecting fraud: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/load_model")
async def load_model():
    """Load a trained model from file."""
    try:
        analysis.load_model()
        return {"status": "success", "message": "Model loaded successfully" if analysis.is_trained else "No model found"}
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Main execution
if __name__ == "__main__":
    # Example usage
    try:
        analysis.load_transaction_history()
        amount_data = [{"amount": 10000, "currency": "toman"}] * max(len(analysis.transactions), 1)
        results = analysis.analyze_transactions(amount_data)
        print(f"Analysis Results: {results}")

        train_results = analysis.train_model(amount_data)
        print(f"Training Results: {train_results}")

        prediction = analysis.predict_transaction(10000, "toman", "1234567890123456")
        print(f"Prediction: {prediction}")

        fraud_cases = analysis.detect_fraud(amount_data)
        print(f"Fraud Cases: {fraud_cases}")

        retry_suggestions = analysis.suggest_retries()
        print(f"Retry Suggestions: {retry_suggestions}")
    except Exception as e:
        logger.error(f"Main execution error: {e}")

    # Start FastAPI server
    uvicorn.run(app, host="0.0.0.0", port=8000)
