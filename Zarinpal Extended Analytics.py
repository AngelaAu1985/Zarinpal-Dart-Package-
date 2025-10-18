# -------------------------------------------------------------
# 🟢 ZARINPAL EXTENDED ANALYTICS - FIXED + DASHBOARD UI
# -------------------------------------------------------------
# Author: Phoenix Marie (refined)
# Purpose: Extended analytics, forecasting, and intelligent
#          data modeling for Zarinpal Dart SDK transaction data.
# -------------------------------------------------------------

from dataclasses import dataclass
from typing import Optional, Dict
import pandas as pd
import json
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sklearn.linear_model import LinearRegression
import uvicorn
import os
import numpy as np
import datetime
import joblib
import shutil

# -------------------------------------------------------------
# 🧩 DATA MODELS
# -------------------------------------------------------------
@dataclass
class PaymentRequest:
    amount: int
    callback_url: str
    description: str
    email: Optional[str] = None
    mobile: Optional[str] = None


@dataclass
class PaymentResponse:
    code: int
    message: str
    authority: str
    fee_type: Optional[str] = None
    fee: Optional[int] = 0


@dataclass
class PaymentVerify:
    code: int
    message: str
    ref_id: int
    card_pan: str


# -------------------------------------------------------------
# 📊 LOAD AND PREPARE DATA
# -------------------------------------------------------------
def load_transaction_data(file_path: str = "zarinpal_history.json") -> pd.DataFrame:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"⚠️ File not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    df = pd.DataFrame(data)

    # Fix timestamp parsing
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "ref_id" not in df.columns:
        df["ref_id"] = range(1, len(df) + 1)

    if "amount" not in df.columns:
        df["amount"] = 10000

    if "code" not in df.columns:
        df["code"] = 0

    df["is_success"] = (df["code"] == 100).astype(int)
    return df


df = load_transaction_data()

# -------------------------------------------------------------
# 🧠 MACHINE LEARNING MODEL
# -------------------------------------------------------------
if len(df) < 2 or df["is_success"].nunique() < 2:
    class TrivialModel:
        def predict(self, X):
            return np.zeros(len(X))
        def predict_proba(self, X):
            return np.column_stack([np.ones(len(X)), np.zeros(len(X))])
    model = TrivialModel()
    accuracy = 0.0
else:
    X = df[["amount"]]
    y = df["is_success"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)
    accuracy = model.score(X_test, y_test)

print(f"✅ Model Ready — Accuracy: {accuracy:.2f}")

# -------------------------------------------------------------
# 🌐 FASTAPI APP
# -------------------------------------------------------------
app = FastAPI(
    title="Zarinpal Analytics API",
    description="Provides real-time Zarinpal transaction insights, predictions, and visual dashboard.",
    version="3.0",
)

templates = Jinja2Templates(directory="templates")

# -------------------------------------------------------------
# 🧩 UTILITIES
# -------------------------------------------------------------
def save_model(path="zarinpal_model.pkl"):
    try:
        joblib.dump(model, path)
        print(f"💾 Model saved: {path}")
    except Exception as e:
        print("⚠️ Model save failed:", e)


def detect_anomalies(df: pd.DataFrame, threshold: float = 2.5) -> pd.DataFrame:
    if "amount" not in df or df["amount"].isnull().all():
        return pd.DataFrame()
    mean, std = df["amount"].mean(), df["amount"].std(ddof=0)
    if std == 0:
        return pd.DataFrame()
    z = (df["amount"] - mean) / std
    return df.loc[abs(z) > threshold]


def forecast_transaction_trend(df: pd.DataFrame, days_ahead: int = 7) -> Dict[str, int]:
    if "timestamp" not in df or df["timestamp"].isnull().all():
        return {}
    daily = df.groupby(df["timestamp"].dt.date)["ref_id"].count().reset_index(name="count")
    if len(daily) < 2:
        return {}
    daily["ordinal"] = daily["timestamp"].map(lambda x: x.toordinal())
    X, y = daily[["ordinal"]], daily["count"]
    reg = LinearRegression().fit(X, y)
    future_dates = [datetime.date.today() + datetime.timedelta(days=i) for i in range(1, days_ahead + 1)]
    preds = reg.predict(np.array([d.toordinal() for d in future_dates]).reshape(-1, 1))
    return {str(future_dates[i]): int(max(0, round(preds[i]))) for i in range(len(preds))}


# -------------------------------------------------------------
# 🌍 HTML DASHBOARD
# -------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    df_local = load_transaction_data()
    success_rate = (df_local["code"] == 100).mean() * 100
    total_tx = len(df_local)
    anomalies = len(detect_anomalies(df_local))
    forecast = forecast_transaction_trend(df_local, days_ahead=7)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "success_rate": round(success_rate, 2),
            "total_transactions": total_tx,
            "anomalies": anomalies,
            "forecast_labels": list(forecast.keys()),
            "forecast_values": list(forecast.values()),
        },
    )


# -------------------------------------------------------------
# 📡 API ENDPOINTS
# -------------------------------------------------------------
@app.get("/analytics/success_rate")
def get_success_rate():
    df_local = load_transaction_data()
    rate = (df_local["code"] == 100).mean() * 100
    return {"success_rate": round(rate, 2)}


@app.get("/analytics/predict_success")
def predict_success(amount: int):
    X_in = np.array([[amount]])
    pred = int(model.predict(X_in)[0])
    try:
        prob = model.predict_proba(X_in)[0][pred]
    except Exception:
        prob = 0.0
    return {
        "amount": amount,
        "predicted_success": bool(pred),
        "confidence": round(prob * 100, 2),
    }


@app.get("/analytics/forecast")
def get_forecast(days: int = 7):
    df_local = load_transaction_data()
    return forecast_transaction_trend(df_local, days)


@app.get("/analytics/anomalies")
def get_anomalies():
    df_local = load_transaction_data()
    a = detect_anomalies(df_local)
    return {"count": len(a), "records": a.to_dict(orient="records")}


# -------------------------------------------------------------
# 🚀 MAIN
# -------------------------------------------------------------
if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)

    # Create a minimal but stylish dashboard template
    with open("templates/dashboard.html", "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Zarinpal Analytics Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {
  font-family: 'Poppins', sans-serif;
  background: linear-gradient(135deg, #f8f9fa, #e3f2fd);
  color: #222;
  text-align: center;
  margin: 0;
  padding: 40px;
}
h1 {
  color: #1976d2;
}
.metric {
  background: white;
  display: inline-block;
  margin: 15px;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}
canvas {
  margin-top: 30px;
}
footer {
  margin-top: 40px;
  color: #888;
}
</style>
</head>
<body>
<h1>💳 Zarinpal Analytics Dashboard</h1>

<div class="metric">
  <h2>✅ Success Rate</h2>
  <p style="font-size:28px;">{{ success_rate }}%</p>
</div>

<div class="metric">
  <h2>💰 Total Transactions</h2>
  <p style="font-size:28px;">{{ total_transactions }}</p>
</div>

<div class="metric">
  <h2>⚠️ Anomalies Detected</h2>
  <p style="font-size:28px;">{{ anomalies }}</p>
</div>

<canvas id="forecastChart" width="600" height="300"></canvas>

<footer>© 2025 Phoenix Marie | Zarinpal Analytics</footer>

<script>
const ctx = document.getElementById('forecastChart');
const forecastChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: {{ forecast_labels | safe }},
        datasets: [{
            label: 'Predicted Daily Transactions',
            data: {{ forecast_values | safe }},
            borderColor: '#1976d2',
            backgroundColor: 'rgba(25,118,210,0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.3
        }]
    },
    options: {
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } }
    }
});
</script>
</body>
</html>""")

    print("✅ Dashboard template generated successfully.")
    print("🌐 Open http://127.0.0.1:8000 to view analytics dashboard.")
    uvicorn.run(app, host="127.0.0.1", port=8000)