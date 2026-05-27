import pandas as pd
import numpy as np
import joblib
import os
import sys
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from xgboost import XGBClassifier
DATA_FILE = os.path.join(os.path.dirname(__file__), 'dataset.csv')
MODEL_FILE = os.path.join(os.path.dirname(__file__), 'hybrid_model.pkl')
def initialize_system(tune_hyperparams=False):
    print("=" * 55)
    print("  PHISHING DETECTION — HYBRID MODEL TRAINING")
    print("=" * 55)
    if not os.path.exists(DATA_FILE):
        print(f"[!] Error: {DATA_FILE} not found.")
        print("    Download from: https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector")
        sys.exit(1)
    print(f"\n[1] Loading {DATA_FILE}...")
    data = pd.read_csv(DATA_FILE)
    for col in ['id', 'Index', 'index']:
        if col in data.columns:
            data = data.drop(columns=[col])
    X = data.drop('Result', axis=1)
    y = data['Result'].map({-1: 0, 1: 1}).fillna(data['Result'])
    print(f"    → {X.shape[0]} samples, {X.shape[1]} features")
    print(f"    → Phishing: {(y==1).sum()} | Legitimate: {(y==0).sum()}")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    if tune_hyperparams:
        print("\n[2] Running GridSearchCV for Random Forest...")
        rf_params = {
            "n_estimators": [50, 100, 200],
            "max_depth": [None, 10, 20],
            "min_samples_split": [2, 5],
        }
        rf_grid = GridSearchCV(
            RandomForestClassifier(random_state=42),
            rf_params, cv=3, scoring="accuracy", n_jobs=-1, verbose=1
        )
        rf_grid.fit(X_train, y_train)
        best_rf_params = rf_grid.best_params_
        print(f"    → Best RF params: {best_rf_params}")
        print("\n[2b] Running GridSearchCV for XGBoost...")
        xgb_params = {
            "n_estimators": [100, 200],
            "max_depth": [3, 6],
            "learning_rate": [0.05, 0.1],
        }
        xgb_grid = GridSearchCV(
            XGBClassifier(eval_metric='logloss', random_state=42),
            xgb_params, cv=3, scoring="accuracy", n_jobs=-1, verbose=1
        )
        xgb_grid.fit(X_train, y_train)
        best_xgb_params = xgb_grid.best_params_
        print(f"    → Best XGB params: {best_xgb_params}")
    else:
        print("\n[2] Using pre-tuned hyperparameters (skip --tune to change)...")
        best_rf_params = {"max_depth": None, "min_samples_split": 2, "n_estimators": 200}
        best_xgb_params = {"learning_rate": 0.1, "max_depth": 6, "n_estimators": 200}
    print("\n[3] Building Hybrid Voting Classifier (RF + XGBoost)...")
    rf = RandomForestClassifier(**best_rf_params, random_state=42)
    xgb = XGBClassifier(
        **best_xgb_params,
        eval_metric='logloss',
        random_state=42
    )
    model = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb)],
        voting='soft',
        weights=[1, 1]
    )
    print("[4] Training model...")
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    acc = accuracy_score(y_test, predictions)
    print("\n" + "=" * 55)
    print(f"  ACCURACY  : {acc * 100:.2f}%")
    print("=" * 55)
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["Legitimate", "Phishing"]))
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f"5-Fold Cross-Val Accuracy: {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")
    joblib.dump(model, MODEL_FILE)
    print(f"\n[✓] Model saved to {MODEL_FILE}")
    return model
if __name__ == "__main__":
    tune = "--tune" in sys.argv
    initialize_system(tune_hyperparams=tune)
