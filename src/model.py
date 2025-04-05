from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import os

def detect_anomalies(features_df):
    """
    Detect anomalies using both supervised and unsupervised methods
    depending on whether labeled data is available
    """
    # Check if we have labeled data for supervised learning
    if 'label' in features_df.columns:
        return detect_supervised(features_df)
    else:
        return detect_unsupervised(features_df)

def detect_unsupervised(features_df):
    """Detect anomalies using unsupervised learning (Isolation Forest)"""
    print("Using unsupervised anomaly detection (Isolation Forest)")
    X = features_df.drop(columns=['user', 'department'])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.1, random_state=42)
    features_df['anomaly_score'] = model.fit_predict(X_scaled)  # -1 = anomaly
    return features_df

def detect_supervised(features_df):
    """
    Detect anomalies using supervised learning (Random Forest Classifier)
    Train on existing labeled data to identify known threat patterns
    """
    print("Using supervised anomaly detection (Random Forest Classifier)")
    
    # Create binary target variable (normal vs anomalous)
    features_df['is_anomalous'] = features_df['label'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Save the original labels for later
    original_labels = features_df['label'].copy()
    
    # Feature columns (exclude user, department, label, and is_anomalous)
    feature_cols = [col for col in features_df.columns 
                   if col not in ['user', 'department', 'label', 'is_anomalous']]
    
    # Split into features and target
    X = features_df[feature_cols]
    y = features_df['is_anomalous']
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train classifier
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_scaled, y)
    
    # Get predictions
    features_df['anomaly_prob'] = clf.predict_proba(X_scaled)[:, 1]  # Probability of being anomalous
    features_df['anomaly_score'] = features_df['anomaly_prob'].apply(lambda p: -1 if p > 0.5 else 1)
    
    # Get feature importances
    importances = pd.DataFrame({
        'feature': feature_cols,
        'importance': clf.feature_importances_
    }).sort_values('importance', ascending=False)
    
    # Save feature importances
    os.makedirs('outputs', exist_ok=True)
    importances.to_csv('outputs/feature_importances.csv', index=False)
    print(f"Feature importances saved to outputs/feature_importances.csv")
    
    # Restore original labels
    features_df['label'] = original_labels
    
    # Additional analysis for different types of threats
    if len(set(original_labels)) > 2:  # If we have more than just normal/anomalous
        # Train multi-class classifier to distinguish between different threat types
        print("Training multi-class classifier for threat type identification")
        
        # Encode labels
        le = LabelEncoder()
        threat_labels = le.fit_transform(original_labels)
        
        # Train classifier only on the anomalous data
        anomalous_idx = features_df['is_anomalous'] == 1
        if sum(anomalous_idx) > 1:  # Need at least 2 samples to train
            X_anomalous = X_scaled[anomalous_idx]
            y_anomalous = threat_labels[anomalous_idx]
            
            # Train a classifier to distinguish between types of threats
            threat_clf = RandomForestClassifier(random_state=42)
            threat_clf.fit(X_anomalous, y_anomalous)
            
            # Save the mapping of encoded labels
            label_mapping = {i: label for i, label in enumerate(le.classes_)}
            pd.DataFrame({
                'encoded_value': list(label_mapping.keys()),
                'threat_type': list(label_mapping.values())
            }).to_csv('outputs/threat_type_mapping.csv', index=False)
            
            # Generate predictions for threat types on anomalous data
            anomalous_users = features_df.loc[anomalous_idx, 'user'].values
            
            try:
                # Try to get probability predictions for each class
                threat_probs = threat_clf.predict_proba(X_anomalous)
                
                # Create simple DataFrame with user and predicted threat
                threat_df = pd.DataFrame({
                    'user': anomalous_users,
                    'predicted_threat': le.inverse_transform(threat_clf.predict(X_anomalous))
                })
                
                # Add probability columns one by one to avoid shape issues
                for i, class_name in enumerate(le.classes_):
                    if i < threat_probs.shape[1]:  # Make sure the column exists
                        col_name = f"prob_{class_name}"
                        threat_df[col_name] = threat_probs[:, i]
            except Exception as e:
                print(f"Warning: Could not generate detailed threat probabilities: {e}")
                # Fallback to simpler analysis
                threat_df = pd.DataFrame({
                    'user': anomalous_users,
                    'predicted_threat': le.inverse_transform(threat_clf.predict(X_anomalous))
                })
            
            # Save threat analysis
            threat_df.to_csv('outputs/threat_analysis.csv', index=False)
            print(f"Threat type analysis saved to outputs/threat_analysis.csv")
    
    return features_df
