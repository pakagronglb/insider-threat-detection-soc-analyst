from src.ingest import load_logs
from src.feature_engineer import extract_features
from src.model import detect_anomalies
from src.ai_explainer import explain_anomaly
import json
import os
import pandas as pd

def format_file_size(size_bytes):
    """Format bytes to human-readable format with appropriate units"""
    if size_bytes == 0:
        return "0 B"
        
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while size_bytes >= 1024 and i < len(units) - 1:
        size_bytes /= 1024
        i += 1
    
    # Use whole numbers if the value is large enough
    if size_bytes >= 100:
        return f"{int(size_bytes)} {units[i]}"
    else:
        return f"{size_bytes:.1f} {units[i]}"

def main():
    # Ensure outputs directory exists
    os.makedirs('outputs', exist_ok=True)
    
    # Run log generation
    print("Generating log data...")
    from generate_logs import generate_log_data
    generate_log_data()

    print("Loading logs...")
    df = load_logs('data/simulated_logs.csv')

    print("Extracting features...")
    features = extract_features(df)

    print("Detecting anomalies...")
    results = detect_anomalies(features)

    # Identify suspicious users
    anomalies = results[results['anomaly_score'] == -1].copy()
    
    # Optionally get AI explanations
    print("Generating AI explanations...")
    anomalies['explanation'] = anomalies.apply(lambda row: explain_anomaly(row.to_dict()), axis=1)

    print("Saving results...")
    anomalies.to_json('outputs/anomalies.json', orient='records', indent=2)
    
    # Print summary of suspicious behaviors
    print("\n===== DETECTION RESULTS =====")
    if len(anomalies) > 0:
        print(f"Found {len(anomalies)} suspicious users:")
        for _, row in anomalies.iterrows():
            print(f"- {row['user']} (Department: {row['department']})")
            
            # Show the threat type if using supervised learning
            if 'label' in row and row['label'] != 'normal':
                print(f"  Threat type: {row['label']}")
                
            max_size = row.get('max_file_size', 0)
            total_size = row.get('total_file_size', 0)
            off_hours = row.get('offhours_access_pct', 0)
            cross_dept = row.get('cross_dept_access_pct', 0)
            sensitive = row.get('sensitive_resource_pct', 0)
            
            print(f"  Max file size: {max_size} bytes ({format_file_size(max_size)})")
            print(f"  Off-hours access: {off_hours:.1f}% of activity")
            print(f"  Cross-department access: {cross_dept:.1f}% of file access")
            print(f"  Sensitive resource access: {sensitive:.1f}% of file access")
            print(f"  Total data transferred: {total_size} bytes ({format_file_size(total_size)})")
            
            # Show anomaly probability if available (from supervised learning)
            if 'anomaly_prob' in row:
                print(f"  Confidence score: {row['anomaly_prob']*100:.1f}%")
            
    else:
        print("No suspicious users detected.")
    print("=============================")
    
    # Check if we're using supervised learning and have threat analysis
    threat_analysis_path = 'outputs/threat_analysis.csv'
    if os.path.exists(threat_analysis_path):
        threat_df = pd.read_csv(threat_analysis_path)
        print("\n===== THREAT TYPE ANALYSIS =====")
        for _, row in threat_df.iterrows():
            user = row['user']
            predicted_threat = row['predicted_threat']
            
            # Get the probability columns
            prob_columns = [c for c in row.index if c.startswith('prob_')]
            
            print(f"User: {user}")
            print(f"  Predicted threat type: {predicted_threat}")
            print("  Threat probabilities:")
            for col in prob_columns:
                threat_type = col.replace('prob_', '')
                print(f"    - {threat_type}: {row[col]*100:.1f}%")
            print()
        print("================================")
    
    # Check if we have feature importance analysis
    feature_imp_path = 'outputs/feature_importances.csv'
    if os.path.exists(feature_imp_path):
        importance_df = pd.read_csv(feature_imp_path)
        print("\n===== TOP FEATURES FOR DETECTION =====")
        for _, row in importance_df.head(5).iterrows():
            print(f"- {row['feature']}: {row['importance']:.4f}")
        print("======================================")

if __name__ == '__main__':
    main()
