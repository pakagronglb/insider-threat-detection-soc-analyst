from src.ingest import load_logs
from src.feature_engineer import extract_features
from src.model import detect_anomalies
from src.ai_explainer import explain_anomaly
import json
import os
import pandas as pd
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

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
    print(f"{Fore.CYAN}Generating log data...{Style.RESET_ALL}")
    from generate_logs import generate_log_data
    generate_log_data()

    print(f"{Fore.CYAN}Loading logs...{Style.RESET_ALL}")
    df = load_logs('data/simulated_logs.csv')

    print(f"{Fore.CYAN}Extracting features...{Style.RESET_ALL}")
    features = extract_features(df)

    print(f"{Fore.CYAN}Detecting anomalies...{Style.RESET_ALL}")
    results = detect_anomalies(features)

    # Identify suspicious users
    anomalies = results[results['anomaly_score'] == -1].copy()
    
    # Optionally get AI explanations
    print(f"{Fore.CYAN}Generating AI explanations...{Style.RESET_ALL}")
    anomalies['explanation'] = anomalies.apply(lambda row: explain_anomaly(row.to_dict()), axis=1)

    print(f"{Fore.CYAN}Saving results...{Style.RESET_ALL}")
    anomalies.to_json('outputs/anomalies.json', orient='records', indent=2)
    
    # Print summary of suspicious behaviors
    print(f"\n{Back.RED}{Fore.WHITE} ===== DETECTION RESULTS ===== {Style.RESET_ALL}")
    if len(anomalies) > 0:
        print(f"{Fore.YELLOW}Found {Fore.RED}{len(anomalies)}{Fore.YELLOW} suspicious users:{Style.RESET_ALL}")
        for _, row in anomalies.iterrows():
            # Assign colors based on threat type
            threat_color = Fore.RED  # Default
            if 'label' in row:
                if row['label'] == 'mass_downloader':
                    threat_color = Fore.RED
                elif row['label'] == 'off_hours_access':
                    threat_color = Fore.MAGENTA
                elif row['label'] == 'privilege_abuse':
                    threat_color = Fore.YELLOW
                elif row['label'] == 'data_snooping':
                    threat_color = Fore.BLUE
            
            print(f"- {Fore.LIGHTWHITE_EX}{row['user']}{Style.RESET_ALL} (Department: {Fore.GREEN}{row['department']}{Style.RESET_ALL})")
            
            # Show the threat type if using supervised learning
            if 'label' in row and row['label'] != 'normal':
                print(f"  {Fore.WHITE}Threat type: {threat_color}{row['label']}{Style.RESET_ALL}")
                
            max_size = row.get('max_file_size', 0)
            total_size = row.get('total_file_size', 0)
            off_hours = row.get('offhours_access_pct', 0)
            cross_dept = row.get('cross_dept_access_pct', 0)
            sensitive = row.get('sensitive_resource_pct', 0)
            
            print(f"  {Fore.WHITE}Max file size:{Style.RESET_ALL} {max_size} bytes ({Fore.CYAN}{format_file_size(max_size)}{Style.RESET_ALL})")
            
            # Color-code percentages based on severity
            off_color = Fore.GREEN
            if off_hours > 50:
                off_color = Fore.RED
            elif off_hours > 20:
                off_color = Fore.YELLOW
                
            cross_color = Fore.GREEN
            if cross_dept > 50:
                cross_color = Fore.RED
            elif cross_dept > 20:
                cross_color = Fore.YELLOW
                
            sensitive_color = Fore.GREEN
            if sensitive > 50:
                sensitive_color = Fore.RED
            elif sensitive > 20:
                sensitive_color = Fore.YELLOW
            
            print(f"  {Fore.WHITE}Off-hours access:{Style.RESET_ALL} {off_color}{off_hours:.1f}%{Style.RESET_ALL} of activity")
            print(f"  {Fore.WHITE}Cross-department access:{Style.RESET_ALL} {cross_color}{cross_dept:.1f}%{Style.RESET_ALL} of file access")
            print(f"  {Fore.WHITE}Sensitive resource access:{Style.RESET_ALL} {sensitive_color}{sensitive:.1f}%{Style.RESET_ALL} of file access")
            print(f"  {Fore.WHITE}Total data transferred:{Style.RESET_ALL} {total_size} bytes ({Fore.CYAN}{format_file_size(total_size)}{Style.RESET_ALL})")
            
            # Show anomaly probability if available (from supervised learning)
            if 'anomaly_prob' in row:
                confidence = row['anomaly_prob']*100
                conf_color = Fore.GREEN
                if confidence > 90:
                    conf_color = Fore.RED
                elif confidence > 70:
                    conf_color = Fore.YELLOW
                    
                print(f"  {Fore.WHITE}Confidence score:{Style.RESET_ALL} {conf_color}{confidence:.1f}%{Style.RESET_ALL}")
            
    else:
        print(f"{Fore.GREEN}No suspicious users detected.{Style.RESET_ALL}")
    print(f"{Back.RED}{Fore.WHITE} ============================= {Style.RESET_ALL}")
    
    # Check if we're using supervised learning and have threat analysis
    threat_analysis_path = 'outputs/threat_analysis.csv'
    if os.path.exists(threat_analysis_path):
        threat_df = pd.read_csv(threat_analysis_path)
        print(f"\n{Back.BLUE}{Fore.WHITE} ===== THREAT TYPE ANALYSIS ===== {Style.RESET_ALL}")
        for _, row in threat_df.iterrows():
            user = row['user']
            predicted_threat = row['predicted_threat']
            
            # Get the probability columns
            prob_columns = [c for c in row.index if c.startswith('prob_')]
            
            print(f"{Fore.LIGHTWHITE_EX}User: {Fore.YELLOW}{user}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Predicted threat type: {Fore.RED}{predicted_threat}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Threat probabilities:{Style.RESET_ALL}")
            for col in prob_columns:
                threat_type = col.replace('prob_', '')
                prob_value = row[col]*100
                
                # Color based on probability
                prob_color = Fore.GREEN
                if prob_value > 60:
                    prob_color = Fore.RED
                elif prob_value > 30:
                    prob_color = Fore.YELLOW
                    
                print(f"    - {Fore.CYAN}{threat_type}:{Style.RESET_ALL} {prob_color}{prob_value:.1f}%{Style.RESET_ALL}")
            print()
        print(f"{Back.BLUE}{Fore.WHITE} ================================ {Style.RESET_ALL}")
    
    # Check if we have feature importance analysis
    feature_imp_path = 'outputs/feature_importances.csv'
    if os.path.exists(feature_imp_path):
        importance_df = pd.read_csv(feature_imp_path)
        print(f"\n{Back.GREEN}{Fore.BLACK} ===== TOP FEATURES FOR DETECTION ===== {Style.RESET_ALL}")
        for _, row in importance_df.head(5).iterrows():
            feature_name = row['feature']
            importance = row['importance']
            
            # Gradient of colors based on importance
            imp_color = Fore.GREEN
            if importance > 0.3:
                imp_color = Fore.RED
            elif importance > 0.1:
                imp_color = Fore.YELLOW
                
            print(f"- {Fore.CYAN}{feature_name}:{Style.RESET_ALL} {imp_color}{importance:.4f}{Style.RESET_ALL}")
        print(f"{Back.GREEN}{Fore.BLACK} ====================================== {Style.RESET_ALL}")

if __name__ == '__main__':
    main()
