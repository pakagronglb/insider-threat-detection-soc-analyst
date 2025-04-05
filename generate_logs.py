import pandas as pd
import numpy as np
from datetime import datetime, timedelta, time
import os

def generate_log_data(num_users=10, days=7, output_path='data/simulated_logs.csv'):
    np.random.seed(42)
    
    # Define departments/roles
    departments = ['IT', 'HR', 'Finance', 'Marketing', 'Sales', 'Engineering', 'Executive']
    
    # Create normal users with assigned departments
    users = []
    for i in range(num_users):
        user_id = f'user_{i+1}'
        dept = np.random.choice(departments)
        users.append((user_id, dept, 'normal'))
    
    # Add suspicious users with departments and labels
    users.append(('suspicious_downloader', 'Finance', 'mass_downloader'))
    users.append(('suspicious_offhours', 'IT', 'off_hours_access'))
    
    # Add a privileged user doing suspicious activities
    users.append(('admin_suspicious', 'IT', 'privilege_abuse'))
    
    # Add an HR employee accessing sensitive files
    users.append(('hr_suspicious', 'HR', 'data_snooping'))
    
    base_time = datetime.now() - timedelta(days=days)
    events = ['login', 'file_access', 'email', 'usb_usage']
    
    rows = []

    for user, department, label in users:
        if label == 'mass_downloader':
            # Generate suspicious mass download behavior
            num_logs = np.random.randint(30, 50)  # Fewer logs but many downloads
            for _ in range(num_logs):
                timestamp = base_time + timedelta(seconds=np.random.randint(0, days * 24 * 3600))
                event_type = np.random.choice(['login', 'file_access'], p=[0.1, 0.9])  # Mostly file access
                
                # Generate large file sizes for downloads
                file_size = np.random.randint(50000, 200000) if event_type == 'file_access' else ''
                
                # Add more metadata about the files being accessed
                resource = "financial_reports" if event_type == 'file_access' else ''
                
                rows.append({
                    'user': user,
                    'department': department,
                    'timestamp': timestamp.isoformat(),
                    'event_type': event_type,
                    'file_size': file_size,
                    'resource': resource,
                    'label': label
                })
                
        elif label == 'off_hours_access':
            # Generate suspicious off-hours access
            num_logs = np.random.randint(50, 100)
            for _ in range(num_logs):
                # Create timestamps during night hours (10 PM - 4 AM)
                day_offset = np.random.randint(0, days)
                hour = np.random.randint(22, 28) % 24  # 22, 23, 0, 1, 2, 3
                minute = np.random.randint(0, 60)
                
                timestamp = base_time + timedelta(days=day_offset, 
                                                  hours=hour, 
                                                  minutes=minute)
                
                event_type = np.random.choice(events)
                file_size = np.random.randint(100, 20000) if event_type == 'file_access' else ''
                resource = "server_logs" if event_type == 'file_access' else ''
                
                rows.append({
                    'user': user,
                    'department': department,
                    'timestamp': timestamp.isoformat(),
                    'event_type': event_type,
                    'file_size': file_size,
                    'resource': resource,
                    'label': label
                })
                
        elif label == 'privilege_abuse':
            # IT admin accessing resources they shouldn't need
            num_logs = np.random.randint(70, 120)
            for _ in range(num_logs):
                day_offset = np.random.randint(0, days)
                hour = np.random.randint(9, 18)  # Normal hours
                minute = np.random.randint(0, 60)
                
                timestamp = base_time + timedelta(days=day_offset, 
                                                 hours=hour, 
                                                 minutes=minute)
                
                event_type = np.random.choice(['login', 'file_access'], p=[0.2, 0.8])
                file_size = np.random.randint(100, 5000) if event_type == 'file_access' else ''
                
                # Admin accessing HR and Finance resources
                resources = ['payroll_data', 'employee_reviews', 'salary_info', 'hr_database']
                resource = np.random.choice(resources) if event_type == 'file_access' else ''
                
                rows.append({
                    'user': user,
                    'department': department,
                    'timestamp': timestamp.isoformat(),
                    'event_type': event_type,
                    'file_size': file_size,
                    'resource': resource,
                    'label': label
                })
                
        elif label == 'data_snooping':
            # HR employee looking at files they shouldn't need
            num_logs = np.random.randint(80, 150)
            for _ in range(num_logs):
                day_offset = np.random.randint(0, days)
                hour = np.random.randint(9, 18)  # Normal hours
                minute = np.random.randint(0, 60)
                
                timestamp = base_time + timedelta(days=day_offset, 
                                                 hours=hour, 
                                                 minutes=minute)
                
                event_type = np.random.choice(events, p=[0.3, 0.5, 0.1, 0.1])
                file_size = np.random.randint(100, 3000) if event_type == 'file_access' else ''
                
                # HR person accessing executive files they shouldn't need
                resources = ['executive_meeting_notes', 'strategic_plans', 'acquisition_plans']
                resource = np.random.choice(resources) if event_type == 'file_access' else ''
                
                rows.append({
                    'user': user,
                    'department': department,
                    'timestamp': timestamp.isoformat(),
                    'event_type': event_type,
                    'file_size': file_size,
                    'resource': resource,
                    'label': label
                })
                
        else:  # Normal users
            # Normal user behavior
            num_logs = np.random.randint(100, 300)
            for _ in range(num_logs):
                # Generate timestamps during normal work hours (9 AM - 5 PM)
                day_offset = np.random.randint(0, days)
                hour = np.random.randint(9, 18)  # 9 AM to 5 PM
                minute = np.random.randint(0, 60)
                
                timestamp = base_time + timedelta(days=day_offset, 
                                                hours=hour, 
                                                minutes=minute)
                
                event_type = np.random.choice(events, p=[0.4, 0.3, 0.2, 0.1])
                file_size = np.random.randint(100, 20000) if event_type == 'file_access' else ''
                
                # Resource access based on department
                resource = ''
                if event_type == 'file_access':
                    if department == 'IT':
                        resource = np.random.choice(['server_logs', 'network_configs', 'system_backups'])
                    elif department == 'HR':
                        resource = np.random.choice(['employee_records', 'hiring_docs', 'benefits_info'])
                    elif department == 'Finance':
                        resource = np.random.choice(['invoices', 'budget_reports', 'expense_claims'])
                    elif department == 'Marketing':
                        resource = np.random.choice(['campaign_assets', 'market_research', 'brand_guidelines'])
                    elif department == 'Sales':
                        resource = np.random.choice(['customer_data', 'sales_reports', 'lead_lists'])
                    elif department == 'Engineering':
                        resource = np.random.choice(['product_specs', 'code_repos', 'design_docs'])
                    elif department == 'Executive':
                        resource = np.random.choice(['board_minutes', 'strategy_docs', 'performance_reviews'])
                
                rows.append({
                    'user': user,
                    'department': department,
                    'timestamp': timestamp.isoformat(),
                    'event_type': event_type,
                    'file_size': file_size,
                    'resource': resource,
                    'label': label
                })

    # Ensure data folder exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)
    print(f"[✔] Log data generated: {output_path}")
    
    # Save a separate file with just the labels for supervised learning
    labels_df = df[['user', 'department', 'label']].drop_duplicates()
    labels_df.to_csv('data/user_labels.csv', index=False)
    print(f"[✔] User labels saved for supervised learning: data/user_labels.csv")

if __name__ == "__main__":
    generate_log_data()
