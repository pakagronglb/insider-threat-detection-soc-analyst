import pandas as pd
import numpy as np
from datetime import datetime
from collections import Counter

def extract_features(df):
    # Convert the timestamp column to datetime if it isn't already
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Extract hour from timestamp
    df['hour'] = df['timestamp'].dt.hour
    
    # Define off-hours (10 PM - 4 AM)
    df['is_offhours'] = df['hour'].apply(lambda h: h >= 22 or h < 4)
    
    # Basic user activity aggregations
    features = df.groupby(['user', 'department']).agg(
        total_logs=('event_type', 'count'),
        login_count=('event_type', lambda x: (x == 'login').sum()),
        file_access_count=('event_type', lambda x: (x == 'file_access').sum()),
        email_count=('event_type', lambda x: (x == 'email').sum()),
        usb_usage_count=('event_type', lambda x: (x == 'usb_usage').sum()),
        avg_file_size=('file_size', 'mean'),
        max_file_size=('file_size', 'max'),
        total_file_size=('file_size', lambda x: pd.to_numeric(x, errors='coerce').fillna(0).sum()),
        offhours_access_count=('is_offhours', lambda x: x.sum()),
        unique_resources=('resource', lambda x: len(set(x)))
    ).reset_index()
    
    # Calculate percentage of off-hours activity
    features['offhours_access_pct'] = features['offhours_access_count'] / features['total_logs'] * 100
    
    # Fill missing values
    features['avg_file_size'] = features['avg_file_size'].fillna(0)
    features['max_file_size'] = features['max_file_size'].fillna(0)
    
    # Add department-specific resource access features
    features = add_department_access_features(df, features)
    
    # Add label if it exists in the dataframe
    if 'label' in df.columns:
        label_map = df.groupby('user')['label'].first().to_dict()
        features['label'] = features['user'].map(label_map)
    
    return features

def add_department_access_features(df, features_df):
    """Calculate features related to accessing resources from other departments"""
    # Identify typical resource access patterns by department
    dept_typical_resources = {
        'IT': ['server_logs', 'network_configs', 'system_backups'],
        'HR': ['employee_records', 'hiring_docs', 'benefits_info'],
        'Finance': ['invoices', 'budget_reports', 'expense_claims'],
        'Marketing': ['campaign_assets', 'market_research', 'brand_guidelines'],
        'Sales': ['customer_data', 'sales_reports', 'lead_lists'],
        'Engineering': ['product_specs', 'code_repos', 'design_docs'],
        'Executive': ['board_minutes', 'strategy_docs', 'performance_reviews']
    }
    
    # Additional suspicious resource patterns
    sensitive_resources = [
        'payroll_data', 'employee_reviews', 'salary_info', 'hr_database',
        'executive_meeting_notes', 'strategic_plans', 'acquisition_plans',
        'financial_reports'
    ]
    
    # Calculate cross-department access for each user
    users_depts = features_df.set_index('user')['department'].to_dict()
    
    # Initialize new features
    features_df['cross_dept_access_count'] = 0
    features_df['sensitive_resource_access'] = 0
    
    # Loop through each user
    for user, group in df.groupby('user'):
        if user not in users_depts:
            continue
            
        dept = users_depts[user]
        
        # Count resources accessed from other departments
        cross_dept_count = 0
        sensitive_access = 0
        
        # Create a counter of resources accessed by this user
        resource_counts = Counter(group['resource'].dropna())
        
        # Count the cross-department accesses
        for resource, count in resource_counts.items():
            resource_found = False
            
            # Check if this resource belongs to user's department
            if dept in dept_typical_resources:
                if resource in dept_typical_resources[dept]:
                    resource_found = True
            
            # If resource doesn't belong to user's dept, increment counter
            if not resource_found and resource:
                cross_dept_count += count
            
            # Check for sensitive resource access
            if resource in sensitive_resources:
                sensitive_access += count
        
        # Update the features dataframe
        idx = features_df[features_df['user'] == user].index
        if len(idx) > 0:
            features_df.loc[idx, 'cross_dept_access_count'] = cross_dept_count
            features_df.loc[idx, 'sensitive_resource_access'] = sensitive_access
    
    # Calculate percentage of cross-department access
    features_df['cross_dept_access_pct'] = (features_df['cross_dept_access_count'] / 
                                           features_df['file_access_count'] * 100)
    features_df['cross_dept_access_pct'] = features_df['cross_dept_access_pct'].fillna(0)
    
    # Calculate percentage of sensitive resource access
    features_df['sensitive_resource_pct'] = (features_df['sensitive_resource_access'] / 
                                           features_df['file_access_count'] * 100)
    features_df['sensitive_resource_pct'] = features_df['sensitive_resource_pct'].fillna(0)
    
    return features_df
