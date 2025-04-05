# Insider Threat Detection System 🐞

A Python application that generates simulated logs and detects suspicious user behaviour patterns that may indicate insider threats.

## Features ✨

- Simulates user logs including normal and suspicious activity patterns
- Detects various suspicious behaviors:
  - Mass downloads (unusual file sizes and high volume)
  - Off-hours access (activity outside normal working hours)
  - Cross-department resource access (users accessing resources from other departments)
  - Sensitive data access (accessing restricted files)
  - USB usage patterns
  - Email activity patterns
- Department/role-based analysis to identify suspicious access patterns
- Supervised learning with labeled data to identify known threat types:
  - Mass downloaders
  - Off-hours access
  - Privilege abuse (IT admins accessing HR/Finance data)
  - Data snooping (accessing data outside job responsibilities)
- Unsupervised learning for detecting novel anomalies
- Detailed threat type analysis and feature importance

## Setup 📦

1. Clone this repository
2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. (Optional) Set up a DeepSeek API key in `.env` file for AI explanations:
   ```
   DEEPSEEK_API_KEY=your_api_key_here
   ```

## Running the Application 🚀

Simply run the main script which will:
1. Generate simulated log data
2. Process the logs to extract features
3. Detect anomalous behaviors
4. Save results to the outputs directory

```
python main.py
```

## Understanding the Results 📝

The application will output results to the console and save detailed findings to several files:

- `outputs/anomalies.json` - Detailed anomaly information
- `outputs/feature_importances.csv` - Which features are most important for detection
- `outputs/threat_analysis.csv` - Analysis of different threat types
- `outputs/threat_type_mapping.csv` - Mapping of threat type labels

The console output will show:
- Number of suspicious users detected
- User IDs, departments, and threat types of suspicious users
- Key metrics for each suspicious user:
  - Maximum file size downloaded
  - Percentage of off-hours access
  - Cross-department access percentage
  - Sensitive resource access percentage
  - Total data volume accessed
  - Confidence score (with supervised learning)
- Threat type analysis with probabilities
- Top features for detection

## Customisation ⚙️

You can modify the suspicious behavior thresholds and department definitions in:
- `src/ai_explainer.py` - For explanation thresholds 
- `generate_logs.py` - For simulating different suspicious patterns
- `src/feature_engineer.py` - For department-specific resource patterns

## Example Output ✍🏻

```
===== DETECTION RESULTS =====
Found 4 suspicious users:
- suspicious_downloader (Department: Finance)
  Threat type: mass_downloader
  Max file size: 198117 bytes (193 KB)
  Off-hours access: 23.4% of activity
  Cross-department access: 0.0% of file access
  Sensitive resource access: 100.0% of file access
  Total data transferred: 4596760 bytes (4.4 MB)
  Confidence score: 98.7%
- suspicious_offhours (Department: IT)
  Threat type: off_hours_access
  Max file size: 15711 bytes (15.3 KB)
  Off-hours access: 70.0% of activity
  Cross-department access: 0.0% of file access
  Sensitive resource access: 0.0% of file access
  Total data transferred: 99843 bytes (97.5 KB)
  Confidence score: 92.1%
=============================

===== THREAT TYPE ANALYSIS =====
User: suspicious_downloader
  Predicted threat type: mass_downloader
  Threat probabilities:
    - mass_downloader: 87.5%
    - off_hours_access: 5.2%
    - privilege_abuse: 4.1%
    - data_snooping: 3.2%

User: suspicious_offhours
  Predicted threat type: off_hours_access
  Threat probabilities:
    - mass_downloader: 6.3%
    - off_hours_access: 82.1%
    - privilege_abuse: 6.8%
    - data_snooping: 4.8%
================================

===== TOP FEATURES FOR DETECTION =====
- offhours_access_pct: 0.4236
- max_file_size: 0.3427
- total_file_size: 0.1854
- sensitive_resource_pct: 0.0215
- cross_dept_access_pct: 0.0178
======================================
```

```
python data/simulated_logs.py
```
