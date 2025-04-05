import requests
import os
import dotenv

dotenv.load_dotenv()

def explain_anomaly(user_data):
    try:
        url = "https://api.deepseek.com/v1/generate"
        headers = {
            "Authorization": os.getenv("DEEPSEEK_API_KEY"),
            "Content-Type": "application/json"
        }
        prompt = f"Explain why this user's behavior is anomalous: {user_data}"
        payload = {
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}]
        }

        response = requests.post(url, headers=headers, json=payload)
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        # If API call fails, provide a basic explanation based on data
        explanation = "Potential suspicious behavior detected: "
        
        if 'max_file_size' in user_data and user_data['max_file_size'] > 50000:
            explanation += f"Unusually large file downloads ({user_data['max_file_size']} bytes). "
            
        if 'offhours_access_pct' in user_data and user_data['offhours_access_pct'] > 10:
            explanation += f"Significant off-hours activity ({user_data['offhours_access_pct']:.2f}%). "
            
        if 'total_file_size' in user_data and user_data['total_file_size'] > 500000:
            explanation += f"High volume of data transferred ({user_data['total_file_size']} bytes)."
            
        return explanation
