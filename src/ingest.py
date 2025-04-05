import pandas as pd

def load_logs(file_path):
    df = pd.read_csv(file_path, parse_dates=['timestamp'])
    return df