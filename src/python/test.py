import pandas as pd
import os

data = {
    'ip_address': ['127.0.0.1'],
    'user_agent': ['Test Agent'],
    'request_data': ['Test data'],
    'detected_attacks': ['None']
}

log_df = pd.DataFrame(data)

log_df.to_csv('user_logs.csv', mode='a', index=False, header=not os.path.isfile('user_logs.csv'))
print("Test log saved to CSV")