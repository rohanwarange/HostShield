import pandas as pd

csv_file_path = "sample.csv"
df = pd.read_csv(csv_file_path)

user_data_transfer = 'EventName'

prefixes_to_count = ['get', 'put', 'create', 'set','add', 'update', 'modify', 'change', 'attach', 'allocate', 'assign', 'associate']
user_prefix_counts = {}

# Iterates through the DataFrame and update prefix counts for each user ID
for _, row in df.iterrows():
    user_id = row['AccessKeyId']  
    
    if user_id not in user_prefix_counts:
        user_prefix_counts[user_id] = {prefix: 0 for prefix in prefixes_to_count}
    
    # Count the occurrences of each prefix in the specified column
    for prefix in prefixes_to_count:
        text = row[user_data_transfer].lower()
        user_prefix_counts[user_id][prefix] += text.count(prefix)

user_transfer_frequencies = df.groupby('AccessKeyId')[user_data_transfer].apply(lambda x: ', '.join(map(str, x))).reset_index()

for prefix in prefixes_to_count:
    user_transfer_frequencies[f'{prefix}_Count'] = user_transfer_frequencies['AccessKeyId'].map(lambda x: user_prefix_counts.get(x, {}).get(prefix, 0))

user_transfer_frequencies['User_Rating'] = user_transfer_frequencies[[f'{prefix}_Count' for prefix in prefixes_to_count]].sum(axis=1) * 2

user_transfer_frequencies.to_csv('C:/Users/ROHAN/Desktop/InsiderShield-main/userData.csv', index=False)
print(user_transfer_frequencies)


working_starthr = 9
working_endhr = 5

def is_outside_working_hours(timestamp):
    hour = timestamp.hour
    return hour < working_starthr or hour >= working_endhr

login_df = df[df['EventSource'] == 'logs.amazonaws.com']

#Creates a warning column for eventTime outside working hours
login_df['Warning'] = login_df['EventTime'].apply(lambda x: 'Outside Working Hours' if is_outside_working_hours(pd.to_datetime(x)) else '')

user_login_activity_df = login_df[['AccessKeyId','Username', 'EventTime', 'EventSource', 'Warning']].copy()

user_login_activity_df.to_csv('log_data1.csv', index=False)

print(user_login_activity_df)


merged_df = pd.merge(user_login_activity_df, user_transfer_frequencies, on='AccessKeyId', how='inner')

merged_df.to_csv('merged_data.csv', index=False)

print(merged_df)



