import boto3
import datetime
import json
import pandas as pd
import webbrowser
from pytz import timezone
from taipy.gui import Gui, notify

# AWS credentials and configuration
aws_access_key_id = 'AKIA22XP4DXY25GWREI6'
aws_secret_access_key = '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'
aws_region = 'us-west-2'
bucket_name = 'hostshield-security'

session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=aws_region
)
s3 = session.client('s3')
cloudtrail = session.client('cloudtrail')

prefixes_to_include = ["create", "delete", "update", "start", "stop", "terminate", "run",
                       "associate", "assign", "detach", "enable", "authorize", "revoke", "abort",
                       "rebuild", "restart", "swap", "terminate", "apply", "deregister", "add",
                       "console", "enable", "put", "upload", "authorize", "failover"]

# Function to filter and export CloudTrail logs
def filter_and_export_cloudtrail_logs():
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    end_time = utc_now
    start_time = end_time - datetime.timedelta(hours=96)
    response = cloudtrail.lookup_events(StartTime=start_time, EndTime=end_time)

    cloudtrail_column_names = [
        'EventTime',
        'EventName',
        'ReadOnly',
        'Username',
        'ResourceType',
        'ResourceName',
        'EventSource',
        'AccessKeyId',
        'SourceIPAddress',
    ]
    filtered_logs = [cloudtrail_column_names]

    for event in response['Events']:
        event_time = event['EventTime'].replace(tzinfo=None)
        if event_time.hour >= 17 or event_time.hour < 9:
            source_ip = ''
            if 'CloudTrailEvent' in event:
                try:
                    cloudtrail_event = json.loads(event['CloudTrailEvent'])
                    source_ip = cloudtrail_event.get('sourceIPAddress', '')
                except json.JSONDecodeError:
                    pass

            event_name = event['EventName'].lower()
            if any(event_name.startswith(prefix) for prefix in prefixes_to_include) or event_name == "consolelogin":
                event_source_parts = event['EventSource'].split('.')
                resource_name = event_source_parts[0] if len(event_source_parts) > 0 else ''
                csv_row = [
                    event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    event_name,
                    event.get('ReadOnly', ''),
                    event.get('Username', ''),
                    event.get('ResourceType', ''),
                    resource_name,
                    event['EventSource'],
                    event.get('AccessKeyId', ''),
                    source_ip,
                ]
                filtered_logs.append(csv_row)

    return filtered_logs

def lambda_handler(event, context):
    filtered_logs = filter_and_export_cloudtrail_logs()
    cloudtrail_csv_file = '\n'.join([','.join(row) for row in filtered_logs])
    cloudtrail_key = 'fixed-cloudtrail-logs/filtered-cloudtrail.csv'
    s3.put_object(Bucket=bucket_name, Key=cloudtrail_key, Body=cloudtrail_csv_file)

    return {
        'statusCode': 200,
        'body': 'Filtered CloudTrail logs saved as a CSV file in S3.'
    }

# Data processing function
def process_data():
    csv_file_path = "sample.csv"
    df = pd.read_csv(csv_file_path)

    user_data_transfer = 'EventName'
    prefixes_to_count = ['get', 'put', 'create', 'set','add', 'update', 'modify', 'change', 'attach', 'allocate', 'assign', 'associate']
    user_prefix_counts = {}

    for _, row in df.iterrows():
        user_id = row['AccessKeyId']
        if user_id not in user_prefix_counts:
            user_prefix_counts[user_id] = {prefix: 0 for prefix in prefixes_to_count}
        for prefix in prefixes_to_count:
            text = row[user_data_transfer].lower()
            user_prefix_counts[user_id][prefix] += text.count(prefix)

    user_transfer_frequencies = df.groupby('AccessKeyId')[user_data_transfer].apply(lambda x: ', '.join(map(str, x))).reset_index()
    for prefix in prefixes_to_count:
        user_transfer_frequencies[f'{prefix}_Count'] = user_transfer_frequencies['AccessKeyId'].map(lambda x: user_prefix_counts.get(x, {}).get(prefix, 0))
    user_transfer_frequencies['User_Rating'] = user_transfer_frequencies[[f'{prefix}_Count' for prefix in prefixes_to_count]].sum(axis=1) * 2
    user_transfer_frequencies.to_csv('userData.csv', index=False)

    working_starthr = 9
    working_endhr = 5
    def is_outside_working_hours(timestamp):
        hour = timestamp.hour
        return hour < working_starthr or hour >= working_endhr

    login_df = df[df['EventSource'] == 'logs.amazonaws.com']
    login_df['Warning'] = login_df['EventTime'].apply(lambda x: 'Outside Working Hours' if is_outside_working_hours(pd.to_datetime(x)) else '')
    user_login_activity_df = login_df[['AccessKeyId','Username', 'EventTime', 'EventSource', 'Warning']].copy()
    user_login_activity_df.to_csv('log_data1.csv', index=False)

    merged_df = pd.merge(user_login_activity_df, user_transfer_frequencies, on='AccessKeyId', how='inner')
    merged_df.to_csv('merged_data.csv', index=False)

# Taipy GUI components
section_1 = """
<center>
<|navbar|lov={[("page1")]}|>
</center>
<span style='color: red;'> ! HostShield Threat Intelligence Dashboard !</span>
=========================
<|layout|columns=1 3|
<|
###<span style='color: blue;'>!  Check the logs for threat ! </span>
<br/>
<center>
<|file_selector|label=Upload log file|>
</center>
|>
<|
<center>
<|{logo}|image|height=250px|width=600px|on_action=image_action|>
</center>
|>
|>
"""

section_2 = """
##<span style='color: red;'>! ! Data Visualization ! !</span>
<|{dataset}|chart|mode=lines|x=EventTime|y[1]=SourceIPAddress|y[2]=ResourceName|color[1]=blue|color[2]=red|>
"""

section_3 = """
<|layout|columns= 1 5|
<|
## Custom Parameters
**Starting Date**\n\n<|{start_date}|date|not with_time|on_change=start_date_onchange|>
<br/><br/>
**Ending Date**\n\n<|{end_date}|date|not with_time|on_change=end_date_onchange|>
<br/>
<br/>
<|button|label=GO|on_action=button_action|>
|>
<|
<center> <h2>Dataset</h2><|{download_data}|file_download|on_action=download|>
</center>
<center>
<|{dataset}|table|page_size=10|height=500px|width=65%|>
</center>
|>
|>
"""

def image_action(state):
    webbrowser.open("https://taipy.io")

def get_data(path: str):
    dataset = pd.read_csv(path)
    dataset["EventTime"] = pd.to_datetime(dataset["EventTime"]).dt.date
    return dataset

def download(state):
    state.dataset.to_csv('download.csv')
    state.download_data = 'download.csv'

logo = "images/logo.png"
dataset = get_data("datasets/weather.csv")
start_date = datetime.date(2008, 12, 1)
end_date = datetime.date(2017, 6, 25)

# Main function to run the GUI and process data
if __name__ == '__main__':
    lambda_handler(None, None)
    process_data()
    Gui(page=section_1 + section_2 + section_3).run(dark_mode=False)
