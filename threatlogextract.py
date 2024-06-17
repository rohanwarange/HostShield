import boto3
import datetime
import csv
import json
from pytz import timezone

# Specify your AWS credentials directly (replace with your actual credentials)
aws_access_key_id = 'AKIA22XP4DXY25GWREI6'
aws_secret_access_key = 'NAGr0c7WEOLjr0+Gci52ItjC63C+FgZiCOCZLvmh'
aws_region = 'us-west-2'

# Initialize AWS clients with specified credentials
session = boto3.Session(
aws_access_key_id=aws_access_key_id,
aws_secret_access_key=aws_secret_access_key,
region_name=aws_region
)
s3 = session.client('s3')
cloudtrail = session.client('cloudtrail')

# Define your S3 bucket name
bucket_name = 'hostshield-security'

# Define the event name prefixes to include
prefixes_to_include = ["create", "delete", "update", "start", "stop", "terminate", "run",
                       "associate", "assign", "detach", "enable", "authorize", "revoke", "abort",
                       "rebuild", "restart", "swap", "terminate", "apply", "deregister", "add",
                       "console", "enable", "put", "upload", "authorize", "failover"]

def filter_and_export_cloudtrail_logs():
    # Calculate the start and end times for the query (last 96 hours)
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    end_time = utc_now
    start_time = end_time - datetime.timedelta(hours=96)

    # Retrieve CloudTrail events within the specified time range
    response = cloudtrail.lookup_events(
        StartTime=start_time,
        EndTime=end_time,
    )

    # Define column names for CloudTrail events
    cloudtrail_column_names = [
        'EventTime',
        'EventName',
        'ReadOnly',
        'Username',
        'ResourceType',
        'ResourceName',
        'EventSource',
        'AccessKeyId',
        'SourceIPAddress',  # Add a column for Source IP Address
    ]

    # Initialize filtered logs list
    filtered_logs = [cloudtrail_column_names]

    # Iterate through the CloudTrail events
    for event in response['Events']:
        # Check if the event time is within the desired time range (5 PM to 9 AM)
        event_time = event['EventTime'].replace(tzinfo=None)
        if event_time.hour >= 17 or event_time.hour < 9:
            # Initialize source IP address as an empty string
            source_ip = ''

            # Check if 'CloudTrailEvent' is present and parse it as JSON
            if 'CloudTrailEvent' in event:
                try:
                    cloudtrail_event = json.loads(event['CloudTrailEvent'])
                    source_ip = cloudtrail_event.get('sourceIPAddress', '')
                except json.JSONDecodeError:
                    pass

            # Check if the event name starts with one of the specified prefixes or is "consolelogin"
            event_name = event['EventName'].lower()
            if any(event_name.startswith(prefix) for prefix in prefixes_to_include) or event_name == "consolelogin":
                # Extract the data before the first period in the EventSource column
                event_source_parts = event['EventSource'].split('.')
                resource_name = event_source_parts[0] if len(event_source_parts) > 0 else ''
                
                # Define the CSV row based on the data you need
                csv_row = [
                    event_time.strftime("%Y-%m-%d %H:%M:%S"),  # Format datetime as a string
                    event_name,
                    event.get('ReadOnly', ''),  # Handle the possibility of 'ReadOnly' key not being present
                    event.get('Username', ''),  # Handle the possibility of 'Username' key not being present
                    event.get('ResourceType', ''),  # Handle the possibility of 'ResourceType' key not being present
                    resource_name,  # Use the extracted resource name
                    event['EventSource'],
                    event.get('AccessKeyId', ''),  # Handle the possibility of 'AccessKeyId' key not being present
                    source_ip,  # Include the Source IP Address
                ]

                filtered_logs.append(csv_row)

    return filtered_logs

def lambda_handler(event, context):
    # Filter and export CloudTrail logs within the specified time range and with event name prefixes
    filtered_logs = filter_and_export_cloudtrail_logs()

    # Prepare the CSV file for CloudTrail events
    cloudtrail_csv_file = '\n'.join([','.join(row) for row in filtered_logs])

    # Define the fixed S3 key for the CloudTrail CSV file
    cloudtrail_key = 'fixed-cloudtrail-logs/filtered-cloudtrail.csv'

    # Upload the filtered CloudTrail CSV data to S3, overwriting the existing file
    s3.put_object(Bucket=bucket_name, Key=cloudtrail_key, Body=cloudtrail_csv_file)

    return {
        'statusCode': 200,
        'body': 'Filtered CloudTrail logs saved as a CSV file in S3.'
    }

if __name__ == '__main__':
    lambda_handler(None, None)
