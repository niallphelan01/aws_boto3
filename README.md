AWS assignment to automatically setup and control AWS EC2 instances.

This program makes use of the boto3 api to connnect to EC2 instances, S3 bucket(s) and Cloudwatch resources.

It has a logged installed, set to debug level for feedback on errors etc. The logger also adds info for what the user selects for feedback should there be issues.

Custom cloud metrics can be applied to an EC2 instance using automation to connect to the EC2 instance, add AWS credentials and add a cron job to upload these every minute using a script for same.
These custom cloud metrics can be also retrieved using the applicaiton (for atleast IO_WAIT anyway)

The folder /log will need to be created for this project
The file credentials will need to be created using the following syntax

[default]
aws_access_key_id=xxxxxxxxxxxxxxxxxxxxx
aws_secret_access_key=xxxxxxxxxxxxxxxxxxxxx

And the config file will need to be created using the following:

[default]
region = eu-west-1



