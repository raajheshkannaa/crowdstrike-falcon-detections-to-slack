# CrowdStrike Falcon Detections to Slack 
CS Falcon didn't have native integration with Slack for notifying on new detection or findings, either the logs had to be fed into a SIEM and that would be configured to send alerts to security operations channels. 

To simplify this workflow, this lambda function could be deployed in any account with the necessary details, added to AWS SSM Parameter store.
* Slack HOOK URL
* CS Falcon API Client ID
* CS Falcon API Client Secret 

Trigger this lambda function using CloudWatch Event Rules as often as 10 mins.