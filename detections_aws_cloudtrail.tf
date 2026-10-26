locals {
  # AWS control-plane and data-plane activity collected from CloudTrail.
  aws_cloudtrail_detections = {
    aws_account_creates_user_and_access_keys = {
      name        = "Account Creates User and Access Keys"
      platform    = "AWS"
      data_source = "CloudTrail"
      description = <<-EOT
        This could be a persistence mechanism for an attacker to maintain access to the environment.
        This detection looks for a user creating another user and then creating access keys for that user within a 10 minute window.
      EOT
      search      = <<-EOT
        index=aws
        | rename userIdentity.type as src_user
        | rename userIdentity.userName as user_name
        | rename requestParameters.userName as TargetUser
        | transaction startswith="CreateUser" endswith="CreateAccessKey" maxspan=10m
        | stats values(eventName) as APICalls, count(eventName) as CallCount by _time, user_name, TargetUser
      EOT
    }

    aws_anomalous_access_denied_errors = {
      name        = "Detecting Anomalous Access Denied Errors Code"
      platform    = "AWS"
      data_source = "CloudTrail"
      description = <<-EOT
        This detection looks for anomalous access denied errors in AWS CloudTrail logs.
        It uses statistical anomaly detection to identify unusual spikes in access denied events,
        which could indicate potential security threats or misconfigurations in the AWS environment.
      EOT
      search      = <<-EOT
        index=aws errorCode="AccessDenied" earliest=-30d latest=now()
        | bin _time span=15m
        | rename userIdentity.userName as user_name
        | search userIdentity.arn != "*SplunkInput"
        | stats
            count as access_denied_count
            values(eventName) as eventName
            values(errorMessage) as error_messages
            values(user_agent) as useragent
            dc(eventName) as unique_apis
          by _time, aws_account_id, sourceIPAddress, userIdentity.arn
        | anomalydetection
            access_denied_count
            action=annotate
            BY aws_account_id sourceIPAddress userIdentity.arn
        | eval isOutlier = if(probable_cause != "", "1", "0")
        | where isnotnull(probable_cause)
      EOT
    }

    aws_s3_possible_data_exfiltration = {
      name        = "Possible Data Exfiltration from an S3 bucket"
      platform    = "AWS"
      data_source = "CloudTrail"
      description = <<-EOT
        Triggers an alert when a user transfers a large amount of data out of an S3 bucket.
        Indicating potential data exfiltration or misuse of S3 resources.
      EOT
      search      = <<-EOT
        index=aws eventSource = "s3.amazonaws.com" eventCategory=Data
        | rename additionalEventData.bytesTransferredOut as bytesOut
        | bin _time span=15m
        | rename requestParameters.bucketName as bucket_name
        | rename userIdentity.userName as src_user
        | where src_user != "SplunkInput"
        | stats sum(bytesOut) as bytesOutSum by src_user, bucket_name, _time
        | eval MegabytesOut=bytesOutSum/1024/1024
        | where MegabytesOut > 1
        | sort -MegabytesOut
      EOT
    }

    aws_suspicious_api_call_volume = {
      name        = "Suspicious Number of Attempts API Calls"
      platform    = "AWS"
      data_source = "CloudTrail"
      description = <<-EOT
        This detection identifies users who are making a large number of API calls in a short period of time. This could indicate automation or malicious activity
        through probing, reconnaissance, or enumeration of our environment.
      EOT
      search      = <<-EOT
        index=aws
        | rename userIdentity.type as src_user
        | rename userIdentity.userName as user_name
        | rename requestParameters.userName as TargetUser
        | where user_name!="SplunkInput"
        | bin _time span=15m
        | stats values(eventName) as APICalls, count(eventName) as CallCount by _time, user_name
        | sort by -CallCount
        | eval Enumeration=if(CallCount > 100, "Suspicious", "N/A")
      EOT
    }
  }
}
