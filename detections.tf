locals {
  detections = {
    detection1 = {
      name        = "Account Creates User and Access Keys1"
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
    detection2 = {
      name        = "Detecting Anomalous Access Denied Errors Code1"
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
      count                        as access_denied_count
      values(eventName)            as eventName
      values(errorMessage)         as error_messages
      values(user_agent)           as useragent
      dc(eventName)                as unique_apis
    by _time, aws_account_id, sourceIPAddress, userIdentity.arn
    
   | anomalydetection
      access_denied_count
      action=annotate
      BY aws_account_id sourceIPAddress userIdentity.arn
   | eval isOutlier = if(probable_cause != "", "1", "0")
   | where isnotnull(probable_cause)
  EOT
    }
    detection3 = {
      name        = "Possible Data Exfiltration from an S3 bucket1"
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
    detection4 = {
      name        = "Suspicious Number of Attempts API Calls1"
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
    detection5 = {
      name        = "Unexpected process makes network connection1"
      description = <<-EOT
        This detection identifies unexpected processes that are making network connections.
        It looks for processes that are not typically associated with network activity, such as system processes or known benign applications,
        and flags them for further investigation.
  EOT
      search      = <<-EOT
        index=* EventCode=3
    | sort 0 _time
    | streamstats current=f last(_time) as previous_time by host, process_guid, src_ip, dest_ip
    | eval interval_seconds=round(_time-previous_time, 2)
    | table _time src_ip dest_ip process_name interval_seconds, process_guid, host
    | eval suspicious_level = case(
      process_name == "MpDefenderCoreService.exe", "Low",
      process_name = "OneDrive.Sync.Service.exe", "Low",
      process_name = "chrome.exe", "Low",
      process_name = "svchost.exe", "Low",
      true(), "High"
      )
  EOT
    }
    detection6 = {
      name        = "Unsigned DLL Load and Network Activity in the Same Process1"
      description = <<-EOT
        This detection identifies processes that have loaded unsigned DLLs and are also making network connections.
        This could indicate malicious activity, as unsigned DLLs may be used to inject malicious code into legitimate processes,
        and network activity could be used for data exfiltration or command and control communication.
  EOT
      search      = <<-EOT
        index=* EventCode IN (3, 7)
| eval unsigned_dll=if(
    EventCode=7
    AND lower(Signed)="false"
    AND like(lower(ImageLoaded), "%.dll"),
    ImageLoaded,
    null()
  )
| bin _time span=15m
| stats
    count(eval(EventCode=3)) as network_connections
    values(unsigned_dll) as unsigned_dlls
    values(Image) as process_path
    values(dest_ip) as destinations
    by _time host ProcessGuid
| where network_connections > 0 AND mvcount(unsigned_dlls) > 0
| eval priority="Suspicious — unsigned DLL load and network activity"
  EOT
    }
  }
}
resource "splunk_saved_searches" "detection" {
  for_each = local.detections

  name        = each.value.name
  description = each.value.description
  search      = <<-EOT
${trim(each.value.search, " \t\n\r")}
| addinfo
| eval rule_description=urldecode(${jsonencode(urlencode(trimspace(each.value.description)))})
| eval trigger_range=strftime(info_min_time, "%Y-%m-%d %H:%M:%S %Z")." to ".strftime(info_max_time, "%Y-%m-%d %H:%M:%S %Z")
| eval query_url=${jsonencode("${trimsuffix(var.SPLUNK_UI_URL, "/")}/app/search/@go?sid=")}.info_sid
| eval query=urldecode(${jsonencode(urlencode(trim(each.value.search, " \t\n\r")))})
| fields rule_description trigger_range query_url query
EOT


  # 1. Scheduling Settings
  is_scheduled  = true
  cron_schedule = "*/5 * * * *" # Evaluates every 5 minutes

  # 2. Time Window Settings
  dispatch_earliest_time = "-12h"
  dispatch_latest_time   = "now"

  # 3. Alert Trigger Condition Rules
  alert_type            = "number of events"
  alert_comparator      = "greater than"
  alert_threshold       = "0"
  alert_digest_mode     = true
  alert_suppress        = true
  alert_suppress_period = "10m"
  alert_track           = true # Crucial: Tells Splunk to fire this as an alert

  # 4. Action Settings
  actions                  = "webhook"
  action_webhook_param_url = var.TINES_WEBHOOK

  # 5. Access Control (Optional)
  acl {
    owner   = "siris"
    sharing = "app"
    app     = "search"
  }
}
