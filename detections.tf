locals {
  # Terraform loads every .tf file in this directory as one module. Each
  # telemetry-specific file contributes its rules to this combined collection.
  detections = merge(
    local.aws_cloudtrail_detections,
    local.windows_sysmon_detections,
    local.linux_detections,
  )
}

resource "splunk_saved_searches" "detection" {
  for_each    = local.detections
  name        = trimspace(each.value.name)
  description = each.value.description
  search      = trimspace(each.value.search)

  # The Splunk provider reads the Better Webhook URL back through this generic
  # webhook field, causing a perpetual null diff. The Better Webhook-specific
  # URL below remains fully managed by Terraform.
  lifecycle {
    ignore_changes = [action_webhook_param_url]
  }

  # 1. Scheduling Settings
  is_scheduled  = true
  cron_schedule = "*/15 * * * *" # Evaluates every 15 minutes

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
  actions                                 = "better_webhook"
  action_better_webhook_param_url         = var.TINES_WEBHOOK
  action_better_webhook_param_body_format = <<-JSON
{
  "platform": ${jsonencode(each.value.platform)},
  "data_source": ${jsonencode(each.value.data_source)},
  "rule_description": ${jsonencode(trimspace(each.value.description))},
  "trigger_start": "$job.earliestTime$",
  "trigger_end": "$job.latestTime$",
  "query": ${jsonencode(trimspace(each.value.search))},
  "result": $$full_result$$,
  "sid": $$sid$$,
  "search_name": $$search_name$$,
  "results_link": $$results_link$$
}
JSON

  # 5. Access Control (Optional)
  acl {
    owner   = "siris"
    sharing = "app"
    app     = "search"
  }
}

# Preserve the existing Terraform resource identities while replacing the
# numbered rule keys with descriptive keys.
moved {
  from = splunk_saved_searches.detection["detection1"]
  to   = splunk_saved_searches.detection["aws_account_creates_user_and_access_keys"]
}

moved {
  from = splunk_saved_searches.detection["detection2"]
  to   = splunk_saved_searches.detection["aws_anomalous_access_denied_errors"]
}

moved {
  from = splunk_saved_searches.detection["detection3"]
  to   = splunk_saved_searches.detection["aws_s3_possible_data_exfiltration"]
}

moved {
  from = splunk_saved_searches.detection["detection4"]
  to   = splunk_saved_searches.detection["aws_suspicious_api_call_volume"]
}

moved {
  from = splunk_saved_searches.detection["detection5"]
  to   = splunk_saved_searches.detection["windows_unexpected_process_network_connection"]
}

moved {
  from = splunk_saved_searches.detection["detection6"]
  to   = splunk_saved_searches.detection["windows_unsigned_dll_and_network_activity"]
}
