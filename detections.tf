locals {
  detections = {
    high_error_rate_alert22 = {
      name        = "What Happening and dapening"
      description = "Triggers an alert when error counts exceed 10 in a 5-minute window"
      search      = <<-EOT
        index=main sourcetype=nginx_logs status>=500 | stats count
      EOT
    }
  }
}

resource "splunk_saved_searches" "detection" {
  for_each = local.detections

  name        = each.value.name
  description = each.value.description
  search      = trim(each.value.search, " \t\n\r")


  # 1. Scheduling Settings
  is_scheduled  = true
  cron_schedule = "*/5 * * * *" # Evaluates every 5 minutes
  
  # 2. Time Window Settings
  dispatch_earliest_time = "-5m"
  dispatch_latest_time   = "now"

  # 3. Alert Trigger Condition Rules
  alert_type       = "number of events"
  alert_comparator = "greater than"
  alert_threshold  = "0"
  alert_track      = true # Crucial: Tells Splunk to fire this as an alert

  # 4. Action Settings (Example: Email Notification)
  actions                    = "Webhook"
  action_better_webhook_param_url = var.TINES_WEBHOOK

  # 5. Access Control (Optional)
  acl {
    owner   = "siris"
    sharing = "app"
    app     = "search"
  }
}

moved {
  from = splunk_saved_searches.high_error_rate_alert22
  to   = splunk_saved_searches.detection["high_error_rate_alert22"]
}


