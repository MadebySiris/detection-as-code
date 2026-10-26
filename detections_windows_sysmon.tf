locals {
  # Windows endpoint activity collected from Sysmon.
  windows_sysmon_detections = {
    windows_unexpected_process_network_connection = {
      name        = "Unexpected process makes network connection"
      platform    = "Windows"
      data_source = "Sysmon"
      description = <<-EOT
        This detection identifies unexpected processes that are making network connections.
        It looks for processes that are not typically associated with network activity, such as system processes or known benign applications,
        and flags them for further investigation.
      EOT
      search      = <<-EOT
        index=sysmon EventCode=3
        | sort 0 _time
        | streamstats current=f last(_time) as previous_time by host, process_guid, src_ip, dest_ip
        | eval interval_seconds=round(_time-previous_time, 2)
        | table _time src_ip dest_ip process_name interval_seconds, process_guid, host
        | where NOT process_name IN (
            "MpDefenderCoreService.exe",
            "OneDrive.Sync.Service.exe",
            "chrome.exe",
            "svchost.exe",
            "mmc.exe",
            "OneDriveSetup.exe"
          )
      EOT
    }

    windows_unsigned_dll_and_network_activity = {
      name        = "Unsigned DLL Load and Network Activity in the Same Process"
      platform    = "Windows"
      data_source = "Sysmon"
      description = <<-EOT
        This detection identifies processes that have loaded unsigned DLLs and are also making network connections.
        This could indicate malicious activity, as unsigned DLLs may be used to inject malicious code into legitimate processes,
        and network activity could be used for data exfiltration or command and control communication.
      EOT
      search      = <<-EOT
        index=sysmon EventCode IN (3, 7)
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
