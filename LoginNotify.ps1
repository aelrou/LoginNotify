# Set-ExecutionPolicy RemoteSigned
# Unblock-File -Path "C:\Users\Public\PowerShell\LoginNotify\LoginNotify.ps1"
# "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File "C:\Users\Public\PowerShell\LoginNotify\LoginNotify.ps1"

$UserWhitelist = @(
    "DoNotNotifyForThisUsername1",
    "DoNotNotifyForThisUsername2"
)

$CurrentTime = Get-Date
$WatchTime = $CurrentTime.AddMinutes(-1)

$SecurityLogFailureBatch = (Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4625 } -MaxEvents 99 | Where-Object { $_.TimeCreated -gt $WatchTime })
$SecurityLogSuccessBatch = (Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624 } -MaxEvents 99 | Where-Object { $_.TimeCreated -gt $WatchTime })

# foreach ($SecurityLogSuccess in $SecurityLogSuccessBatch) {
#     $SecurityLogSuccessXML = $null
#     $SecurityLogSuccessXML = [xml]$SecurityLogSuccess.ToXml()   
#     Write-Host($SecurityLogSuccessXML.Event.EventData.Data.Name)
# }

$FormatTime = "yyyy-MM-ddTHH:mm:ss.ffff"
$Events = $null
$Events = @{}

foreach ($SecurityLogFailure in $SecurityLogFailureBatch) {
    $SecurityLogFailureXML = $null
    $SecurityLogFailureXML = [xml]$SecurityLogFailure.ToXml()   

    [String]$EventType = "Audit Failure"

    [String]$RecordId = $null
    [String]$RecordId = ($SecurityLogFailure.RecordId)

    [String]$IpAddress = $null
    [String]$IpAddress = ($SecurityLogFailureXML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"

    [String]$WorkstationName = $null
    [String]$WorkstationName = ($SecurityLogFailureXML.Event.EventData.Data | Where-Object { $_.Name -eq "WorkstationName" })."#text"

    [String]$TargetUserName = $null
    [String]$TargetUserName = ($SecurityLogFailureXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" })."#text"

    [String]$TimeCreated = $null
    [String]$TimeCreated = (Get-Date -Date $SecurityLogFailure.TimeCreated -Format $FormatTime)

    $NewEvent = $null
    $NewEvent = @{}
    if (!($IpAddress -eq "-")) {
        if (!($WorkstationName -eq "-")) {
            if (!($TargetUserName -eq "-")) {
                $NewEvent.Add("EventType", $EventType)
                $NewEvent.Add("IpAddress", $IpAddress)
                $NewEvent.Add("WorkstationName", $WorkstationName)
                $NewEvent.Add("TargetUserName", $TargetUserName)
                $NewEvent.Add("TimeCreated", $TimeCreated)
            }
        }
    }

    if ($NewEvent.Count -gt 0) {
        if ($Events.Count -eq 0) {
            $Events.Add($RecordId, $NewEvent)
        }
        else {
            $Unique = $true
            foreach ($N in $NewEvent) {
                foreach ($E in $Events.GetEnumerator()) {
                    if ($N.EventType -eq $E.Value.EventType) {
                        if ($N.IpAddress -eq $E.Value.IpAddress) {
                            if ($N.WorkstationName -eq $E.Value.WorkstationName) {
                                if ($N.TargetUserName -eq $E.Value.TargetUserName) {
                                    $Unique = $false
                                    # if ($N.TimeCreated -eq $E.Value.TimeCreated) {
                                    #     $Unique = $false
                                    # }
                                }
                            }
                        }
                    }
                }
            }
            if ($Unique) {
                $Events.Add($RecordId, $NewEvent)
            }
        }
    }
}

foreach ($SecurityLogSuccess in $SecurityLogSuccessBatch) {
    $SecurityLogSuccessXML = $null
    $SecurityLogSuccessXML = [xml]$SecurityLogSuccess.ToXml()   

    [String]$EventType = "Audit Success"

    [String]$RecordId = $null
    [String]$RecordId = ($SecurityLogSuccess.RecordId)

    [String]$IpAddress = $null
    [String]$IpAddress = ($SecurityLogSuccessXML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"

    [String]$WorkstationName = $null
    [String]$WorkstationName = ($SecurityLogSuccessXML.Event.EventData.Data | Where-Object { $_.Name -eq "WorkstationName" })."#text"

    [String]$TargetUserName = $null
    [String]$TargetUserName = ($SecurityLogSuccessXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" })."#text"

    [String]$TimeCreated = $null
    [String]$TimeCreated = (Get-Date -Date $SecurityLogSuccess.TimeCreated -Format $FormatTime)

    $NewEvent = $null
    $NewEvent = @{}
    if (!($IpAddress -eq "-")) {
        if (!($WorkstationName -eq "-")) {
            if (!($TargetUserName -eq "-")) {
                $Whitelisted = $false
                foreach ($W in $UserWhitelist) {
                    if ($W -eq $TargetUserName) {
                        $Whitelisted = $true
                    }
                }
                if (!($Whitelisted)) {
                    $NewEvent.Add("EventType", $EventType)
                    $NewEvent.Add("IpAddress", $IpAddress)
                    $NewEvent.Add("WorkstationName", $WorkstationName)
                    $NewEvent.Add("TargetUserName", $TargetUserName)
                    $NewEvent.Add("TimeCreated", $TimeCreated)
                }
            }
        }
    }

    if ($NewEvent.Count -gt 0) {
        if ($Events.Count -eq 0) {
            $Events.Add($RecordId, $NewEvent)
        }
        else {
            $Unique = $true
            foreach ($N in $NewEvent) {
                foreach ($E in $Events.GetEnumerator()) {
                    if ($N.EventType -eq $E.Value.EventType) {
                        if ($N.IpAddress -eq $E.Value.IpAddress) {
                            if ($N.WorkstationName -eq $E.Value.WorkstationName) {
                                if ($N.TargetUserName -eq $E.Value.TargetUserName) {
                                    $Unique = $false
                                    # if ($N.TimeCreated -eq $E.Value.TimeCreated) {
                                    #     $Unique = $false
                                    # }
                                }
                            }
                        }
                    }
                }
            }
            if ($Unique) {
                $Events.Add($RecordId, $NewEvent)
            }
        }
    }
}

[string]$ReportingEvents = $null
if ($Events.Count -gt 0) {
    foreach($E in $Events.GetEnumerator()){
        # Write-Host("$($E.Name) : $($E.Value.Keys)")
        # Write-Host("$($E.Name) : $($E.Value.Values)")
        $ReportingEvents = "$($ReportingEvents)$($E.Value.EventType) for user ""$($E.Value.WorkstationName)\$($E.Value.TargetUserName)"" to machine ""$($env:computername)"" from $($E.Value.IpAddress) at $($E.Value.TimeCreated) `r`n"
    }
    Write-Host($ReportingEvents)
    $NotifyMessage = $null
    $NotifyMessage = @{"text" = $ReportingEvents}
    Write-Host($NotifyMessage | ConvertTo-Json)
    $NotifyEndpoint = "https://chat.googleapis.com/v1/spaces/XXXXXXXXXXX/messages?key=XXXXXXXXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX&token=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    Invoke-WebRequest -Uri $NotifyEndpoint -Method POST -Body ($NotifyMessage | ConvertTo-Json) -ContentType "application/json"
}

exit 0
