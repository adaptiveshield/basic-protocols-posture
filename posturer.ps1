function Get-DeepClone {
  [CmdletBinding()]
  param( $InputObject )
  
  if($InputObject -is [hashtable]) {
    $clone = @{}
    foreach($key in $InputObject.keys) {
      $clone[$key] = Get-DeepClone $InputObject[$key]
    }
    return $clone
  } else {
      return $InputObject
  }
}

$my_protocols_hash = @{
  activesync = @{
    attribute = 'AllowBasicAuthActiveSync'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  imap = @{
    attribute = 'AllowBasicAuthImap'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  mapi = @{
    attribute = 'AllowBasicAuthMapi'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  pop = @{
    attribute = 'AllowBasicAuthPop'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  smtp = @{
    attribute = 'AllowBasicAuthSmtp'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  ews = @{
    attribute = 'AllowBasicAuthWebServices'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  autodiscover = @{
    attribute = 'AllowBasicAuthAutodiscover'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  oab = @{
    attribute = 'AllowBasicAuthOfflineAddressBook'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  outlookservice = @{
    attribute = 'AllowBasicAuthOutlookService'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  rpc = @{
    attribute = 'AllowBasicAuthRpc'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  rws = @{
    attribute = 'AllowBasicAuthReportingWebServices'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  powershell = @{
    attribute = 'AllowBasicAuthPowershell'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
}
$cas_protocols_hash = @{
  activesync = @{
    attribute = 'ActiveSyncEnabled'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  imap = @{
    attribute = 'ImapEnabled'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  mapi = @{
    attribute = 'MapiEnabled'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  pop = @{
    attribute = 'PopEnabled'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
  outlookservice = @{
    attribute = 'OWAEnabled'
    enabled = $true
    blocked_method = "NOT BLOCKED"
  }
}
$msol = Get-MsolUser
$exchange_users = Get-User
$policies = Get-AuthenticationPolicy
$cas = Get-CASMailbox
$org_config = Get-OrganizationConfig
$transport_config = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
$def_auth_policy = $policies | Where-Object {$_.Name -eq $org_config.DefaultAuthenticationPolicy}
$users = @()

foreach ($user in $msol){
  $policy = $null
  $is_def = $null
  $exchange_user = $null
  $user_policy = $null
  if ($def_auth_policy){
    $policy = $def_auth_policy
    $is_def = $true 
  }
  $exchange_user = $exchange_users | Where-Object {$_.UserPrincipalName -eq $user.UserPrincipalName}
  $user_policy = $policies | Where-Object {$_.Name -eq $exchange_user.AuthenticationPolicy}
  if ($user_policy){
    $policy = $user_policy
    $is_def = $false
  }
  $user_protocols = Get-DeepClone $my_protocols_hash
  if ($policy){
    foreach ($protocol in $user_protocols.Keys){
      $attr = $user_protocols[$protocol].attribute
      $user_protocols[$protocol].enabled = $policy.$attr
      if ($policy.$attr -eq $false){
        $user_protocols[$protocol].blocked_method = "Authentication Policy"
      }
    }
  }
  #SMTP
  $cas_mailbox = $cas | Where-Object {$_.PrimarySmtpAddress -eq $user.UserPrincipalName}
  if ($cas_mailbox){
    if ($cas_mailbox.SmtpClientAuthenticationDisabled -eq $null){
      # Transport Config SMTP AUTH  
      if ($transport_config.SmtpClientAuthenticationDisabled -eq $true){
        if ($user_protocols.smtp.enabled -eq $false){
          $user_protocols.smtp.blocked_method = $user_protocols.smtp.blocked_method + "; Transport Config"
        }else{
          $user_protocols.smtp.enabled = $false
          $user_protocols.smtp.blocked_method = "Transport Config"
        }
      }
    }elseif ($cas_mailbox.SmtpClientAuthenticationDisabled -eq $true){
      #CAS SMTP 
      if ($user_protocols.smtp.enabled -eq $false){
        $user_protocols.smtp.blocked_method = $user_protocols.smtp.blocked_method + "; CAS Mailbox"
      }else{
        $user_protocols.smtp.enabled = $false
        $user_protocols.smtp.blocked_method = "CAS Mailbox"
      }
    }
  }else{
    $user_protocols.smtp.blocked_method = "No Mailbox"
    $user_protocols.smtp.enabled = $false
  }
  
  # CAS Clients
  if ($cas_mailbox){
    $cas_protocols = Get-DeepClone $cas_protocols_hash
    foreach ($protocol in $cas_protocols.Keys){
      $attr = $cas_protocols[$protocol].attribute
      if ($cas_mailbox.$attr -eq $false){
        if ($user_protocols[$protocol].enabled -eq $false){
          $user_protocols[$protocol].blocked_method = $user_protocols[$protocol].blocked_method + "; CAS Mailbox"
        }else{
          $user_protocols[$protocol].blocked_method = "CAS Mailbox"
        }
        $user_protocols[$protocol].enabled = $false
      } 
    }
  }else{
    $user_protocols[$protocol].blocked_method = "No Mailbox"
    $user_protocols[$protocol].enabled = $false
  }


  $users += [pscustomobject]@{
    user = $user.UserPrincipalName
    has_mailbox = !!($cas_mailbox)
    blocked = $user.BlockCredential
    mfa = ($user.StrongAuthenticationMethods.Count -gt 0)
    auth_policy = $policy.Name
    is_ap_def = $is_def
    activesync = $user_protocols.activesync.enabled
    activesync_method = $user_protocols.activesync.blocked_method
    imap = $user_protocols.imap.enabled
    imap_method = $user_protocols.imap.blocked_method
    mapi = $user_protocols.mapi.enabled
    mapi_method = $user_protocols.mapi.blocked_method
    pop = $user_protocols.pop.enabled
    pop_method = $user_protocols.pop.blocked_method
    smtp = $user_protocols.smtp.enabled
    smtp_method = $user_protocols.smtp.blocked_method
    outlookservice = $user_protocols.outlookservice.enabled
    outlookservice_method = $user_protocols.outlookservice.blocked_method
    powershell = $user_protocols.powershell.enabled
    ExchangeWebServices = $user_protocols.ews.enabled
    autodiscover = $user_protocols.autodiscover.enabled
    OfflineAddressBook = $user_protocols.oab.enabled
    rpc = $user_protocols.rpc.enabled
    ReportingWebServices = $user_protocols.rws.enabled
  }
}
$users | Export-Csv -Path .\BasicProtocolsReport.csv
