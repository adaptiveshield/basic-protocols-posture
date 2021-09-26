# basic-protocols-posture
A PowerShell script shows users and their legacy protocols status. Each protocols' status is being tested against Authentication Policy, Mailbox services, and Transport config.

### Execution
1. Download the script `posturer.ps1` and save it on the machine you use to connect PowerShell.
2. Connect using PowerShell to your organization (with a Global reader permissions)

```
$User = "user@org.com"
$PWord = ConvertTo-SecureString -String 'PASSWORD123' -AsPlainText -Force
$LiveCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell/ -Credential $LiveCred -Authentication Basic -AllowRedirection
Import-PSSession $Session
Connect-MsolService -Credential $LiveCred;
```

3. Execute the script `./posturer.ps1`

### Payload
The script generates a file `BasicProtocolsReport.csv`
Columns description:
 * user
 * has_mailbox - Indicate if the user has a mailbox licensed
 * blocked - Account status (enabled/disabled)
 * mfa - Multifactor authentication enrollment status
 * auth_policy - Name of effective authentication policy (if set)
 * is_ap_def - Indicates wheather the effective authentication policy is an organization default or specifically assigned to the user
 * protocol columns (activesync, imap, mapi, pop, smtp, outlookservice, powershell, ExchangeWebServices, autodiscover, OfflineAddressBook, rpc, ReportingWebServices) - Status (TRUE - enabled; FALSE - blocked)
 * protocl_method columns (activesync, imap, mapi, pop, smtp, outlookservice) - Each of these protocols can be blocked using mailbox services settings, authentication policy, and transport config (global settings for SMTP) this columns detailed which methods are in place to block these protocols.

