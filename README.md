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
The script will create a file
