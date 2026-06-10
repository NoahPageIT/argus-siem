# Argus SIEM — Attack Simulator
# Generates REAL Windows failed-logon events (4625) to validate the brute-force detection.
# Uses a fake username so your real account is NEVER locked out.
#
# Usage:  .\simulate-attack.ps1
# Then run the collector and refresh the dashboard — you'll see a HIGH-severity brute-force alert.

$sig = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LogonUser(string user, string domain, string pass, int type, int provider, out System.IntPtr token);
'@
$api = Add-Type -MemberDefinition $sig -Name Win32LogonApi -Namespace Argus -PassThru
$fake = 'attacker_test'

Write-Host "Simulating a brute-force attack against fake account '$fake' (your real account is untouched)..."
1..6 | ForEach-Object {
  [System.IntPtr]$tok = 0
  [void]$api::LogonUser($fake, $env:COMPUTERNAME, "WrongPass!$_", 2, 0, [ref]$tok)
  Write-Host "  attempt $_/6 — failed logon (4625) generated"
  Start-Sleep -Milliseconds 300
}
Write-Host "`nDone. Now run:  .\collector\collect.ps1   (as admin)  then refresh http://localhost:3001"
Write-Host "Expected: HIGH-severity 'Brute-force logon attempt' alert mapped to MITRE T1110."
