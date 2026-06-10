# Argus SIEM — Collector
# Pulls SOC-relevant Windows Security events, normalizes them, appends to a JSONL event store.
# Incremental by RecordId so each run only ingests new events.
# NOTE: reading the Security log requires elevation (run as admin / scheduled task w/ highest privileges).

$ErrorActionPreference = 'Stop'
$root    = Split-Path -Parent $PSScriptRoot          # argus-siem\
$dataDir = Join-Path $root 'data'
$store   = Join-Path $dataDir 'events.jsonl'
$stateF  = Join-Path $dataDir 'state.json'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# SOC-relevant Security event IDs
$ids = 4624,4625,4634,4647,4648,4672,4720,4722,4724,4728,4732,4740,4756,4688,1102

# Incremental state
$lastRecord = 0
if (Test-Path $stateF) { try { $lastRecord = [long]((Get-Content $stateF -Raw | ConvertFrom-Json).lastRecordId) } catch {} }
# First run: look back 7 days; subsequent runs: last 2 days (then filtered by RecordId)
$startTime = if ($lastRecord -gt 0) { (Get-Date).AddDays(-2) } else { (Get-Date).AddDays(-7) }

try {
  $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$ids; StartTime=$startTime } -ErrorAction Stop
} catch {
  if ($_.Exception.Message -match 'No events were found') { Write-Host 'No new events.'; return }
  throw
}

# Helper: pull EventData fields into a hashtable keyed by Name
function Get-Fields($evt) {
  $h = @{}
  try {
    $xml = [xml]$evt.ToXml()
    foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = $d.'#text' } }
  } catch {}
  return $h
}

$new = 0; $maxRecord = $lastRecord
$lines = New-Object System.Collections.Generic.List[string]
foreach ($e in ($events | Sort-Object RecordId)) {
  if ($e.RecordId -le $lastRecord) { continue }
  $f = Get-Fields $e
  $obj = [ordered]@{
    id        = [long]$e.RecordId
    ts        = $e.TimeCreated.ToUniversalTime().ToString('o')
    eventId   = [int]$e.Id
    level     = $e.LevelDisplayName
    computer  = $e.MachineName
    user      = $f['TargetUserName']
    domain    = $f['TargetDomainName']
    logonType = $f['LogonType']
    sourceIp  = $f['IpAddress']
    workstation = $f['WorkstationName']
    process   = if ($f['NewProcessName']) { $f['NewProcessName'] } else { $f['ProcessName'] }
    subject   = $f['SubjectUserName']
  }
  $lines.Add(($obj | ConvertTo-Json -Compress))
  $new++
  if ($e.RecordId -gt $maxRecord) { $maxRecord = $e.RecordId }
}

if ($new -gt 0) {
  # Write UTF-8 WITHOUT BOM (Windows PowerShell's -Encoding utf8 adds a BOM that breaks JSON parsers)
  $enc = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::AppendAllText($store, (($lines -join "`n") + "`n"), $enc)
  [System.IO.File]::WriteAllText($stateF, (@{ lastRecordId = $maxRecord; lastRun = (Get-Date).ToString('o') } | ConvertTo-Json), $enc)
}
Write-Host "Ingested $new new event(s). Store: $store"
