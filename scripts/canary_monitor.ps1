# canary_monitor.ps1 — Canary C1 long observation (24h+)
# Logs metrics every 60s to CSV + console summary every 15min
param(
    [int]$DurationHours = 24,
    [string]$Out = "$env:TEMP\opencode\canary-c1-monitor"
)
$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$Csv = Join-Path $Out "canary_metrics.csv"
$Log = Join-Path $Out "canary_monitor.log"
$Nodes = @(
    @{name="node1"; rpc=42101},
    @{name="node2"; rpc=43101},
    @{name="node3"; rpc=44101},
    @{name="node4"; rpc=45101},
    @{name="node5"; rpc=46101},
    @{name="node6"; rpc=47101},
    @{name="node7"; rpc=48101},
    @{name="node8"; rpc=49101},
    @{name="node9"; rpc=49109}
)
function Log($msg){ $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; "$ts $msg" | Add-Content $Log -Encoding utf8; Write-Host "[$ts] $msg" }
function Rpc($port,$method,$params){ try{ $b=@{jsonrpc="2.0";method=$method;params=$params;id=1}|ConvertTo-Json -Compress -Depth 6; $r=Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 10; return $r.result }catch{ return $null } }

# CSV header
"timestamp,node,total,tip_count,connected_peers,rebuild_total,getdata_local,getdata_remote,duplicate_ignored,store_hits,wal_recovery" | Add-Content $Csv -Encoding utf8

$deadline = (Get-Date).AddHours($DurationHours)
$checkNum = 0
$lastTotal = -1
$stallCount = 0

Log "START monitoring for $DurationHours hours"
Log "Nodes: $($Nodes.Count) ($(($Nodes | ForEach-Object { $_.name }) -join ', '))"

while((Get-Date) -lt $deadline){
    $checkNum++
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    foreach($node in $Nodes){
        $s = Rpc $node.rpc "aether_getDagStats" @()
        $ys = Rpc $node.rpc "aether_getSyncStats" @()
        if($s -and $ys){
            $total = $s.total_transactions
            $tips = $s.tip_count
            $peers = $s.connected_peers
            $rebuild = $ys.rebuild_total
            $glocal = $ys.getdata_local
            $gremote = $ys.getdata_remote
            $dup = $ys.duplicate_ignored
            $shits = $ys.store_hits
            $wal = $ys.wal_recovery
            
            "$ts,$($node.name),$total,$tips,$peers,$rebuild,$glocal,$gremote,$dup,$shits,$wal" | Add-Content $Csv -Encoding utf8
            
            # Detect stall
            if($node.name -eq "node1"){
                if($total -eq $lastTotal){ $stallCount++ } else { $stallCount = 0 }
                $lastTotal = $total
            }
            
            # Detect anomalies
            if($rebuild -gt 0){ Log "ALERT: $($node.name) rebuild=$rebuild" }
            if($wal -gt 0){ Log "ALERT: $($node.name) wal_recovery=$wal" }
        } else {
            Log "ALERT: $($node.name) DOWN"
        }
    }
    
    # Console summary every 15 min
    if($checkNum % 15 -eq 0){
        $ref = Rpc 42101 "aether_getDagStats" @()
        $matchCount = 0
        foreach($node in $Nodes){
            $s = Rpc $node.rpc "aether_getDagStats" @()
            if($s -and $s.total_transactions -eq $ref.total_transactions){ $matchCount++ }
        }
        $elapsed = [math]::Round(((Get-Date) - $deadline.AddHours($DurationHours)).TotalMinutes, 1)
        Log "CHECK #$checkNum (${elapsed}min): total=$($ref.total_transactions) tips=$($ref.tip_count) peers=$($ref.connected_peers) match=$matchCount/$($Nodes.Count) stall=$stallCount"
    }
    
    # Stall detection
    if($stallCount -ge 10){
        Log "WARNING: DAG stalled for $stallCount checks at total=$lastTotal"
    }
    
    Start-Sleep 60
}

Log "MONITORING COMPLETE: $checkNum checks over $DurationHours hours"
Log "Final total: $lastTotal"
