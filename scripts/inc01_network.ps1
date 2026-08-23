# inc01_network.ps1 - INC-01 network campaign: rebuild / crash / GetData / 14 nodes
# Ports alignés phase F: node1-8 42001-49001 p2p / 42101-49101 rpc, node9-14 49002-49007/49102-49107
param(
    [string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe",
    [string]$Root = "$env:TEMP\opencode\aether-canary-inc01",
    [string]$WalletsRoot = "$env:TEMP\opencode\aether-canary-b4",
    [string]$Out = "$env:TEMP\opencode\aether-canary-inc01-result",
    [int]$Nodes = 14
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$Log = Join-Path $Out "inc01_network.log"
$Csv = Join-Path $Out "inc01_network.csv"
$PW = "canary-pass-2026"
if (-not (Test-Path $Bin)) { throw "binary not found: $Bin" }
$Addrs = @("eee2fc331674af7669fb07023f9b62753a1f34ac7f2b15fce26282c811b301b1","f1de7fbfb834c25af4200afb71636c08b633b13a2aa4f4917d94e812c8d80dc0","3b9fdf9903d987025f7980ff20cbb07fc0ae0edafca1ec82d7f6a5a4fad1a7d8","a8dfcc54e32c7bc6695ebb39182b2a6043ca971f5deebfdf33f61ef578b28484","f499fa066be16d25a917e7cc9d4cc598a91b9af2d9232a0dd8cd5948ca32644f","e4dd96bf597798e583efcbf5ac02eb95cd697da6f076fda61aea2a1c86c8c298","390d26b4b8bde10118d2e673dadedcc1ab79bb5cbf276a775f378768e1e89898","8ddf5ce49ed728dec797a1aa089df72ee0e56836d6a819b4ebd657a2d20c5e60","2c7ebf0ccc3c291e1a578ae409e3be33ff9af8a34cb6265a699c757d651b8a07","40cca42d8257bb6e223af76df1ec37343d0541441e9d4170bfb45c995e362cca","6a4f940ca8730d92d7dd556b8a67cf763df84b3f3ee288bd4fe13e1dbfcf109b","84d6e6b04c22c3e733fafc0ca0c842c5b43274aa5079c6fbaa2c4e2a288f843d","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb","2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4","1111111111111111111111111111111111111111111111111111111111111111")
function Log($m){ $l="[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),$m; Add-Content -Path $Log -Value $l -Encoding utf8; Write-Host $l }
function Rpc($port,$method,$params){ try{ $b=@{jsonrpc="2.0";method=$method;params=$params;id=1}|ConvertTo-Json -Compress -Depth 6; $r=Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 20; return $r.result }catch{ return $null } }
function HexId($b){ if($null -eq $b){return ""} if($b -is [string]){return $b} if($b -is [byte[]]){ return (($b|ForEach-Object{$_.ToString("x2")}) -join "") } return "$b" }
function Get-State($port){
    $st=Rpc $port "aether_getDagStats" @()
    if(-not $st){ return $null }
    $g=Rpc $port "aether_getDagGraph" @(10000)
    $tipsRaw=Rpc $port "aether_getTips" @()
    $tips=@()
    if($tipsRaw -and $tipsRaw.tips){ $tips=@($tipsRaw.tips|Sort-Object|ForEach-Object{ HexId $_ }) } elseif($tipsRaw -and $tipsRaw.result -and $tipsRaw.result.tips){ $tips=@($tipsRaw.result.tips|Sort-Object|ForEach-Object{ HexId $_ }) }
    $led=@(); $supply=0
    foreach($a in $Addrs){ $bl=Rpc $port "aether_getBalance" @($a); $nn=Rpc $port "aether_getAccountNonce" @($a); if($bl -and $nn){ $led+="$a=$($bl.balance)/$($nn.next_nonce)"; $supply+=[long]$bl.balance } else { $led+="$a=ERR" } }
    $txset=@(); $dag=@(); $w=@()
    if($g -and $g.nodes){ $txset=@($g.nodes|ForEach-Object{ HexId $_.tx_id }|Sort-Object); $dag=@($g.edges|ForEach-Object{ (HexId $_.from)+"->"+(HexId $_.to) }|Sort-Object); $w=@($g.nodes|Sort-Object{ HexId $_.tx_id }|ForEach-Object{ (HexId $_.tx_id)+":"+$_.weight }) }
    elseif($g -and $g.result -and $g.result.nodes){ $txset=@($g.result.nodes|ForEach-Object{ HexId $_.tx_id }|Sort-Object); $dag=@($g.result.edges|ForEach-Object{ (HexId $_.from)+"->"+(HexId $_.to) }|Sort-Object); $w=@($g.result.nodes|Sort-Object{ HexId $_.tx_id }|ForEach-Object{ (HexId $_.tx_id)+":"+$_.weight }) }
    return @{ txset=($txset -join ","); dag=($dag -join ","); tips=($tips -join ","); led=($led -join ";"); w=($w -join ","); supply="$supply"; total=[long]$st.total_transactions; tipcount=[long]$st.tip_count }
}
function Fp($s){ $sha=[System.Security.Cryptography.SHA256]::Create(); $txt="$($s.txset)|$($s.dag)|$($s.tips)|$($s.led)|$($s.w)|$($s.supply)"; return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($txt))|ForEach-Object{$_.ToString("x2")}) -join "") }
function NodePorts($id){ if($id -le 8){ $p2p=41000+$id*1000+1; $rpc=41100+$id*1000+1 } else { $p2p=49000+$id; $rpc=49100+$id } return @($p2p,$rpc) }
function Wait-Up($id,$timeoutSec=90){ $ports=NodePorts $id; $deadline=(Get-Date).AddSeconds($timeoutSec); while((Get-Date) -lt $deadline){ $s=Rpc $ports[1] "aether_getDagStats" @(); if($s -and $null -ne $s.total_transactions){ return $true } Start-Sleep 1 } return $false }
function Start-Node($id,$fresh){ $ports=NodePorts $id; $dir=Join-Path $Root ("node"+$id); if($fresh -and (Test-Path $dir)){ Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue } New-Item -ItemType Directory -Force -Path $dir|Out-Null; # copy faucet.key for node1 so aether_faucet is enabled
    $fkSrc="$env:TEMP\opencode\aether-canary-phase-e\node1\faucet.key"; if((Test-Path $fkSrc) -and $id -eq 1 -and -not (Test-Path (Join-Path $dir "faucet.key"))){ Copy-Item $fkSrc (Join-Path $dir "faucet.key") -Force; Log "copied faucet.key to node$id" }
    # LOCAL ONLY: pas de VPS 103.102.135.123:25565 — tous les nœuds utilisent le seed local 127.0.0.1:42001 (node1 inclus en self pour écraser le default VPS)
    $args=@("--node-type","validator","--data-dir",$dir,"--p2p-port","$($ports[0])","--rpc-port","$($ports[1])","--bootnodes","127.0.0.1:42001"); $proc=Start-Process -FilePath $Bin -ArgumentList $args -RedirectStandardOutput (Join-Path $dir "node.log") -RedirectStandardError (Join-Path $dir "node.err") -WindowStyle Hidden -PassThru; if(-not (Wait-Up $id 90)){ Log "node$id FAILED to come up"; return $null } Log "node$id up p2p $($ports[0]) rpc $($ports[1]) pid $($proc.Id)"; return $proc }
function Stop-Node($id){ $ports=NodePorts $id; $dir=Join-Path $Root ("node"+$id); $procs=Get-CimInstance Win32_Process -Filter "Name='aether.exe'" -ErrorAction SilentlyContinue | Where-Object{ $_.CommandLine -match [regex]::Escape($dir) }; foreach($p in $procs){ try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }catch{} } Start-Sleep 2 }
function Kill-Hard($id){ $dir=Join-Path $Root ("node"+$id); $procs=Get-CimInstance Win32_Process -Filter "Name='aether.exe'" -ErrorAction SilentlyContinue | Where-Object{ $_.CommandLine -match [regex]::Escape($dir) }; foreach($p in $procs){ try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; Log "KILL hard node$id pid $($p.ProcessId)" }catch{} } }
function TxTotal($rpc){ $s=Rpc $rpc "aether_getDagStats" @(); if($s){ return [long]$s.total_transactions } return -1 }
function Ramp-To($target,$label){
    $rpc=(NodePorts 1)[1]
    $base=TxTotal $rpc; Log "RAMP $label : base=$base target=$target"
    if($base -ge $target){ Log " already at $base >= $target"; return $true }
    # PERFORMANCE: 8× parallèle via wallets b8_*.json (pré-fundés par faucet) — ~2-3 tx/s vs 0.6 tx/s single-faucet, nécessaire pour 10k <2h
    $wallets=@(); foreach($i in 0..7){ $f="$WalletsRoot\b8_$i.json"; if(Test-Path $f){ $o= (& $Bin balance $f --rpc-url "http://127.0.0.1:$rpc" --password $PW 2>&1 | Out-String); $addr=([regex]::Match($o,"Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower(); if($addr){ $wallets+=@{addr=$addr;path=$f} } } }
    if($wallets.Count -eq 0){ Log "WARN no wallets, fallback single-faucet"; $sw=[System.Diagnostics.Stopwatch]::StartNew(); $waves=0; $accepted=0; while((TxTotal $rpc) -lt $target -and $waves -lt 8000){ $waves++; $g1=[Guid]::NewGuid().ToString("N"); $g2=[Guid]::NewGuid().ToString("N"); $randAddr=($g1+$g2).Substring(0,64); $r=Rpc $rpc "aether_faucet" @($randAddr); $isOk=$false; if($r){ if($r.success -eq $true -or $r.status -eq "ok"){ $isOk=$true } }; if($isOk){ $accepted++ }; if($waves % 50 -eq 0){ Log " wave $waves accepted=$accepted total=$(TxTotal $rpc)" }; Start-Sleep -Milliseconds 80 }; $sw.Stop(); $cur=TxTotal $rpc; Log "RAMP $label done: accepted=$accepted total=$cur in $($sw.Elapsed.TotalSeconds.ToString('N1'))s"; return ($cur -ge $target) }
    # fund wallets once if balance low (faucet 10 AETH ≈ 990 tx per wallet)
    foreach($w in $wallets){ $bal=Rpc $rpc "aether_getBalance" @($w.addr); if(-not $bal -or [long]$bal.balance -lt 50000000000){ $g1=[Guid]::NewGuid().ToString("N"); $g2=[Guid]::NewGuid().ToString("N"); $randAddr=($g1+$g2).Substring(0,64); $fr=Rpc $rpc "aether_faucet" @($w.addr); if($fr.success){ Log "funded $($w.addr.Substring(0,8))" } Start-Sleep -Milliseconds 200 } }
    $sw=[System.Diagnostics.Stopwatch]::StartNew(); $waves=0; $accepted=0
    while((TxTotal $rpc) -lt $target -and $waves -lt 5000){
        $waves++; $procs=@()
        foreach($w in $wallets){ $to=([Guid]::NewGuid().ToString("N")+ [Guid]::NewGuid().ToString("N")).Substring(0,64); $procs+=Start-Process -FilePath $Bin -ArgumentList @("send",$to,"1","10","--rpc-url","http://127.0.0.1:$rpc","--wallet",$w.path,"--password",$PW) -WindowStyle Hidden -PassThru }
        foreach($p in $procs){ $p.WaitForExit(15000) | Out-Null; if($p.ExitCode -eq 0){ $accepted++ } }
        if($waves % 20 -eq 0){ $cur=TxTotal $rpc; Log " wave $waves accepted=$accepted total=$cur" }
        if($waves % 100 -eq 0){ $cur=TxTotal $rpc; if($cur -eq $base -and $cur -lt $target){ Log " STALL at wave $waves cur=$cur" } $base=$cur }
        Start-Sleep -Milliseconds 100
    }
    $sw.Stop(); $cur=TxTotal $rpc; Log "RAMP $label done: accepted=$accepted total=$cur in $($sw.Elapsed.TotalSeconds.ToString('N1'))s"
    return ($cur -ge $target)
}
function Check-Converged($ids,$label){
    $ref=Get-State (NodePorts $ids[0])[1]; if(-not $ref){ Log "FAIL $label : ref node $($ids[0]) DOWN"; return $false }
    $refFp=Fp $ref; $ok=$true
    foreach($id in $ids){
        $s=Get-State (NodePorts $id)[1]; if(-not $s){ Log "FAIL $label : node$id DOWN"; $ok=$false; continue }
        $fp=Fp $s
        $match=($s.txset -eq $ref.txset) -and ($s.dag -eq $ref.dag) -and ($s.tips -eq $ref.tips) -and ($s.led -eq $ref.led) -and ($s.w -eq $ref.w) -and ($s.supply -eq $ref.supply) -and ($s.total -eq $ref.total)
        if(-not $match){
            Log "FAIL $label : node$id diverged total $($s.total) vs ref $($ref.total) fp $fp vs $refFp"
            Log "  ref tips=$($ref.tips.Substring(0,[Math]::Min(80,$ref.tips.Length)))"
            Log "  node tips=$($s.tips.Substring(0,[Math]::Min(80,$s.tips.Length)))"
            $ok=$false
        } else {
            Log "PASS $label : node$id converged total=$($s.total) fp=$($fp.Substring(0,12))"
        }
        # also log sync stats
        $ys=Rpc (NodePorts $id)[1] "aether_getSyncStats" @()
        if($ys){ Log "  sync node$id : rebuild_total=$($ys.rebuild_total) orphan_resolved=$($ys.orphan_resolved) store_hits=$($ys.store_hits) getdata_local=$($ys.getdata_local) getdata_remote=$($ys.getdata_remote)" }
    }
    if($ok){ Log "CONVERGED [$label] nodes $($ids -join ',') total=$($ref.total) fp=$($refFp.Substring(0,16))" }
    return $ok
}
function Test-Reboot($ids,$target,$label){
    Log "=== REBOOT TEST $label target $target ==="
    $ok=Ramp-To $target $label; if(-not $ok){ Log "WARN ramp not reached $target"; }
    Start-Sleep 5
    $preOk=Check-Converged $ids "pre-reboot $label"
    # pick victim node 8 (if exists) else last
    $victim=$ids[-1]; $vRpc=(NodePorts $victim)[1]
    $preState=Get-State $vRpc; $preFp=Fp $preState
    Log "Killing victim node$victim total=$($preState.total) fp=$($preFp.Substring(0,12))"
    Stop-Node $victim; Start-Sleep 3
    $t0=Get-Date
    $proc=Start-Node $victim $false; if(-not $proc){ Log "FAIL reboot $label : node$victim did not restart"; return $false }
    $rebuildTime=((Get-Date)-$t0).TotalSeconds
    Log "node$victim restarted rebuildTime=${rebuildTime}s"
    # wait for sync
    $deadline=(Get-Date).AddSeconds(120); $synced=$false
    while((Get-Date) -lt $deadline){
        $s=Get-State $vRpc; $ref=Get-State (NodePorts $ids[0])[1]
        if($s -and $ref -and $s.total -eq $ref.total -and (Fp $s) -eq (Fp $ref)){ $synced=$true; break }
        Start-Sleep 3
    }
    if(-not $synced){ Log "FAIL reboot $label : node$victim did not resync within 120s"; Check-Converged $ids "post-reboot $label"; return $false }
    $postState=Get-State $vRpc; $postFp=Fp $postState
    $eq=($preFp -eq $postFp) -or (Check-Converged $ids "post-reboot $label")
    Log "POST reboot node$victim total=$($postState.total) fp=$($postFp.Substring(0,12)) rebuildTime=${rebuildTime}s synced=$synced"
    return $eq
}
function Test-GetDataStoreFirst($label){
    Log "=== GetData store-first $label ==="
    $rpc=(NodePorts 1)[1]
    # pick a tx id from getDagGraph
    $g=Rpc $rpc "aether_getDagGraph" @(5)
    $txId=$null
    if($g -and $g.nodes -and $g.nodes.Count -gt 0){ $txId=HexId $g.nodes[0].tx_id } elseif($g -and $g.result -and $g.result.nodes.Count -gt 0){ $txId=HexId $g.result.nodes[0].tx_id }
    if(-not $txId){ Log "SKIP GetData : no tx yet"; return $true }
    # victim node rebooted already has tx on disk but not in mempool
    $victim=14; if($Nodes -lt 14){ $victim=$Nodes }
    $vRpc=(NodePorts $victim)[1]
    $before=Rpc $vRpc "aether_getSyncStats" @()
    $r=Rpc $vRpc "aether_getTransaction" @($txId)
    $after=Rpc $vRpc "aether_getSyncStats" @()
    $servedLocal=$false
    if($r -and $r.tx_id -or $r -and $r.result -and $r.result.tx_id){ $servedLocal=$true }
    Log "GetData existing tx $txId : servedLocal=$servedLocal before_getdata_local=$($before.getdata_local) after=$($after.getdata_local) store_hits=$($after.store_hits)"
    # missing tx should trigger P2P
    $fake="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    $b2=Rpc $vRpc "aether_getSyncStats" @()
    $r2=Rpc $vRpc "aether_getTransaction" @($fake)
    $a2=Rpc $vRpc "aether_getSyncStats" @()
    Log "GetData missing tx : result null=$($null -eq $r2) store_misses before=$($b2.store_misses) after=$($a2.store_misses) getdata_remote before=$($b2.getdata_remote) after=$($a2.getdata_remote)"
    $pass=$servedLocal -and ($after.getdata_local -gt $before.getdata_local) -and ($a2.store_misses -gt $b2.store_misses)
    if($pass){ Log "PASS GetData store-first $label" } else { Log "FAIL GetData store-first $label" }
    return $pass
}
function Test-CrashHard($ids,$label){
    Log "=== CRASH DUR $label ==="
    $rpc=(NodePorts 1)[1]
    Ramp-To 200 "crash-preload" | Out-Null
    $victim=$ids[-1]; $vRpc=(NodePorts $victim)[1]
    $pre=Get-State $vRpc; $preFp=Fp $pre
    # start ramp in background then kill during write
    $job=Start-Job -ScriptBlock { param($bin,$rpc,$pw,$walletsRoot) $gen=@(); foreach($i in 0..3){ $f="$walletsRoot\b8_$i.json"; if(Test-Path $f){ $o= (& $bin balance $f --rpc-url "http://127.0.0.1:$rpc" --password $pw 2>&1 | Out-String); $addr=([regex]::Match($o,"Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower(); if($addr){ $gen+=@{addr=$addr;path=$f} } } }; for($k=0;$k -lt 30;$k++){ foreach($gw in $gen){ Start-Process -FilePath $bin -ArgumentList @("send",$gw.addr,"1","10","--rpc-url","http://127.0.0.1:$rpc","--wallet",$gw.path,"--password",$pw) -WindowStyle Hidden | Out-Null } Start-Sleep -Milliseconds 300 } } -ArgumentList $Bin,$rpc,$PW,$WalletsRoot
    Start-Sleep 2
    Kill-Hard $victim
    Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    Start-Sleep 3
    $t0=Get-Date; $proc=Start-Node $victim $false; $rebuild=((Get-Date)-$t0).TotalSeconds
    if(-not $proc){ Log "FAIL crash $label : restart failed"; return $false }
    $deadline=(Get-Date).AddSeconds(120); $synced=$false
    while((Get-Date) -lt $deadline){
        $s=Get-State $vRpc; $ref=Get-State (NodePorts $ids[0])[1]
        if($s -and $ref -and $s.total -eq $ref.total){ $synced=$true; break }
        Start-Sleep 3
    }
    $post=Get-State $vRpc; $postFp=Fp $post
    $ys=Rpc $vRpc "aether_getSyncStats" @()
    Log "CRASH result: pre total=$($pre.total) post total=$($post.total) rebuild=${rebuild}s synced=$synced wal_recovery=$($ys.wal_recovery) rebuild_total=$($ys.rebuild_total) rebuild_inserted=$($ys.rebuild_inserted) rebuild_orphaned=$($ys.rebuild_orphaned)"
    $div=($preFp -ne $postFp) -and ($post.total -ne $pre.total)
    if(-not $synced){ Log "FAIL crash $label : not synced"; return $false }
    $conv=Check-Converged $ids "post-crash $label"
    return $conv
}

# --- CLEAN ---
Log "CLEAN $Root"
Get-CimInstance Win32_Process -Filter "Name='aether.exe'" -ErrorAction SilentlyContinue | ForEach-Object{ try{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }catch{} }
Start-Sleep 2
if(Test-Path $Root){ Remove-Item -Recurse -Force $Root -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $Root|Out-Null
if(Test-Path $Out){ Remove-Item -Recurse -Force "$Out\*" -ErrorAction SilentlyContinue }

# --- LAUNCH 14 nodes ---
Log "Launching $Nodes nodes"
$procs=@()
for($i=1;$i -le $Nodes;$i++){ $p=Start-Node $i $true; if(-not $p){ Log "FAILED to start node$i"; exit 1 } $procs+=$p; Start-Sleep -Milliseconds 500 }
Start-Sleep 10
$ids=1..$Nodes
Check-Converged $ids "initial" | Out-Null

# --- REBOOT 100 / 1000 / 5000 / 10000 ---
$results=@()
$results+= @{ label="reboot-100"; ok=(Test-Reboot $ids 100 "reboot-100") }
$results+= @{ label="reboot-1000"; ok=(Test-Reboot $ids 1000 "reboot-1000") }
$results+= @{ label="reboot-5000"; ok=(Test-Reboot $ids 5000 "reboot-5000") }
$results+= @{ label="reboot-10000"; ok=(Test-Reboot $ids 10000 "reboot-10000") }

# --- GetData store-first ---
$results+= @{ label="getdata-store-first"; ok=(Test-GetDataStoreFirst "getdata") }

# --- Crash dur ---
$results+= @{ label="crash-dur"; ok=(Test-CrashHard $ids "crash-dur") }

# --- Reboots répétés (3x node8) ---
Log "=== REBOOTS REPETES 3x ==="
$repOk=$true
for($k=1;$k -le 3;$k++){
    $victim=8; Stop-Node $victim; Start-Sleep 2; $p=Start-Node $victim $false
    if(-not $p){ $repOk=$false; break }
    Start-Sleep 10
    if(-not (Check-Converged $ids "rep-$k")){ $repOk=$false; break }
}
$results+= @{ label="reboots-repetes"; ok=$repOk }
Log "repetes ok=$repOk"

# --- Final 14 nodes convergence ---
$final=Check-Converged $ids "final-14nodes"
$results+= @{ label="final-14nodes"; ok=$final }

# --- SUMMARY ---
Log "=== SUMMARY ==="
foreach($r in $results){ Log ("{0}: {1}" -f $r.label, $(if($r.ok){"PASS"}else{"FAIL"})) }
$fails=@($results | Where-Object{ -not $_.ok })
if($fails.Count -gt 0){ Log "OVERALL FAIL : $($fails.Count) / $($results.Count)"; exit 1 } else { Log "OVERALL PASS : $($results.Count)/$($results.Count)"; exit 0 }
