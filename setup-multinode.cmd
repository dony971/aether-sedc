@echo off
setlocal

set "ROOT=C:\Users\Shadow\Documents\aether-fix\aether-main"
set "PATH=C:\Users\Shadow\AppData\Local\Temp\opencode\mingw\mingw64\bin;%PATH%"

echo Cleaning data directories...
if exist "%ROOT%\data-bootnode" rmdir /s /q "%ROOT%\data-bootnode"
if exist "%ROOT%\data-miner-1" rmdir /s /q "%ROOT%\data-miner-1"
if exist "%ROOT%\data-miner-2" rmdir /s /q "%ROOT%\data-miner-2"

echo Starting bootnode (P2P:25565 RPC:9933)...
start /B "" "%ROOT%\target\debug\aether.exe" --node-type miner --data-dir "%ROOT%\data-bootnode" --p2p-port 25565 --rpc-port 9933

echo Waiting for bootnode...
:wait_boot
timeout /t 3 /nobreak >nul
for /f "tokens=*" %%a in ('curl -s -X POST http://127.0.0.1:9933 -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"aether_getDagStats\",\"params\":[],\"id\":1}" 2^>nul') do set "RESP=%%a"
echo %RESP% | findstr "total_transactions" >nul 2>&1
if errorlevel 1 goto wait_boot
echo Bootnode READY!

echo Starting miner1 (P2P:25566 RPC:9934)...
start /B "" "%ROOT%\target\debug\aether.exe" --node-type miner --data-dir "%ROOT%\data-miner-1" --p2p-port 25566 --rpc-port 9934 --bootnodes 127.0.0.1:25565

echo Starting miner2 (P2P:25567 RPC:9935)...
start /B "" "%ROOT%\target\debug\aether.exe" --node-type miner --data-dir "%ROOT%\data-miner-2" --p2p-port 25567 --rpc-port 9935 --bootnodes 127.0.0.1:25565

echo Network is running!
echo Bootnode: http://127.0.0.1:9933
echo Miner1:   http://127.0.0.1:9934
echo Miner2:   http://127.0.0.1:9935
echo.
echo Check peers:
echo curl -s -X POST http://127.0.0.1:9933 -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"aether_getDagStats\",\"params\":[],\"id\":1}"
echo Test P2P propagation:
echo curl -s -X POST http://127.0.0.1:9934 -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"aether_faucet\",\"params\":[\"f0b7b77b7669460f3aa3d5f82ec363dd68d555e305207097b17c196dd00d1f0b\"],\"id\":1}"
