@echo off
REM Bridge: run licensed kdb-x q in WSL on a script FILE (arg %1 = Windows path).
REM File-based, not stdin: the WSL stdin layer mangles backticks. The q file
REM content is read by q directly, so bash here is safe (no shell parse of it).
wsl bash -lc "QHOME=$HOME/kdbx QLIC=$HOME/kdbx exec $HOME/kdbx/l64/q \"$(wslpath '%~1')\" -q"
