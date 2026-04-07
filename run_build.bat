@echo off
cd /d c:\Users\mehta\Desktop\SecureGuard
dotnet build -v m > build_latest.txt 2>&1
type build_latest.txt
