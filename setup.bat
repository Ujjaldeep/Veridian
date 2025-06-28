@echo off
mkdir var
cd var
mkdir main-instance
cd ..
IF NOT EXIST databases(
  mkdir databases
)
