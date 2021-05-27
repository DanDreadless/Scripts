@ECHO off
SETLOCAL

:: change source and destination as required

SET _source=\\SERVER\SHARE
SET _dest=\\SERVER\SHARE

SET _what=/MIR /SEC /ZB /XD "$RECYCLE.BIN" "System Volume Information"
:: /MIR :: MIRror a directory tree 
:: /SEC :: copies files with security
:: /Z :: copy files in restartable mode
:: /B :: copy files in Backup mode. 
:: /XD :: exclude directory

:: change log location as required

SET _options=/R:0 /W:0 /LOG:C:\batch\RoboLog_%date:~-4,4%%date:~-7,2%%date:~-10,2%.txt /NFL /NDL
:: /R:n :: number of Retries
:: /W:n :: Wait time between retries
:: /LOG :: Output log file
:: /NFL :: No file logging
:: /NDL :: No dir logging

ROBOCOPY %_source% %_dest% %_what% %_options%
