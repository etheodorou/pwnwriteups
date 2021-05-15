# Chall_00

##Solution

#####Disassembling

First we run 'checksec --file=a.out' to see any vulnerabilities and see there is 'No canary found'. 
Then we run 'r2 -Ad a.out' to disassemble the file in debug mode and then enter 's main' to be taken to main and 'Vp' to open visual.
