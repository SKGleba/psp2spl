# psp2spl
Custom tiny lv0 framework for Playstation Vita/TV

# Usage
1) Put psp2spl.skprx in ur0:tai/
2) Add a line to ux0: or ur0: /tai/config.txt under *KERNEL
	- ur0:tai/psp2spl.skprx
3) Reboot

## Basic info for developers
### This framework's only task is to run lv0 code when requested: check [spl_exec_code] in main.c
	- For all communication ARM<->FRAMEWORK the secure kernel enc addr in Venezia SPRAM is used.
		- In spl it is referred to as "commem" or "corridor", spl uses only first 32 bytes of it for config.
	- There is one patch used: fcmd_handler() hook - After ARM command is received, before executing it.
	- At every sleep/resume the crypto processor is reset, commem is reset too.
	- The framework is injected by exploiting update_sm::0x50002 and is stored @0x00809e00

# Credits
	- Team Molecule for the update_sm 0x50002 exploit and help over discord
	- Team Molecule for HenKaku, TaiHen and Enso
	- TheFlow0 for help with the sleep-resume stuff