# UEberForensIcs
With UEberForensics we integrate forensic software that enables cold boot like memory acquisition directly into a computer's firmware.
The proof-of-concept is implemented as a DXE-Driver for [OVMF](https://github.com/tianocore/tianocore.github.io/wiki/OVMF) based on [EDK II](https://github.com/tianocore/tianocore.github.io/wiki/EDK-II).
The driver acquires the memory and sends it via TCP to a forensic workstation server.

## Implementation
UEberForensic is implemented as a standalone application and also as a dynamic command.
It does not store memory dumps on the local drive as it would lead to corruption, but exfiltrates the data via the network.
This is achieved via the EDK II TCP stack.
