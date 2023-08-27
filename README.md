# ZNC FISHSLiM Reloaded

FISHSLiM encryption for ZNC with support for CBC and ECB modes, and key exchange using DH1080

## Features:
- FISHSLiM encryption CBC and ECB over:
  - Channel messages
  - Private messages
  - Topics
  - Actions
  - Notices
- Key exchange with DH1080
- Visual message prefixes that indicate:
  - E🔓 > Encrypted message using ECB mode **(UNSAFE)**
  - C🔒 > Encrypted message using CBC mode **(USE THIS ALWAYS)**
  - 🔄  > The sender sent the message using a different encryption mode than the one saved in their keychain
  - ❌  > The sender sent an unencrypted message in a context where you use encryption
  - ⚠️ > The incoming message couldn't be decrypted

## Install

1. You need to have the `pycryptodome` library installed in your Python environment
2. Copy the `fishslism.py` file into the `modules` folder in your ZNC configuration folder
3. Enable in ZNC per each network

## Commands

- **ListKeys** Display the keys in the keychain 
- **SetKey <target> <key>** Set a new key for a target
- **DelKey <target>** Delete a key for a target
- **KeyX <target>** Initiate key exchange using DH1080 with a target