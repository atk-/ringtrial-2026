#!/bin/sh

# 03: SQLCipher
hashcat -O -m 24600 03-toonvault/db.hash $@

# 05: RAR
hashcat -O -m 13000 05-rar/rar.hash $@
