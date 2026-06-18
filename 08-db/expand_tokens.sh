#!/bin/bash
XFILE=expanded_tokens.txt
hashcat --stdout -a 0 tokens.txt -r tokens.rule > $XFILE
sort -u $XFILE -o $XFILE
