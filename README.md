# spoof-checker
## Overview
The script simply checks whether a given domain can be spoofed or not. The program checks SPF and DMARC records for weak configurations that potentially allow spoofing.

It is an adaptation of the [spoofcheck](https://github.com/BishopFox/spoofcheck) in python3 with complete structural makeover. Thanks for the idea!!!

Usage:
```
python3 spoofdetect.py [DOMAIN]
```
Domains are said to be spoofable if the following conditions are met:
* Lack of an SPF or DMARC record altogether
* SPF record that never specifies softfail (~all) or hardfail (-all)
* SPF with softfail, and DMARC with policy as none (p=none) or non-existent.

## Only Catch
Made with :heart: for Linux (Sorry Windows :smiling_imp:)

## Things to add
* Support for **include** and **redirect** SPF record parameters
* Support for organizational DMARC record checks

## References
* [Detectify Blog](https://blog.detectify.com/2016/06/20/misconfigured-email-servers-open-the-door-to-spoofed-emails-from-top-domains/)
* [SPF Syntax Table](https://dmarcian.com/spf-syntax-table/)
* [DMARC Structure](https://dmarc.org/overview/)
