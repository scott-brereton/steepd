# Third-party notices

## EFF large wordlist

`src/steepd/wordlist.txt` is derived from the Electronic Frontier Foundation's large
wordlist for passphrases (`eff_large_wordlist.txt`, 2016), published at
https://www.eff.org/dice and licensed under the Creative Commons Attribution 3.0 United
States licence (https://creativecommons.org/licenses/by/3.0/us/). The vendored copy
strips the leading dice indices and omits the four hyphenated entries; see
`src/steepd/words.py` for the exact diff.

## Trafilatura

Steepd uses Trafilatura 2.2.0 to extract the readable article and metadata from webpage
HTML. Trafilatura is published at https://github.com/adbar/trafilatura and licensed under
the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).
