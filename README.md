MozillaRecovery
===============

Recovers the master password of key3.db files, i.e. Thunderbird, Firefox

### Usage

Once you start the program, it searches automatically for default locations of your key3.db in Firefox and, if not found, in the Thunderbird application directory. I prepared and tested this for Windows 7 and Linux. You can change the location manually, of course. key3.db is the file that is used to recover the master password.

You have three kinds of attack:
- Wordlist attack: Tries passwords from a given wordlist.
- Bruteforce attack: Tries every combination from given chars up to a configurable length. 
- Proccess wordlist attack: Uses the output from a given program as wordlist. (Interesting, for example, in combination with rule based wordlist generators)
