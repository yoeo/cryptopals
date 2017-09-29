# Hacking state-of-the-art Cryptography [![Build Status](https://travis-ci.org/yoeo/cryptopals.svg?branch=master)](https://travis-ci.org/yoeo/cryptopals)
*Cryptopals challenges solved in Ruby*

## What is it?

This project demonstrates attacks on **state-of-the-art
Cryptography** implementations, including
[AES](https://fr.wikipedia.org/wiki/Advanced_Encryption_Standard),
[RSA](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29),
[SHA-1](https://fr.wikipedia.org/wiki/SHA-1),
[random number generators](https://en.wikipedia.org/wiki/Mersenne_Twister)
and much more...

## Which attacks are implemented?

[Basics](lib/set_1_basics.rb)
  - [x] **Convert hex to base64**
    - encodes hex to base64
  - [x] **Fixed XOR**
    - runs XOR
  - [x] **Single-byte XOR cipher**
    - decrypts simple XOR
  - [x] **Detect single-character XOR**
    - finds encrypted line
  - [x] **Implement repeating-key XOR**
    - encrypts a text with a key
  - [x] **Break repeating-key XOR**
    - checks the Hamming distance
  - [x] **AES in ECB mode**
    - decrypts AES-ECB encrypted file
  - [x] **Detect AES in ECB mode**
    - finds the AES-ECB encrypted line

[Block Crypto](lib/set_2_block_crypto.rb)
  - [x] **Implement PKCS#7 padding**
    - appends padding to the input
  - [x] **Implement CBC mode**
    - implements CBC mode decryption from AES-ECB cipher
  - [x] **An ECB/CBC detection oracle**
    - detects ECB or CBC encryption mode
  - [x] **Byte-at-a-time ECB decryption (Simple)**
    - recovers the plain text from an ECB oracle
  - [x] **ECB cut-and-paste**
    - alters ECB encrypted data
  - [x] **Byte-at-a-time ECB decryption (Harder)**
    - recovers the first byte of plain text from a random ECB oracle
  - [x] **PKCS#7 padding validation**
    - strips valid padding**
    - fails while stripping bad padding
  - [x] **CBC bitflipping attacks**
    - decrypts CBC encrypted data

[Block and Stream Crypto](lib/set_3_block_and_stream_crypto.rb)
  - [x] **The CBC padding oracle**
    - attacks CBC using padding information
  - [x] **Implement CTR, the stream cipher mode**
    - implements CTR mode using ECB
  - [x] **Break fixed-nonce CTR mode using substitutions**
    - attacks text encrypted with same nonce in CTR mode
  - [x] **Break fixed-nonce CTR statistically**
    - attacks same nonce in CTR as a repeating-key XOR
  - [x] **Implement the MT19937 Mersenne Twister RNG**
    - implements a pseudorandom numbers generators
  - [x] **Crack an MT19937 seed**
    - guesses the seed of a pseudorandom numbers generators
  - [x] **Clone an MT19937 RNG from its output**
    - creates a copy of the state of a PRNG
  - [x] **Create the MT19937 stream cipher and break it**
    - creates a PRNG stream cipher
    - creates cracks the PRNG stream cipher
    - checks if a token comes from a MT19937 PRNG seeded with current time

[Stream Crypto and Randomness](lib/set_4_stream_crypto_and_randomness.rb)
  - [x] **Break "random access read/write" AES CTR**
    - attacks CTR using random access
  - [x] **CTR bitflipping**
    - modifies CTR encrypted text by flipping bits
  - [x] **Recover the key from CBC with IV=Key**
    - guesses the encryption key when key and IV are the same
  - [x] **Implement a SHA-1 keyed MAC**
    - works when the MAC matches
    - fails when the MAC doesn't match
  - [x] **Break a SHA-1 keyed MAC using length extension**
    - creates a valid SHA-1 MAC from tempered data
  - [x] **Break an MD4 keyed MAC using length extension**
    - works when the MAC matches
    - fails when the MAC doesn't match
    - creates a valid MD4 MAC from tempered data
  - [x] **Implement and break HMAC-SHA1 with an artificial timing leak**
    - works when the HMAC matches
    - finds the first byte of the HMAC from timing leak
  - [x] **Break HMAC-SHA1 with a slightly less artificial timing leak**
    - finds the first byte of the HMAC from a tiny timing leak

[Diffie Hellman and friends](lib/set_5_diffie_hellman_and_friends.rb)
  - [x] **Implement Diffie-Hellman**
    - ensures that the Diffie-Hellman session keys are valid
  - [x] **Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection**
    - checks the Echo protocol based on Diffie-Hellman
    - performs a man in the middle attack on Diffie-Hellman
  - [x] **Implement DH with negotiated groups, and break with malicious "g" parameters**
    - checks the negotiated groups protocol based on Diffie-Hellman
    - confirms that generated session key = 1 when injected g = 1
    - confirms that generated session key = 0 when injected g = p
    - confirms that session key = (1 or p - 1) when injected g = p - 1
  - [x] **Implement Secure Remote Password (SRP)**
    - authenticates when credentials matches**
    - fails to authenticate when credentials doesn't match
  - [x] **Break SRP with a zero key**
    - confirms that session value is 0 when injected client key is 0
    - confirms that session value is 0 when injected client key is N
    - confirms that session value is 0 when injected client key is x * N
  - [x] **Offline dictionary attack on simplified SRP**
    - authenticates when simplified SRP credentials matches
    - fails to authenticate when simplified SRP credentials doesn't match
    - cracks the password using MITM and dict attack on simplified SRP
  - [x] **Implement RSA**
    - encrypts and decrypts a message using RSA cryptosystem
  - [x] **Implement an E=3 RSA Broadcast attack**
    - cracks the broadcast RSA encrypted message when E is 3

[RSA and DSA](lib/set_6_rsa_and_dsa.rb)
  - [x] **Implement unpadded message recovery oracle**
    - recovers unpadded RSA encrypted message
  - [x] **Bleichenbacher's e=3 RSA Attack**
    - validates a PKCS#1 v1.5 padded hash
    - generates a fake signature for an e=3 RSA public key
  - [x] **DSA key recovery from nonce**
    - validates well signed message
    - doesn't validate bad signed message
    - recovers DSA secret key x from insecure session key k
  - [x] **DSA nonce recovery from repeated nonce**
    - recovers DSA secret key x from reused session key k
  - [x] **DSA parameter tampering**
    - launches a DOS attack when g = np
    - creates a DSA god key that validates any message when g = 1 + np

#### More details...

The vulnerabilities exploited in the attacks
are fully described on http://cryptopals.com:

1. [Basics](http://cryptopals.com/sets/1)
2. [Block crypto](http://cryptopals.com/sets/2)
3. [Block & stream crypto](http://cryptopals.com/sets/3)
4. [Stream crypto and randomness](http://cryptopals.com/sets/4)
5. [Diffie-Hellman and friends](http://cryptopals.com/sets/5)
6. [RSA and DSA](http://cryptopals.com/sets/6)
7. [Hashes](http://cryptopals.com/sets/7)

In the source code, you will find
[rough implementation of algorithms](lib/impl)
used in cryptography like SHA-1, MD4, MT19937...

## How to use it?

Use ```ruby >= 2.2```,
install the dependencies with ```bundle install``` and run it:
```bundle exec run.rb```

Usage:

```
run.rb [--help] [--slow] [SET_NUMBER]
  SET_NUMBER  : the number of the test to run, from 1 to 6
  --slow      : run slow tests, may take hours
  --help      : show help message
```

Examples:
```bash
bundle exec run.rb          # run all tests, except the slow ones
bundle exec run.rb --slow 2 # run all Set#2 tests including the slow ones
```

![Alt text](data/screen.png)

## License?

GNU GPL v3, see https://www.gnu.org/licenses/gpl-3.0.txt

## Why?

Because it's fun, **let's break some crypto** :unlock:
