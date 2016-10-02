# Yet Another Cryptopals repo [![Build Status](https://travis-ci.org/yoeo/cryptopals.svg?branch=master)](https://travis-ci.org/yoeo/cryptopals)
Hacking modern Cryptography / Cryptopals challenges answers in Ruby

## What is it?
It is a set of answers to Cryptopals cryptography challenges
http://cryptopals.com

![Alt text](data/screen.png)

This project implements attacks on actual cryptography, including:
 * cracking **AES encrypted messages** exploiting algorithm usage pitfalls
 * cloning Pseudo Random Number Generators to **predict random numbers**
 * breaking unsafe message signature and **sign malicious messages**
 * setting up **timing attacks**
 * and much much more**...**

Along with the challenges answers you will find rough implementation
of algorithms used in cryptography like SHA1, MD4, MT19937...

Current status:

|Challenges set                                                 |Status  |
|---------------------------------------------------------------|--------|
|1. [Basics](http://cryptopals.com/sets/1)                      |**100%**|
|2. [Block crypto](http://cryptopals.com/sets/2)                |**100%**|
|3. [Block & stream crypto](http://cryptopals.com/sets/3)       |**100%**|
|4. [Stream crypto and randomness](http://cryptopals.com/sets/4)|**100%**|
|5. [Diffie-Hellman and friends](http://cryptopals.com/sets/5)  |**100%**|
|6. [RSA and DSA](http://cryptopals.com/sets/6)                 |*50%*   |
|7. [Hashes](http://cryptopals.com/sets/7)                      |*-*     |
|8. [Abstract Algebra](http://cryptopals.com/sets/8)            |*-*     |

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

Go to http://cryptopals.com to view the tests,
read the code to understand the answers.

## License?
GNU GPL v3, see https://www.gnu.org/licenses/gpl-3.0.txt

## Why?
Because it's fun to break things **let's break some crypto** :unlock:
