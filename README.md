# pkcs12cracker

This crate is a simple tool to concurrently attack a password-protected PKCS#12 (PFX/P12) file. Its main goal is to be faster, more efficient, and more reliable than existing tools written in Go and C.

## Documentation

Detailed documentation is available at [futurelink](https://google.com).

#### Reliability Badges [TODO]

[![Build Status](https://travis-ci.com/username/repo.svg?branch=master)](https://travis-ci.com/username/repo)  
[![Coverage Status](https://coveralls.io/repos/github/username/repo/badge.svg?branch=master)](https://coveralls.io/github/username/repo?branch=master)  
[![Dependency Status](https://deps.rs/repo/github/username/repo/status.svg)](https://deps.rs/repo/github/username/repo)  
![Tests](https://github.com/wowinter13/finance_rb/actions/workflows/tests.yml/badge.svg)  
[![Release](https://img.shields.io/github/v/release/wowinter13/finance_rb.svg?style=flat-square)](https://github.com/wowinter13/finance_rb/releases)  
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)  
[![Maintainability](https://api.codeclimate.com/v1/badges/bbca82ad7815794c6718/maintainability)](https://codeclimate.com/github/wowinter13/finance_rb/maintainability)

#### High-Level Overview [TODO]

By default, all CPUs of the machine are utilized.

(Provide a high-level overview of the project.)

#### Tasks to Complete:
- Add Clippy.
- Set up CI (tests, coverage, code quality checks, etc.).
- Spend time on license comparison.

#### Major TODOs:
- Implement pattern functionality (e.g., `--pattern=abc?d`).
- Add custom charset functionality (e.g., `--charset=ěščřžýáíůä`), which requires thorough testing.
- Create a Homebrew release.
- Benchmark memory, CPU, time, and operations per second.
- Explore advanced multithreading techniques:
  1. Remove `par_split()` and `par_iter()`.
  2. Consider scoped threads.
  3. Explore a custom raw threading approach.




Currently, only some arguments are supported,  
which are as follows:  

| argument     | ready?   | info|
|:------------------------:    |:------------------:  | :------------------|
| certificate_path                           |   ✅    |   Path to the PKCS#12 certificate file to crack|
| dictionary_path                         |   ✅   |   Path to dictionary file for dictionary-based attack|
| pattern                          |    𒉭  |   Pattern template for pattern-based attack|
| pattern_symbol                         |    𒉭  |   Symbol used to mark variable positions in pattern|
| maximum_length                         |    𒉭   |    Maximum password length for brute force attack|
| minumum_length                           |  𒉭    |   Minimum password length for brute force attack|
| bruteforce_flag                         |  ✅  |    Enable brute force attack mode|
| char_sets                          |    𒉭    |    Character sets to use in brute force attack|
| specific_chars                          |   𒉭  |   Custom character set for brute force attack|
| delimiter                         |   𒉭    |    Delimiter for dictionary entries|
| threads                         |    𒉭   |    Number of cracking threads [default: number of CPU cores]|

### Basic Usage

(Provide code examples and usage instructions.)

### Advanced Usage

(Provide more complex code examples and instructions.)

## Contributing

1. Fork the repository (provide a link).  
2. Create your feature branch (`git checkout -b my-new-feature`).  
3. Commit your changes (`git commit -am 'Add some feature'`).  
4. Push to the branch (`git push origin my-new-feature`).  
5. Create a new pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
