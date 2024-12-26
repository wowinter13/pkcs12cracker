<div align="center">
<table>
  <tr>
    <td bgcolor="#4B3B39">
      <div align="center">

  <picture>
    <img src="img/mekus.png" alt="Mekus">
  </picture>
        <h1 style="color:white">pkcs12#cracker</h1>
        <p style="color:white">This crate is a simple tool to concurrently attack a password-protected PKCS#12 (PFX/P12) file. Its main goal is to be faster, more efficient, and more reliable than existing tools written in Go and C.</p>
      </div>
    </td>
  </tr>
</table>
</div>

<p align="center">
<a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/built_with-Rust-dca282.svg?logo=rust" /></a>
<a href="http://makeapullrequest.com"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square" /></a>
</p>



[![Build Status](https://travis-ci.com/username/repo.svg?branch=master)](https://travis-ci.com/username/repo)  
![Tests](https://github.com/wowinter13/finance_rb/actions/workflows/tests.yml/badge.svg)  
[![Release](https://img.shields.io/github/v/release/wowinter13/finance_rb.svg?style=flat-square)](https://github.com/wowinter13/finance_rb/releases)  
[![Maintainability](https://api.codeclimate.com/v1/badges/bbca82ad7815794c6718/maintainability)](https://codeclimate.com/github/wowinter13/finance_rb/maintainability)


## Documentation

Detailed documentation is available at [futurelink](https://google.com).


#### High-Level Overview [TODO]

By default, all CPUs of the machine are utilized.

(Provide a high-level overview of the project.)

#### Tasks to Complete:
- Add Clippy.
- Set up CI (tests, coverage, code quality checks, etc.).
- Spend time on license comparison.
- Enums/ S

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
| pattern                          |    ✅   |   Pattern template for pattern-based attack|
| pattern_symbol                         |    ✅   |   Symbol used to mark variable positions in pattern|
| maximum_length                         |    ✅   |    Maximum password length for brute force attack|
| minumum_length                           |  ✅    |   Minimum password length for brute force attack|
| bruteforce_flag                         |  ✅  |    Enable brute force attack mode|
| char_sets                          |    ✅   |    Character sets to use in brute force attack|
| specific_chars                          |   ✅  |   Custom character set for brute force attack|
| delimiter                         |  ✅    |    Delimiter for dictionary entries|
| threads                         |    ✅   |    Number of cracking threads [default: number of CPU cores]|

### Basic Usage

(Provide code examples and usage instructions.)

### Advanced Usage

(Provide more complex code examples and instructions.)

## License

This project is licensed under the MIT License. See the LICENSE file for details.
