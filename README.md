<div align="center">
<table>
  <tr>
    <td bgcolor="#4B3B39">
      <div align="center">
        <picture>
          <img src="img/mekus.png" alt="Mekus">
        </picture>
        <h1 style="color:white">pkcs12cracker</h1>
        <p style="color:white"> High-performance, multi-threaded PKCS#12 password cracker written in Rust. Supports dictionary, pattern-based, and brute force attacks with focus on performance and reliability.<s>Its main goal is to be faster, more efficient, and more reliable than existing tools written in Go and C.</s></p> 
      </div>
    </td>
  </tr>
</table>
</div>

<p align="center">
<a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/built_with-Rust-dca282.svg?logo=rust" /></a>
<a href="http://makeapullrequest.com"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square" /></a>
<a href="https://github.com/wowinter13/pkcs12cracker/releases"><img src="https://img.shields.io/github/v/release/wowinter13/pkcs12cracker.svg?style=flat-square" /></a>
<a href="https://github.com/wowinter13/pkcs12cracker/actions"><img src="https://github.com/wowinter13/pkcs12cracker/actions/workflows/tests.yml/badge.svg" /></a>
</p>

### Documentation

API reference and usage examples are available at [docs.rs](https://docs.rs/crate/pkcs12cracker/latest).

### Installation

```bash
cargo install pkcs12cracker

# Or build from source
git clone https://github.com/wowinter13/pkcs12cracker
cd pkcs12cracker
cargo build --release
```

### Know-How

- Memory-mapped file handling for efficient dictionary processing
- Parallel processing with configurable thread count
- Cache-friendly chunk-based password cracking
- Optimized string handling and memory allocation
- Multiple attack strategies support

#### Tasks to Complete
- CI (+tests)
- Benchmarks (memory, CPU, time, and operations per second).

#### Major TODOs:
- OS related performance optimizations.
- Explore advanced multithreading techniques (try scoped threads or another raw threading approach).

### Basic Usage

#### Dictionary Attack
Uses a wordlist file to crack passwords:
```bash
# Basic usage with newline-separated dictionary
pkcs12cracker -d wordlist.txt cert.p12
```

#### Pattern-Based Attack
Cracks passwords matching a specific pattern:
```bash
# Custom symbol for variable positions
pkcs12cracker -p "Pass##rd" -s "#" cert.p12
```

#### Brute Force Attack

```bash
# Custom character sets
pkcs12cracker -b -c aAn cert.p12  # alphanumeric
```

### Advanced Usage

#### Character Sets
The `-c` flag supports combining multiple character sets:
- `a` - lowercase letters (a-z)
- `A` - uppercase letters (A-Z)
- `n` - digits (0-9)
- `s` - special characters (!@#$%^&*...)
- `x` - all of the above

Examples:
```bash
# Uppercase + numbers
pkcs12cracker -b -c An cert.p12

# All characters except special
pkcs12cracker -b -c aAn cert.p12

# Everything
pkcs12cracker -b -c x cert.p12
```

#### Custom Character Sets
For specific requirements, use `--custom-chars`:
```bash
# Combine with standard sets
pkcs12cracker -b -c an --custom-chars="!@#" cert.p12
```


### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.