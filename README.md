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
<a href="https://github.com/wowinter13/pkcs12cracker/actions"><img src="https://github.com/wowinter13/pkcs12cracker/actions/workflows/rust.yml/badge.svg" /></a>
</p>

### Documentation

API reference and usage examples are available at [docs.rs](https://docs.rs/crate/pkcs12cracker/latest).

### Installation

```bash
cargo install pkcs12cracker

# Brew tap (macOS)
brew tap wowinter13/pkcs12cracker
brew install pkcs12cracker

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

#### Discussable:
- OS related performance optimizations.
- Explore advanced multithreading techniques (try scoped threads or another raw threading approach).

### Basic Usage

#### Help
```bash
Fast, multi-threaded PKCS#12 password cracker

Usage: pkcs12cracker [OPTIONS] <FILE>...

Arguments:
  <FILE>...  Path to the PKCS#12 (.p12/.pfx) file to crack

Options:
  -d, --dictionary <FILE>      Use dictionary-based attack with the specified wordlist file
  -p, --pattern <PATTERN>      Use pattern-based attack (e.g., 'Pass@@rd' where '@' marks variable positions)
  -s, --pattern-symbol <CHAR>  Symbol to mark variable positions in pattern [default: @] [default: @]
  -m, --min-length <NUM>       Minimum password length for brute force attack [default: 1] [default: 1]
      --max-length <NUM>       Maximum password length for brute force attack [default: 6] [default: 6]
  -b, --brute-force            Enable brute force attack mode
  -c, --charset <SETS>         Character sets to use in brute force attack
      --custom-chars <CHARS>   Custom character set for brute force attack
      --delimiter <CHAR>       Dictionary file entry delimiter [default: newline] [default: "\n"]
  -t, --threads <NUM>          Number of cracking threads [default: number of CPU cores] [default: 1]
  -h, --help                   Print help (see more with '--help')
  -V, --version                Print version
```

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

### Benchmarks

See [BENCHMARKS.md](BENCHMARKS.md) for more information.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
