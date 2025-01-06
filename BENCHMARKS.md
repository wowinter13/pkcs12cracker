# Benchmarks

Benchmarking environment:
- MacBook M1 Pro with 32GB RAM
- Using hyperfine
- All certificates and dictionaries are in `benchmarks` directory

## Compared Tools
- [p12CrackerGo](https://github.com/allyomalley/p12CrackerGo)
- [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12)
- [pkcs12cracker](https://github.com/wowinter13/pkcs12cracker) – this project

## Test Cases

### Certificate #1: Format Support Test
File: `certificate.p12` (password: `test123`)

```bash
# p12CrackerGo: ❌
go run p12Cracker.go passwords.txt certificate.p12 8
> panic: pkcs12: no MAC in data

# crackpkcs12: ❌
crackpkcs12 -d passwords.txt certificate.p12
Dictionary attack - Starting 8 threads
Dictionary attack - Exhausted search
No password found

# pkcs12cracker: ✅
pkcs12cracker -d passwords.txt certificate.p12
Starting password cracking...
Starting dictionary attack with 8 threads
Found correct password: test123
Successfully found password: test123
Total attempts: 98176
```

### Certificate #2: Large File Performance
File: `openwall.pfx` from http://openwall.info/wiki/_media/john/PKCS-12.zip
Dictionary: `four_digits_alphabet.txt` with 456,976 passwords (26^4)

Dictionary attack with 8 threads:
```bash
# p12CrackerGo: ✅
hyperfine "go run p12Cracker.go four_digits_alphabet.txt openwall.pfx 8"
Time (mean ± σ): 21.486s ± 0.127s    [User: 108.294s, System: 9.586s]
Range (min … max): 21.264s … 21.768s    10 runs
# ~21,268 attempts per second

# crackpkcs12: ✅
hyperfine "crackpkcs12 -d four_digits_alphabet.txt openwall.pfx"
Time (mean ± σ): 10.450s ± 0.027s    [User: 69.866s, System: 0.117s]
Range (min … max): 10.410s … 10.484s    10 runs
# ~43,728 attempts per second

# pkcs12cracker: ✅
hyperfine "pkcs12cracker -d four_digits_alphabet.txt openwall.pfx"
Time (mean ± σ): 10.674s ± 0.063s    [User: 69.987s, System: 0.126s]
Range (min … max): 10.599s … 10.792s    10 runs
# ~42,812 attempts per second
```

Bruteforce attack:
```bash
# p12CrackerGo: ❌ (no bruteforce with custom charset support)

# crackpkcs12: ✅
hyperfine "crackpkcs12 -b -c a -m 4 -M 4 openwall.pfx"
Time (mean ± σ): 12.383s ± 0.464s    [User: 67.962s, System: 0.164s]
Range (min … max): 11.747s … 13.231s    10 runs
# ~36,903 attempts per second

# pkcs12cracker: ✅
hyperfine "pkcs12cracker -b -c a -m 4 --max-length 4 openwall.pfx"
Time (mean ± σ): 11.312s ± 0.246s    [User: 68.153s, System: 0.145s]
Range (min … max): 11.095s … 11.932s    10 runs
# ~40,397 attempts per second
```

### Certificate #3: Speed Test
File: `exportado.p12`

```bash
# p12CrackerGo: ❌
go run p12Cracker.go four_digits_alphabet.txt exportado.p12 8
> panic: pkcs12: error reading P12 data: asn1: syntax error: indefinite length found (not DER)

# crackpkcs12: ✅
hyperfine "crackpkcs12 -d four_digits_alphabet.txt exportado.p12"
Time (mean ± σ): 660.0ms ± 4.7ms    [User: 3771.0ms, System: 500.2ms]
Range (min … max): 648.9ms … 665.9ms    10 runs
# ~692,387 attempts per second

# pkcs12cracker: ✅
hyperfine "pkcs12cracker -d four_digits_alphabet.txt exportado.p12"
Time (mean ± σ): 691.7ms ± 11.5ms    [User: 3787.5ms, System: 535.9ms]
Range (min … max): 675.0ms … 711.8ms    10 runs
# ~661,325 attempts per second
```