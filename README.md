# 🦉 OHashHunt

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Password%20/%20Auth-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OHashHunt** — Hash identifier + fast wordlist cracker (MD4/5, SHA-1/224/256/384/512, NTLM, salted) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OHashHunt — Hash identifier + fast wordlist cracker (MD4/5, SHA-1/224/256/384/512, NTLM, salted). Hash Identifier & Wordlist Cracker Identifies hash types by structure/length and recovers plaintext from a wordlist for the digests it can compute: MD4, MD5, SHA-1, SHA-224/256/384/512 and NTLM (MD4 of UTF-16LE), plus salted md5/sha1/sha256 in hash:salt form. The dictionary is indexed once per algorithm, so a whole hash file is cracked in a single pass over the wordlist.

---

## ✨ Features

- Identify hash algorithms from digest shape and markers
- Fast wordlist cracking for MD4/5, SHA family, NTLM and salted forms
- Compute hashes and process hash files in batch
- Salt-mode controls for common encoding layouts
- JSON output for tooling integration
- Self-test and demo modes for verification

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OHashHunt OHashHunt.go
./OHashHunt --help
./OHashHunt --identify --hash 5d41402abc4b2a76b9719d911017c592
./OHashHunt --hashfile hashes.txt --wordlist rockyou.txt
./OHashHunt --compute --algo sha256 --hash secret
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled.s.Haddad
