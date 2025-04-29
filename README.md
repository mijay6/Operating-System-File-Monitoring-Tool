# Folder Integrity and Malicious File Scanner

[![Assembly](https://img.shields.io/badge/language-C-green.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![University: UPT](https://img.shields.io/badge/University-Politehnica%20Timisoara-red.svg)](https://www.upt.ro/)
[![Status: Academic](https://img.shields.io/badge/Status-Academic%20Project-success.svg)](https://github.com/mijay6/Operating-System-File-Monitoring-Tool)
[![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen.svg) ](https://github.com/mijay6/Operating-System-File-Monitoring-Tool/releases) 

## Description
This utility scans one or more directories (and their subdirectories), computes and stores SHA-256 checksums and metadata for every file, then compares snapshots across runs to detect:

- **Additions**: new files or folders  
- **Deletions**: removed files or folders  
- **Modifications**: changes in content (checksum), name, type or permissions  

Additionally, an optional mode will analyze each file for malicious characteristics (based on size, content, keywords, or non-ASCII characters) and move any flagged files to an isolation folder.

## Features

- Recursively traverse directories and record metadata in a snapshot file (`<dirname>_snapshot.dat`).
- Compare current and previous snapshots to list added, removed, or modified entries.
- Compute SHA-256 checksum using OpenSSL.
- `-o` option: specify an output directory for generated snapshots.
- `-s` option: specify an isolation directory for malicious files.
- Concurrent processing: each directory is scanned in parallel to improve performance.
- Malicious file detection via a helper Bash script (`verify_for_malicious.sh`).

## Prerequisites & Build

- **GCC** (with C99 support)  
- **OpenSSL** development libraries (for SHA-256)

Compile with:

```bash
gcc -Wall -o prog prog.c -lssl -lcrypto
```

## Usage

```bash
# Basic snapshot and comparison
./prog folder1 folder2 ...

# Save snapshots to a dedicated output directory
./prog -o snapshots_out folder1 folder2 ...

# Additionally isolate malicious files to a quarantine directory
./prog -o snapshots_out -s quarantine_dir folder1 folder2 ...
```

## Behavior

First run: generates `<dirname>_snapshot.dat` and reports  
> "First run: no previous snapshot found."

Subsequent runs: compares to previous snapshot and prints:

- **Added**: new files or folders  
- **Removed**: deleted files or folders  
- **Modified**: name change, content change, permission change, size change, or type change  

**With `-s`**: files deemed malicious are moved to the specified quarantine directory.

## Malicious File Detection

The script `verify_for_malicious.sh` applies the following heuristics:

1. Flags files exceeding **100 lines**, **5 000 words**, or **10 000 characters** as dangerous.  
2. Flags files with fewer than **3 lines** but more than **1 000 words** or **2 000 characters** as suspicious, then:  
   - Searches for keywords: `corrupted`, `dangerous`, `risk`, `attack`, `malware`, `malicious`.  
   - Detects non-ASCII characters.  
3. Any flagged file has its permissions revoked and is either printed (`SAFE` or file path) or moved to quarantine.

## Test Folders

This repository includes three sample test folders:

- `test_folder1/`  
- `test_folder2/`  
- `test_folder3/`  

Each contains various files and nested directories (including deliberately malicious files) to validate snapshot integrity and malicious detection. 

## Author
Dobra Mihai

Politehnica University of Timișoara  
Faculty of Automation and Computer Science  
Operating systems
Academic Year 2023-2024

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.