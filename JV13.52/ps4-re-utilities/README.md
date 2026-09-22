# PlayStation®4 RE Utilities

A collection of dependency-free Python utilities designed to assist with PlayStation®4 reverse engineering tasks.

## Goals & Philosophy

The primary goal of these utilities is to simplify common RE tasks related to the PlayStation®4, such as:

*   **Simplify Common Tasks:** Provide tools and proofs of concept to extract key information (Secure Kernel/Module/SELF keys) and handle specific file formats (Splitting kernel components or extracting embedded SELFs).
*   **Reduce Tooling Complexity:** Lower the barrier to entry by minimizing the need for complex reverse engineering suites like IDA, Ghidra, or Binary Ninja (With associated necessary custom architectures/loaders/plugins) for these specific tasks.
*   Ensure scripts are **dependency-free** (using only the Python standard library).

These scripts also serve as a time capsule, preserving tooling and methodologies for future research, ensuring that knowledge isn't lost as consoles age and potentially see renewed interest.

**Disclaimer:** These utilities are intended as guides, helpers, or proofs of concept. They are not guaranteed to be turnkey solutions or finalized products and may require adaptation for specific use cases or future firmware versions. They are provided as-is, without warranty. I wrote this a long time ago and, when I went to give them a once over before release, I don't remember why I did some things the way I did... but they all still work so it's whatever.

## Requirements

*   [Python 3.6+](https://www.python.org/downloads/)

## Utilities

### Secure Kernel/BIOS

**`80000001.py`**

Automatically extracts Secure Kernel and BIOS keys from a decrypted Secure Loader binary (`80000001`). It uses the offset of a specific string as a reference point to locate the keys. While this method has changed in the past, the current script has remained effective from firmware 1.00 through 13.50 and unchanged since firmware 4.50.

### Secure Module

**`80010001.py`**

Automatically extracts Secure Module keys from a decrypted Secure Kernel binary (`80010001`). It uses the offset of a specific string as a reference point to locate the keys. This method has remained valid from firmware versions 1.00 through 13.50, though it may change in future updates.

### SELF

**`80010008.py`**

Automatically extracts SELF keys from a decrypted AuthMgr binary (`80010008`). It currently locates key banks by using the checksum of the first 0x10 bytes in each bank as an offset. Although this method is not ideal, it reliably works for firmware versions 1.00 through 13.50.

### Kernel

**`self-extractor.py`**

Automatically extracts embedded SELF files—such as `mini-syscore.elf`, `safemode.elf`, and `SceSysAvControl.elf`—from a decrypted or dumped Kernel ELF (`80010002`). The script assumes there are three embedded SELF files in the specified order, though it will extract all of them if more are present. Output files should be manually verified to ensure correct naming.

**`split_kernel.py`**

Separates the AMD μBIOS and FreeBSD Kernel from a decrypted Kernel ELF (`80010002`) to mimic the structure of a typical kernel dump. This ensures compatibility with debuggers and analysis scripts. While the complete AMD μBIOS ELF includes the FreeBSD Kernel ELF appended to it (as indicated by the sizes and offsets in the AMD μBIOS ELF header), the FreeBSD Kernel ELF itself is a valid standalone file.

## Important Notes

*   **Firmware Compatibility:** Scripts have been tested and are functional up to firmware **13.50**, the current latest FW as of publishing. Future firmware updates may require script modifications.
*   **Input File Requirements:** The scripts require *decrypted* input files. You will need separate means to obtain these decrypted files.

## License

Let's keep the scene open source and free. This project is licensed under the [GPLv3 License](LICENSE) - see the LICENSE file for details.
