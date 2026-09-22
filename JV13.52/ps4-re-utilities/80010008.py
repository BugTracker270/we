#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File name: 80010008.py
Author: Al Azif
Created: 2021-07-25
Version: 1.0.0
Description:
    Automatically extracts SELF keys from a decrypted AuthMgr binary
    (80010008). It currently locates key banks by using the checksum of the
    first 0x10 bytes in each bank as an offset. Although this method is not
    ideal, it reliably works for firmware versions 1.00 through 13.50.
License: GPLv3
Contact: https://github.com/Al-Azif
Dependencies:
    argparse, hashlib, logging, mmap, os, pathlib, re, struct, sys, typing
Changelog:
    1.0.0
        - Initial Release
"""

import argparse
import hashlib
import logging
import mmap
import os
import pathlib
import re
import struct
import sys
from typing import Dict, Optional, Union

# Python Version Check
if sys.version_info < (3, 6):
    print("ERROR: This script requires Python 3.6 or later.", file=sys.stderr)
    sys.exit(1)

# Add lib directory to path
sys.path.append(str(pathlib.Path(__file__).parent.resolve()))
from lib import utils

# Script version
__version__ = "1.0.0"

# Constants
# The size of the sample that's taken to check against known checksums
CHECKSUM_SAMPLE_SIZE: int = 0x10

# Define target hashes for the first CHECKSUM_SAMPLE_SIZE bytes of each key bank
# `hash` is a SHA256 checksum of the binary data, not the hexadecimal string
KEY_BANK_TARGETS: Dict[str, Dict[str, Union[str, int]]] = {
    "0x00": {"hash": "7cf7a6ecbd0eae8ee0ff4a703ee8f21acfc733344e45ba6ee293ff443edb336e", "offset": 0},
    "0x01": {"hash": "693d2637a3c69993388a3b869ada0b0f175bd9cb04d5b1b7d4408484a8865e17", "offset": 0},
    "0x02": {"hash": "29ae7d829d778dd37b435e679bc367034674e1924fc55c811d9a64a0577d7452", "offset": 0},
}
# The number of key bank targets provided
KEY_BANK_TARGETS_LEN: int = len(KEY_BANK_TARGETS)
# The struct format for unpacking keys. Appears consistent across known firmware versions.
# Struct uses '>' for big-endian format. 's' denotes bytes (for key and IV).
KEY_BANK_STRUCT_FORMAT: str = ">16s16s"
# The regex of the key bank termination pattern.
KEY_BANK_TERMINATION_PATTERN: bytes = rb"....\x00\x01\x00\x00....\x08\x00\x00\x00....\x00\x01\x00\x00"
# The length of the key bank termination pattern.
KEY_BANK_TERMINATION_PATTERN_LEN: int = len(KEY_BANK_TERMINATION_PATTERN)

# Define target hashes for the first CHECKSUM_SAMPLE_SIZE bytes of each signature bank
# `hash` is a SHA256 checksum of the binary data, not the hexadecimal string
SIGNATURE_BANK_TARGETS: Dict[str, Dict[str, Union[str, int]]] = {
    "0x00": {"hash": "d96c2d1981af473fd51d0b0b30169b2e75205540414e6a147ac3e25f8921e97a", "offset": 0},
    "0x01": {"hash": "c05badfff635bfe8f900f1cc18d8029cf5894062227bb8c89698c6e047b5cc3d", "offset": 0},  # This should be *directly* after 0x00, so it shouldn't technically be necessary
    "0x02": {"hash": "cfdd6bd305adef79ebbebb82dd252a93c4d3f2df5d09210d7de3f6fcf60927e5", "offset": 0},  # This should be *directly* after 0x01, so it shouldn't technically be necessary
}
# The number of key bank targets provided
SIGNATURE_BANK_TARGETS_LEN: int = len(SIGNATURE_BANK_TARGETS)
# The struct format for unpacking signatures. Appears consistent across known firmware versions.
# Struct uses '>' for big-endian format. 's' denotes bytes (for keys/IVs/RSA components), and 'x' denotes padding bytes to skip.
SIGNATURE_BANK_STRUCT_FORMAT: str = ">256s5x3s256s"

# Type alias for the dictionary structure returned
# Example structure:
# {
#     "SELF": {
#         "X86_64": { "0x00": { "AES_KEY": "...", ... } },
#         "X86_64": { "0x01": { "AES_KEY": "...", ... } },
#         "X86_64": { "0x02": { "AES_KEY": "...", ... } }
#     }
# }
KeysDict = Dict[str, Dict[str, Dict[str, Dict[str, str]]]]

# Asserts
assert KEY_BANK_TARGETS_LEN == SIGNATURE_BANK_TARGETS_LEN, "Must have same amount of key and signature targets"
assert KEY_BANK_TARGETS.keys() == SIGNATURE_BANK_TARGETS.keys(), "Must contain the same key names"


def _fill_bank_offsets(data: Union[bytes, mmap.mmap], type: str, targets: Dict[str, Dict[str, Union[str, int]]], targets_len: int) -> bool:
    """
    Locates and fills in the offsets for key or signature banks within the
    data.

    Searches through the binary data using SHA256 checksums of fixed-size
    samples to identify the starting positions of each bank. Updates the
    'offset' field in the targets dictionary with the found positions.

    Args:
        data: The binary data (bytes or mmap object) to search within.
        type: The type of bank being searched (e.g., "Key" or "Signature"),
              used for logging purposes.
        targets: Dictionary mapping bank IDs to their hash and offset values.
                 The 'offset' field will be updated with found positions.
        targets_len: The expected number of banks to find.

    Returns:
        True if all banks were successfully found, False otherwise.
    """

    logging.info(f"--- Searching for {type} Bank Offsets ---")
    found_count = 0
    # We cheat here, we use a known checksum and search the file for bytes when hashed match the checksum
    for x in range(len(data) - CHECKSUM_SAMPLE_SIZE + 1):
        current_hash = hashlib.sha256(data[x : x + CHECKSUM_SAMPLE_SIZE]).hexdigest()

        for bank_id, target in targets.items():
            # Check if this bank is not found yet and if the hash matches
            if target["offset"] == 0 and current_hash == target["hash"]:
                logging.debug(f"{type} Bank {bank_id} Offset:           0x{x:02X}")
                target["offset"] = x
                found_count += 1

        # Exit early if all banks are found
        if found_count == targets_len:
            logging.info(f"Found all {type.lower()} banks.")
            break
    else:  # This else block executes if the loop completes without a 'break'
        logging.error(f"Unable to find all {type.lower()} banks:")
        for bank_id, target in targets.items():
            if target["offset"] == 0:
                logging.error(f"  - Bank {bank_id} (Hash: {target['hash']}) not found.")
        return False  # Stop processing if not all banks were found

    logging.info(f"All {type.lower()} bank offsets found successfully.")
    return True


def _extract_bank_keys(data: Union[bytes, mmap.mmap], offset: int, bank_id_str: str) -> Optional[KeysDict]:
    """
    Extracts AES keys and IVs from a key bank starting at the specified offset.

    Iterates through sequential key/IV pairs in the bank until a termination
    pattern is detected or the end of data is reached. Each pair consists of
    a 16-byte AES key followed by a 16-byte IV.

    Args:
        data: The binary data (bytes or mmap object) containing the key bank.
        offset: The starting offset of the key bank within the data.
        bank_id_str: The bank identifier (e.g., "0x00") used for structuring
                     the output dictionary and logging.

    Returns:
        A dictionary containing the extracted AES keys and IVs organized by
        bank ID, or None if an error occurs during extraction.
    """

    # Termination pattern appears where the *next* key would start
    termination_pattern = re.compile(KEY_BANK_TERMINATION_PATTERN)

    # Initialize the nested dictionary structure
    output: KeysDict = {"SELF": {"X86_64": {f"{bank_id_str}": {"AES_KEY": {}, "IV": {}}}}}

    key_index = 0
    while True:
        key_struct_size = struct.calcsize(KEY_BANK_STRUCT_FORMAT)
        key_offset = offset + (key_index * key_struct_size)
        next_key_offset = key_offset + key_struct_size

        if key_offset + key_struct_size > len(data):
            logging.error(f"Reached end of data while extracting key/IV pair {key_index} for bank {bank_id_str}.")
            break
        unpacked = struct.unpack_from(KEY_BANK_STRUCT_FORMAT, data, key_offset)

        # Assign components to their correct location
        output["SELF"]["X86_64"][f"{bank_id_str}"]["AES_KEY"][str(key_index)] = unpacked[0].hex().upper()
        output["SELF"]["X86_64"][f"{bank_id_str}"]["IV"][str(key_index)] = unpacked[1].hex().upper()

        # Check bounds before looking for termination pattern
        if next_key_offset + KEY_BANK_TERMINATION_PATTERN_LEN > len(data):
            logging.info(f"Reached end of data after extracting key/IV pair {key_index} for bank {bank_id_str}. Assuming end of bank.")
            break

        # Check for termination pattern at the start of the *next* potential key slot
        if termination_pattern.match(data[next_key_offset : next_key_offset + KEY_BANK_TERMINATION_PATTERN_LEN]):
            logging.info(f"Termination pattern found after key/IV pair {key_index} for bank {bank_id_str}.")
            break

        key_index += 1

    logging.info(f"Successfully extracted {key_index + 1} key/IV pairs from bank {bank_id_str}.")
    return output


def _extract_bank_signatures(data: Union[bytes, mmap.mmap], offset: int, bank_id_str: str) -> Optional[KeysDict]:
    """
    Extracts RSA signature components from a signature bank at the specified
    offset.

    Unpacks the RSA modulus, public exponent, and R2 value from a fixed-size
    signature structure. Performs bounds checking and validates the struct
    format before extraction.

    Args:
        data: The binary data (bytes or mmap object) containing the signature
              bank.
        offset: The starting offset of the signature bank within the data.
        bank_id_str: The bank identifier (e.g., "0x00") used for structuring
                     the output dictionary and logging.

    Returns:
        A dictionary containing the extracted RSA signature components
        organized by bank ID, or None if an error occurs during extraction.
    """

    # Calculate the expected size of the key structure based on the format string.
    logging.debug(f"Attempting to calculate size for struct format: '{SIGNATURE_BANK_STRUCT_FORMAT}'")
    try:
        struct_size = struct.calcsize(SIGNATURE_BANK_STRUCT_FORMAT)
    except struct.error as e:
        # This indicates an issue with the format string defined in STRUCT_FORMAT.
        logging.error(f"Invalid struct format string generated: '{SIGNATURE_BANK_STRUCT_FORMAT}'")
        logging.error(f"Internal Error: {e}")
        return None
    logging.debug(f"Calculated struct size for format '{SIGNATURE_BANK_STRUCT_FORMAT}': {struct_size:,} bytes.")

    if offset + struct_size > len(data):
        logging.error(f"Calculated key struct size ({struct_size:,} bytes) starting at offset 0x{offset:X} exceeds file size ({len(data):,} bytes).")
        return None

    # Attempt to unpack the key data from the calculated offset using the selected format.
    logging.debug(f"Attempting unpack at offset 0x{offset:X} with size {struct_size:,} bytes.")
    try:
        unpacked = struct.unpack_from(SIGNATURE_BANK_STRUCT_FORMAT, data, offset)
    except struct.error as e:
        # This usually means the data at the offset doesn't match the expected structure.
        logging.error(f"Failed to unpack data structure at offset 0x{offset:X}.")
        logging.error(f"Struct Format Used: '{SIGNATURE_BANK_STRUCT_FORMAT}' (Expected Size: {struct_size:,} bytes)")
        logging.error(f"Original Error: {e}")
        return None
    logging.debug(f"Successfully unpacked {len(unpacked)} items from offset 0x{offset:X}.")

    # Initialize the nested dictionary structure
    output: KeysDict = {"SELF": {"X86_64": {f"{bank_id_str}": {"RSA_MODULUS": "", "RSA_PUB_EXPONENT": "", "RSA_R2": ""}}}}

    # Assign components to their correct location
    output["SELF"]["X86_64"][f"{bank_id_str}"]["RSA_MODULUS"] = unpacked[0].hex().upper()
    output["SELF"]["X86_64"][f"{bank_id_str}"]["RSA_PUB_EXPONENT"] = unpacked[1].hex().upper()
    output["SELF"]["X86_64"][f"{bank_id_str}"]["RSA_R2"] = unpacked[2].hex().upper()

    logging.info(f"Successfully extracted signature components from bank {bank_id_str}.")
    return output


def _process_data(data: Union[bytes, mmap.mmap]) -> Optional[KeysDict]:
    """
    Processes the AuthMgr data to extract keys.

    Orchestrates the extraction process from the provided data:
    1. Finds key and signature bank offsets using checksums.
    2. Extracts keys from each bank.
    3. Extracts signatures from each bank.

    Args:
        data: The binary data (bytes or mmap object) of the AuthMgr.

    Returns:
        A dictionary containing the extracted keys if successful, None if an
        error occurred during processing.
    """

    logging.debug("Starting data processing...")

    # Iterate through data to find offsets based on first key hash
    # Stop iterating 16 bytes before the end to avoid hashing partial data
    if not _fill_bank_offsets(data, "Key", KEY_BANK_TARGETS, KEY_BANK_TARGETS_LEN) or not _fill_bank_offsets(data, "Signature", SIGNATURE_BANK_TARGETS, SIGNATURE_BANK_TARGETS_LEN):
        return None

    # Extract keys for each found bank
    output: KeysDict = {}
    for bank_id, target in KEY_BANK_TARGETS.items():
        # The offset check isn't strictly needed here due to the early return above, but it doesn't hurt.
        if target["offset"] != 0:
            key_dict = _extract_bank_keys(data, target["offset"], bank_id)
            if not key_dict:
                return None  # Errors are logged by `_extract_bank_keys`
            utils.merge_dicts(output, key_dict)
    for bank_id, target in SIGNATURE_BANK_TARGETS.items():
        # The offset check isn't strictly needed here due to the early return above, but it doesn't hurt.
        if target["offset"] != 0:
            signature_dict = _extract_bank_signatures(data, target["offset"], bank_id)
            if not signature_dict:
                return None  # Errors are logged by `_extract_bank_signatures`
            utils.merge_dicts(output, signature_dict)

    logging.info("Successfully extracted all keys from data.")
    return output


def _process_input_file(input_path: pathlib.Path) -> Optional[KeysDict]:
    """
    Handles opening, memory-mapping, and processing the input file.

    Args:
        input_path: The pathlib.Path object representing the input file.

    Returns:
        A dictionary containing the extracted keys if successful, None
        otherwise.
    """

    try:
        logging.info(f"Processing file: '{input_path}'...")
        # Open the file in binary read mode.
        with open(input_path, "rb") as f:
            logging.debug(f"Successfully opened '{input_path}' for reading.")
            # Use memory mapping for efficient read access.
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                logging.debug(f"Memory-mapped file, size: {len(data):,} bytes.")
                return _process_data(data)
    except ValueError as e:
        # mmap can raise ValueError for empty files, though size check should prevent this.
        logging.error(f"An unexpected error occurred reading file: ValueError({e})")
    except (FileNotFoundError, PermissionError) as e:
        logging.error(f"Unable to access specified file '{input_path}': {e}")
    except OSError as e:
        logging.error(f"An OS error occurred while processing '{input_path}': {e}")
    except Exception:
        # Catch any other unexpected errors
        logging.exception(f"An unexpected error occurred processing '{input_path}':")

    return None


def _format_keys_string(key_dict: KeysDict) -> str:
    """
    Formats the extracted keys into a string suitable for printing.

    Uses the centralized `KEY_DEFINITIONS` to associate indices in the unpacked
    tuple with descriptive names for the keys. Prints each key's description
    and its hexadecimal value.

    Args:
        key_array: A tuple containing the unpacked key data, as returned by
                   `struct.unpack_from` function. The order and content depend
                   on the struct format used during unpacking.

    Returns:
        A formatted multi-line string containing the key information, or an
        empty string if the input is invalid (though primarily handles
        formatting).
    """

    if not isinstance(key_dict, dict) or not key_dict:
        return ""

    lines = []
    max_desc_width = 27  # Matches prior examples/comments

    def sort_hex_keys(iterable):
        try:
            return sorted(iterable, key=lambda k: int(k, 16))
        except Exception:
            return sorted(iterable)

    def sort_indices(iterable):
        try:
            return sorted(iterable, key=lambda k: int(k))
        except Exception:
            return sorted(iterable)

    for type_name in sorted(key_dict.keys()):
        type_block = key_dict.get(type_name, {})
        if not isinstance(type_block, dict):
            continue

        header = f"--- {type_name} Keys "
        lines.append(f"{header}{'-' * max(0, 70 - len(header))}".rstrip())

        include_arch = len(type_block) > 1
        for arch_name in sorted(type_block.keys()):
            arch_block = type_block.get(arch_name, {})
            if not isinstance(arch_block, dict):
                continue

            for bank_id in sort_hex_keys(arch_block.keys()):
                bank_block = arch_block.get(bank_id, {})
                if not isinstance(bank_block, dict):
                    continue

                # Prefix matches prior printed examples (omit arch unless multiple present)
                prefix = f"{type_name} {bank_id} "
                if include_arch:
                    prefix = f"{type_name} {arch_name} {bank_id} "

                # Symmetric keys
                aes_dict = bank_block.get("AES_KEY")
                if isinstance(aes_dict, dict) and aes_dict:
                    for idx in sort_indices(aes_dict.keys()):
                        desc = f"{prefix}AES_KEY[{idx}]:"
                        lines.append(f"{desc:<{max_desc_width}} {aes_dict[idx]}")

                iv_dict = bank_block.get("IV")
                if isinstance(iv_dict, dict) and iv_dict:
                    for idx in sort_indices(iv_dict.keys()):
                        desc = f"{prefix}IV[{idx}]:"
                        lines.append(f"{desc:<{max_desc_width}} {iv_dict[idx]}")

                # Signatures
                for field in ("RSA_MODULUS", "RSA_PUB_EXPONENT", "RSA_R2"):
                    val = bank_block.get(field)
                    if isinstance(val, str) and val:
                        desc = f"{prefix}{field}:"
                        lines.append(f"{desc:<{max_desc_width}} {val}")

        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(lines)


def main() -> None:
    """
    Main execution entry point for the script.

    Handles the overall workflow:
    1. Parses command-line arguments (input file, JSON output options,
       verbosity).
    2. Configures logging based on verbosity arguments.
    3. Validates the input file path and basic file properties.
    4. Calls the core processing function to extract keys from the file.
    5. If requested, handles writing the extracted keys to a JSON file,
       including optional merging with existing data.
    6. Exits with status code 0 on success, or 1 on failure, logging errors to
       stderr

    Returns:
        None
    """

    # --- Setup argument Parser ---
    parser = argparse.ArgumentParser(description="SELF Key Extractor by Al Azif\nExtracts SELF keys from a decrypted AuthMgr binary (`80010008`).", formatter_class=argparse.RawTextHelpFormatter)
    # Verbosity group
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-q", "--quiet", action="store_true", help="Suppress informational messages, show only warnings and errors.")
    verbosity_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output.")
    # Version argument
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # Positional and optional arguments
    parser.add_argument("file", type=pathlib.Path, help="Specify the location of the decrypted AuthMgr binary")
    parser.add_argument("--output-json", type=pathlib.Path, help="Path to the output file.")
    parser.add_argument("--merge-json", action="store_true", help="If '--output-json' exists, merge new keys into it instead of overwriting.")
    args = parser.parse_args()

    # --- Configure logging ---
    log_level = logging.INFO
    if args.quiet:
        log_level = logging.WARNING
    elif args.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s", stream=sys.stderr)

    logging.debug(f"Parsed arguments: {args}")

    # --- Input File Validation ---
    input_path = pathlib.Path(args.file)
    if not utils.validate_input_file(input_path, CHECKSUM_SAMPLE_SIZE):
        # Errors are logged by `_validate_input_file`
        sys.exit(1)

    # --- Output Directory Validation ---
    output_path = ""
    if args.output_json:
        output_path = pathlib.Path(args.output_json)
        if not utils.validate_output_directory(output_path.parent):
            # Errors are logged by `_validate_output_directory`
            sys.exit(1)

    try:
        # --- File Processing ---
        processed_data = _process_input_file(input_path)
        if processed_data is None:
            # Errors are logged by `_process_input_file`
            sys.exit(1)
        logging.info("Key extraction process completed successfully.")

        # --- Format and Print Keys ---
        logging.info("Formatted Key Output:")
        logging.info(_format_keys_string(processed_data))

        # --- JSON Output Handling ---
        if output_path:
            # Handle writing/merging the JSON file
            if not utils.handle_json_output(output_path, processed_data, args.merge_json):
                # Errors are logged by `_handle_json_output`
                sys.exit(1)
    except Exception as e:
        # Catch any other unexpected errors
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
