#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File name: lib/utils.py
Author: Al Azif
Created: 2021-07-25
Version: 1.0.0
Description:
    Shared functions between the various scripts found in the parent directory.
License: GPLv3
Contact: https://github.com/Al-Azif
Dependencies:
    json, logging, mmap, pathlib, re, sys, typing
Changelog:
    1.0.0
        - Initial Release
"""

import json
import logging
import mmap
import pathlib
import re
import sys
from typing import Dict, Optional, Union

# Python Version Check
if sys.version_info < (3, 6):
    print("ERROR: This script requires Python 3.6 or later.", file=sys.stderr)
    sys.exit(1)

# Constants
# String used to locate the firmware version within the binary data.
FIRMWARE_SEARCH_STRING: bytes = b"release_branches/release_"
# The length of the firmware search string.
FIRMWARE_SEARCH_LEN: int = len(FIRMWARE_SEARCH_STRING)
# The expected length of the firmware version string (e.g., "05.050").
FIRMWARE_VERSION_STRING_LENGTH: int = 6

# (S)ELF file magic bytes
ELF_MAGIC: bytes = b"\x7f\x45\x4c\x46"
SELF_MAGIC: bytes = b"\x4f\x15\x3d\x1d"


def sort_dict_naturally(data: Dict) -> None:
    """
    Recursively sorts dictionary keys using natural (numeric-aware) sorting.

    This function modifies the dictionary **in place**, sorting all keys at
    every nested level. Numeric portions in strings are sorted numerically
    rather than lexicographically (e.g., "2" before "11").

    Args:
        data: The dictionary to sort (modified in place).

    Returns:
        None
    """

    # First, recursively sort any nested dictionaries
    for value in data.values():
        if isinstance(value, dict):
            sort_dict_naturally(value)

    # Then sort the keys at this level using natural sorting
    sorted_items = sorted(data.items(), key=lambda x: [int(text) if text.isdigit() else text.lower() for text in re.split(r"(\d+)", x[0])])
    data.clear()
    data.update(sorted_items)


def deduplicate_firmware_keys(data: Dict) -> None:
    """
    Removes duplicate firmware entries with identical keys, keeping only the
    lowest version number.

    This function examines dictionaries at the firmware version level (e.g.,
    "1.05_SECURE_KERNEL", "1.06_SECURE_KERNEL") and compares their key values.
    If multiple firmware versions have identical keys, only the entry with the
    lowest version number is retained.

    Args:
        data: The dictionary to deduplicate (modified in place).

    Returns:
        None
    """

    # Check if this dictionary level contains firmware version keys
    # (e.g., "1.05_SECURE_KERNEL", "5.05_BIOS")
    firmware_entries = {}
    for key, value in list(data.items()):
        # Check if this looks like a firmware version key (contains underscore and starts with a number)
        if isinstance(value, dict) and "_" in key:
            parts = key.split("_", 1)
            try:
                # Try to parse the version number
                version = float(parts[0])
                suffix = parts[1] if len(parts) > 1 else ""

                # Group entries by their suffix (SECURE_KERNEL, BIOS, etc.)
                if suffix not in firmware_entries:
                    firmware_entries[suffix] = []
                firmware_entries[suffix].append((version, key, value))
            except ValueError:
                # Not a firmware version key, skip
                continue

    # For each suffix group, find and remove duplicates
    for suffix, entries in firmware_entries.items():
        if len(entries) <= 1:
            continue

        # Sort by version number
        entries.sort(key=lambda x: x[0])

        # Build a map of key values to the lowest version that has them
        keys_to_version = {}
        versions_to_remove = set()

        for version, key_name, key_data in entries:
            # Create a hashable representation of the key data
            key_signature = frozenset(key_data.items())

            if key_signature in keys_to_version:
                # We've seen these exact keys before at a lower version
                lowest_version = keys_to_version[key_signature]
                logging.info(f"Duplicate keys found: '{key_name}' has identical keys to version {lowest_version:.2f}. Removing {key_name}.")
                versions_to_remove.add(key_name)
            else:
                # First time seeing these keys, record this version
                keys_to_version[key_signature] = version

        # Remove the duplicate entries
        for key_name in versions_to_remove:
            del data[key_name]


def merge_dicts(base: Dict, new_values: Dict) -> None:
    """
    Performs a deep, recursive merge of the `new_values` dictionary into the
    `base` dictionary.

    This function modifies the `base` dictionary **in place**. For each key in
    `new_values`:
    - If the key exists in `base` and both corresponding values are
      dictionaries, the function recursively calls itself to merge the nested
      dictionaries.
    - Otherwise (key not in `base`, or values are not both dictionaries), the
      key-value pair from `new_values` is added to or overwrites the entry in
      `base`.
    - After merging, removes duplicate firmware entries with identical keys,
      keeping only the lowest version number.

    Args:
        base: The dictionary to merge into (modified in place).
        new_values: The dictionary containing new values to merge into `base`.

    Returns:
        None
    """

    for key, value in new_values.items():
        logging.debug(f"Merging key: '{key}' (Type: {type(value).__name__})")
        if isinstance(value, dict) and key in base and isinstance(base.get(key), dict):
            merge_dicts(base[key], value)
        else:
            base[key] = value

    # Deduplicate firmware entries with identical keys at this level
    deduplicate_firmware_keys(base)


def get_firmware(data: Union[bytes, mmap.mmap]) -> Optional[float]:
    """
    Attempts to find and parse the firmware version string within the data.

    Searches for `FIRMWARE_SEARCH_STRING` and extracts the subsequent
    `FIRMWARE_VERSION_STRING_LENGTH` bytes to parse as a float.

    Args:
        data: The binary data (bytes or mmap object) to search within.

    Returns:
        The firmware version as a float (e.g., 5.05), or None if the string is
        not found, the data is too short, or parsing fails.
    """

    # Check if the firmware string was found in the data.
    start_index = data.find(FIRMWARE_SEARCH_STRING)
    if start_index == -1:
        logging.debug(f"Firmware search string '{FIRMWARE_SEARCH_STRING.decode(errors='ignore')}' not found.")
        return None
    logging.debug(f"Found firmware search string at offset 0x{start_index:X}.")

    # Check if there's enough data remaining to read the version string.
    location = start_index + FIRMWARE_SEARCH_LEN
    if location + FIRMWARE_VERSION_STRING_LENGTH > len(data):
        logging.debug(f"Insufficient data after search string offset 0x{location:X} to read {FIRMWARE_VERSION_STRING_LENGTH} bytes for version.")
        return None

    # Extract and convert the version string to float.
    version_bytes = data[location : location + FIRMWARE_VERSION_STRING_LENGTH]
    logging.debug(f"Extracted potential version bytes: {version_bytes!r}")
    try:
        firmware_version = float(version_bytes)
    except ValueError:
        logging.debug("ValueError while converting version bytes to a float.")
        return None
    logging.debug(f"Parsed firmware version: {firmware_version:.2f}")

    return firmware_version


def validate_input_file(input_path: pathlib.Path, min_size: int) -> bool:
    """
    Performs basic validation checks on the input file path.

    Checks if the path exists, is a file (not a directory), and is larger than
    min_size. Logs errors if any check fails.

    Args:
        input_path: The pathlib.Path object representing the input file.
        min_size: The minimum required file size for validation.

    Returns:
        True if all validation checks pass, False otherwise.
    """

    logging.debug(f"Validating input path: '{input_path}'")
    if not input_path.is_file():
        if input_path.is_dir():
            logging.error(f"Specified path '{input_path}' is a directory, not a file.")
        else:
            logging.error(f"Specified file '{input_path}' does not exist.")
        return False

    try:
        file_size = input_path.stat().st_size
        logging.debug(f"File size: {file_size:,} bytes.")
        if file_size < min_size:
            logging.error(f"File size ({file_size:,} bytes) is too small.")
            logging.error(f"Minimum required: {min_size:,} bytes.")
            return False
    except OSError as e:
        logging.error(f"Unable to get size of file '{input_path}': {e}")
        return False

    logging.debug(f"File path validation successful for '{input_path}'.")
    return True


def validate_output_directory(output_path: pathlib.Path) -> bool:
    """
    Performs basic validation checks on the output directory path.

    Checks if the path exists and is a directory. If it does not exist,
    attempts to create it. Logs errors if any check fails.

    Args:
        output_path: The pathlib.Path object representing the output directory.

    Returns:
        True if all validation checks pass, False otherwise.
    """

    logging.debug(f"Validating output directory: '{output_path}'")

    if output_path.is_dir():
        logging.debug(f"Output directory '{output_path}' already exists.")
        return True
    elif output_path.is_file():
        logging.error(f"'{output_path}' is a file, not a directory")
        return False
    elif output_path.exists():
        logging.error(f"'{output_path}' exists, but is not a directory.")
        return False

    try:
        # Create directory
        logging.debug(f"Creating output directory: '{output_path}'")
        output_path.mkdir(parents=True, exist_ok=True)
        return True
    except OSError as e:
        logging.error(f"Could not create directory: '{output_path}': {e}")
        return False


def validate_elf(data: Union[bytes, mmap.mmap]) -> bool:
    """
    Validates that the provided data has a valid ELF header structure.

    Checks for the ELF magic number, correct header size, valid ELF type
    (ET_EXEC, ET_DYN, or ET_REL), and supported machine architecture
    (EM_AM32 or EM_X86_64).

    Args:
        data: The binary data (bytes or mmap object) to validate.

    Returns:
        True if the data has a valid ELF header, False otherwise.
    """

    ET_EXEC: bytes = b"\x02\x00"
    ET_DYN: bytes = b"\x03\x00"
    ET_REL: bytes = b"\x01\x00"
    EM_NONE: bytes = b"\x00\x00"
    EM_AM32: bytes = b"\x67\x06"
    EM_X86_64: bytes = b"\x3e\x00"

    if len(data) < len(ELF_MAGIC):
        logging.debug("Input data too small to have ELF magic header.")
        return False

    if data[: len(ELF_MAGIC)] != ELF_MAGIC:
        logging.debug("Invalid ELF magic.")
        return False

    if len(data) < 54:
        logging.debug("Input data too small to determine ELF header size.")
        return False
    if len(data) < int.from_bytes(data[52:54]):
        logging.debug("Input data is smaller than the specified ELF header size.")
        return False

    if data[16:18] not in [ET_EXEC, ET_DYN, ET_REL]:  # e_type
        logging.debug("Invalid ELF type.")
        return False

    if data[18:20] == EM_NONE:  # e_machine
        logging.debug("Unknown machine architecture.")
        return False
    if data[18:20] != EM_AM32 and data[18:20] != EM_X86_64:  # e_machine
        logging.debug("Machine architecture is not x86_64 or AM32.")
        return False

    return True


def validate_self(data: Union[bytes, mmap.mmap]) -> bool:
    """
    Validates that the provided data has a valid SELF header structure.

    Checks for the SELF magic number and verifies expected values in the
    version, mode, endian, attr, and ext_flags fields of the SELF header.
    Errors are debug prints because we are just using it as a check vs it being
    an issue.

    Args:
        data: The binary data (bytes or mmap object) to validate.

    Returns:
        True if the data has a valid SELF header, False otherwise.
    """

    VERSION_OFFSET: int = 0x04
    MODE_OFFSET: int = 0x05
    LITTLE_ENDIAN_OFFSET: int = 0x06
    ATTR_OFFSET: int = 0x07
    EXT_FLAGS_OFFSET: int = 0x1A

    VALID_VERSION: bytes = b"\x00"
    VALID_MODE: bytes = b"\x01"
    VALID_LITTLE_ENDIAN: bytes = b"\x01"
    VALID_ATTR: bytes = b"\x12"
    VALID_EXT_FLAGS: bytes = b"\x22"

    if len(data) < len(SELF_MAGIC):
        logging.debug("Input data too small to have SELF magic header.")
        return False

    if data[: len(SELF_MAGIC)] != SELF_MAGIC:
        logging.debug("Invalid SELF magic.")
        return False

    if len(data) < 12:
        logging.debug("Input data too small to determine SELF header size.")
        return False
    if len(data) < int.from_bytes(data[12:14]):
        logging.debug("Input data is smaller than the specified SELF header size.")
        return False

    if data[VERSION_OFFSET : VERSION_OFFSET + len(VALID_VERSION)] != VALID_VERSION:
        logging.debug("Invalid SELF version.")
        return False

    if data[MODE_OFFSET : MODE_OFFSET + len(VALID_MODE)] != VALID_MODE:
        logging.debug("Invalid SELF mode.")
        return False

    if data[LITTLE_ENDIAN_OFFSET : LITTLE_ENDIAN_OFFSET + len(VALID_LITTLE_ENDIAN)] != VALID_LITTLE_ENDIAN:
        logging.debug("Invalid SELF little endian.")
        return False

    if data[ATTR_OFFSET : ATTR_OFFSET + len(VALID_ATTR)] != VALID_ATTR:
        logging.debug("Invalid SELF attr.")
        return False

    if data[EXT_FLAGS_OFFSET : EXT_FLAGS_OFFSET + len(VALID_EXT_FLAGS)] != VALID_EXT_FLAGS:
        logging.debug("Invalid SELF ext flags.")
        return False

    return True


def handle_json_output(output_path: pathlib.Path, new_keys_data: Dict, merge_flag: bool) -> bool:
    """
    Handles writing the extracted keys to a JSON file, optionally merging with
    existing data.

    Args:
        output_path: The pathlib.Path object representing the output JSON file.
        merge_flag: Boolean indicating whether to merge with existing file
                    content.
        new_keys_data: The dictionary of newly extracted keys to write/merge.

    Returns:
        True if JSON handling was successful, False otherwise.
    """

    logging.info(f"Writing keys to JSON file: '{output_path}'...")
    final_json_data: Dict = {}

    # If merge flag is set and file exists, attempt to merge
    if output_path.is_file() and merge_flag:
        logging.info("Attempting to merge keys into existing file...")
        try:
            with open(output_path, "r", encoding="utf-8") as json_file:
                existing_data = json.load(json_file)
            # Ensure existing data is a dictionary before merging
            if isinstance(existing_data, dict):
                final_json_data = existing_data  # Start with existing data
                merge_dicts(final_json_data, new_keys_data)  # Merge new keys into it
                logging.info("Merge successful.")
            else:
                logging.warning(f"Existing JSON file '{output_path}' does not contain a valid JSON object (dictionary). Overwriting.")
                final_json_data = new_keys_data  # Overwrite with new data
        except json.JSONDecodeError as e:
            logging.warning(f"Existing JSON file '{output_path}' is invalid or empty. Overwriting. Error: {e}")
            final_json_data = new_keys_data  # Overwrite with new data
        except OSError as e:
            logging.error(f"Could not read existing JSON file '{output_path}' for merging: {e}")
            return False
    elif not output_path.is_file() and merge_flag:
        logging.debug(f"--merge-json specified, but output file '{output_path}' does not exist. Will create a new file.")
        final_json_data = new_keys_data
    else:  # Not merging or file doesn't exist
        final_json_data = new_keys_data

    # Sort all keys naturally before writing to JSON
    logging.debug("Applying natural sort to all dictionary keys...")
    sort_dict_naturally(final_json_data)

    try:
        with open(output_path, "w", encoding="utf-8") as json_file:
            json.dump(final_json_data, json_file, sort_keys=False, indent=2)  # Write the final data (new or merged), keys already sorted
        logging.info(f"Successfully wrote keys to '{output_path}'.")
        return True
    except OSError as e:
        logging.error(f"Could not write JSON file: '{output_path}': {e}")
        return False


def write_files(output_path: pathlib.Path, extracted_data: Dict[str, bytes]) -> bool:
    """
    Writes the files to the specified output directory.

    Iterates through the data dictionary and writes each file to the output
    directory, using the dictionary keys as filenames.

    Args:
        output_path: The pathlib.Path object representing the output directory
                     where files should be written.
        data: A dictionary mapping filenames (str) to binary data (bytes) to be
              written.

    Returns:
        True if all files were written successfully, False if any error occurs
        during file writing.
    """

    try:
        for name, data in extracted_data.items():
            filename = output_path / name
            try:
                with open(filename, "wb") as fh:
                    fh.write(data)
                logging.info(f"  Successfully wrote {len(data):,} bytes to {filename}")
            except OSError as e:
                logging.error(f"Could not write file {filename}: {e}")
                return False
        return True
    except Exception as e:
        logging.exception(f"Unexpected error while writing extracted files: {e}")
        return False
