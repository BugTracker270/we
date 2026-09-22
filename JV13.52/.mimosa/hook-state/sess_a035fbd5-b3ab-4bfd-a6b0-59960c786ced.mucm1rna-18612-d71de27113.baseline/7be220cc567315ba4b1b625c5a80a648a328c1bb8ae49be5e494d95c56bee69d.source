#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File name: 80000001.py
Author: Al Azif
Created: 2021-07-25
Version: 1.0.0
Description:
    Automatically extracts Secure Kernel and BIOS keys from a decrypted Secure
    Loader binary (80000001). It uses the offset of a specific string as a
    reference point to locate the keys. While this method has changed in the
    past, the current script has remained effective from firmware 1.00 through
    13.50 and unchanged since firmware 4.50.
License: GPLv3
Contact: https://github.com/Al-Azif
Dependencies:
    argparse, logging, mmap, os, pathlib, struct, sys, typing
Changelog:
    1.0.0
        - Initial Release
"""

import argparse
import logging
import mmap
import os
import pathlib
import struct
import sys
from typing import Dict, List, Optional, Tuple, Union

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
# The primary anchor string used to locate the key data block.
ANCHOR_STRING: bytes = b"sceSblSlGetRandom\0\0\0"
# The length of the primary anchor string.
ANCHOR_LENGTH: int = len(ANCHOR_STRING)
# Offset from the *end* of ANCHOR_STRING to the potential start of the key data block or the SECONDARY_ANCHOR_STRING. This offset appears consistent across known firmware versions.
POST_ANCHOR_OFFSET: int = 0x18
# An optional secondary anchor string found between the primary anchor and the key data in firmware versions >= 3.50. If found, its length is added to the offset calculation.
SECONDARY_ANCHOR_STRING: bytes = b"getSamuClockKHz\0"
# The length of the secondary anchor string.
SECONDARY_ANCHOR_LENGTH: int = len(SECONDARY_ANCHOR_STRING)

# Define firmware ranges and their corresponding struct formats
# List of tuples: (max_version, format_string) ordered from lowest to highest max_version
# Struct uses '>' for big-endian format. 's' denotes bytes (for keys/IVs/RSA components), and 'x' denotes padding bytes to skip.
STRUCT_FORMATS: List[Tuple[float, str]] = [
    (1.62, ">16x16x16s16s16s16s16x16x16x16x16x16x256s4x4s256s256s4x4s256s"),  # 1.00 - 1.62
    (1.76, ">16s16s16s16s16x16x16x16x16x16x16x16x256s4x4s256s256s4x4s256s"),  # 1.70 - 1.76
    (2.57, ">16s16s16s16s16x16x16x16x16x16x16x16x32x256s4x4s256s256s4x4s256s"),  # 2.00 - 2.57
    (4.07, ">16x16x16s16s16s16s16x16x16x16x16x16x32x256s4x4s256s256s4x4s256s"),  # 3.00 - 4.07
    (13.50, ">16x16x16s16s16s16s16x16x16x16x16x16x64x256s4x4s256s256s4x4s256s"),  # 4.50 - 13.50 (and fallback)
]
# Define the latest known/verified firmware version explicitly
LATEST_VERIFIED_FIRMWARE: float = 13.50
# Define the format string used for versions > LATEST_VERIFIED_FIRMWARE
FALLBACK_STRUCT_FORMAT: str = STRUCT_FORMATS[-1][1]  # Use the last defined format as fallback

# Type alias for the dictionary structure returned
# Example structure:
# {
#     "SELF": {
#         "AM32": { "5.05_SECURE_KERNEL": { "AES_KEY": "...", ... } },
#         "X86_64": { "5.05_BIOS": { "AES_KEY": "...", ... } }
#     }
# }
KeysDict = Dict[str, Dict[str, Dict[str, Dict[str, str]]]]

# Define key names and their corresponding indices in the unpacked tuple
# Structure: { "Group Name": [(index, "Key Name"), ...], ... }
KEY_DEFINITIONS: Dict[str, List[Tuple[int, str]]] = {
    "Secure Kernel": [
        (0, "AES_KEY"),
        (1, "IV"),
        (4, "RSA_MODULUS"),
        (5, "RSA_PUB_EXPONENT"),
        (6, "RSA_R2"),
    ],
    "BIOS": [
        (2, "AES_KEY"),
        (3, "IV"),
        (7, "RSA_MODULUS"),
        (8, "RSA_PUB_EXPONENT"),
        (9, "RSA_R2"),
    ],
}
# Corresponding JSON structure keys for each group
JSON_KEY_MAP: Dict[str, Tuple[str, str]] = {
    "Secure Kernel": ("SELF", "AM32"),
    "BIOS": ("SELF", "X86_64"),
}


def _get_key_offset(data: Union[bytes, mmap.mmap]) -> Optional[int]:
    """
    Finds the offset where the key data structure begins in the binary data.

    Searches for the primary anchor, calculates an initial offset, then checks,
    and accounts for, the optional secondary anchor.

    Args:
        data: The binary data (bytes or mmap object) of the Secure Loader.

    Returns:
        The calculated integer offset if successful, None otherwise.
    """

    # Basic check: Ensure data is large enough for the primary anchor itself.
    if ANCHOR_LENGTH > len(data):
        logging.error(f"Could not perform anchor check for '{ANCHOR_STRING.decode(errors='ignore')}'.")
        logging.error(f"File ends before the required {ANCHOR_LENGTH:,} bytes could be read (File Size: {len(data):,}).")
        return None

    # Find the offset of the primary anchor string.
    offset = data.find(ANCHOR_STRING)
    if offset == -1:
        logging.error(f"Primary anchor string '{ANCHOR_STRING.decode(errors='ignore')}' not found.")
        return None
    logging.debug(f"Found primary anchor at offset 0x{offset:X}.")

    # Calculate the initial potential offset for key data block or the secondary anchor. This is `POST_ANCHOR_OFFSET` bytes *after* the end of the primary anchor.
    offset = offset + ANCHOR_LENGTH + POST_ANCHOR_OFFSET
    logging.debug(f"Calculated initial potential key offset (after primary anchor + 0x{POST_ANCHOR_OFFSET:X}): 0x{offset:X}.")

    # Check if there's enough data remaining to check for the secondary anchor.
    if offset + SECONDARY_ANCHOR_LENGTH > len(data):
        logging.error(f"Could not perform secondary anchor check for '{SECONDARY_ANCHOR_STRING.decode(errors='ignore')}'.")
        logging.error(f"Check requires reading {SECONDARY_ANCHOR_LENGTH:,} bytes starting at calculated offset 0x{offset:X}, but file size is only {len(data):,} bytes.")
        return None

    # Check if the secondary anchor string exists at the calculated `offset`. If it does, adjust the `offset` to point past it, as the keys start after this string on newer firmware.
    if data[offset : offset + SECONDARY_ANCHOR_LENGTH] == SECONDARY_ANCHOR_STRING:
        offset += SECONDARY_ANCHOR_LENGTH  # Adjust offset to point past the secondary anchor
        logging.debug(f"Secondary anchor found at 0x{offset - SECONDARY_ANCHOR_LENGTH:X}. Adjusted key offset to 0x{offset:X}.")
    else:
        logging.debug(f"Secondary anchor not found at 0x{offset:X}. Using offset 0x{offset:X} for keys.")

    logging.debug(f"Key offset successfully determined: 0x{offset:X}.")
    return offset


def _get_struct_format(firmware_version: float) -> str:
    """
    Selects the appropriate struct format string based on the firmware version.

    This function defines the known struct formats for unpacking key data
    across different firmware ranges.

    If the provided firmware version is newer than the latest explicitly known
    version (`LATEST_VERIFIED_FIRMWARE`), it issues a warning and defaults to
    `FALLBACK_STRUCT_FORMAT`.

    Args:
        firmware_version: The firmware version as a float (e.g., 5.05).

    Returns:
        A struct format string suitable for unpacking the key data for the
        given firmware version using `struct.unpack_from`, or an empty string
        if a critical error occurs.
    """

    selected_format = None
    for max_version, format_string in STRUCT_FORMATS:
        if firmware_version <= max_version:
            selected_format = format_string
            break

    logging.debug(f"Initial format search based on FW {firmware_version:.2f} yielded: '{selected_format}'")

    # If no format matched (shouldn't happen if list covers all ranges up to latest verified) or if firmware is newer than the latest verified, use the fallback.
    if selected_format is None or firmware_version > LATEST_VERIFIED_FIRMWARE:
        selected_format = FALLBACK_STRUCT_FORMAT
        logging.debug(f"Using fallback format: '{selected_format}'")
        if firmware_version > LATEST_VERIFIED_FIRMWARE:
            # Warn if using the fallback format for an untested newer firmware.
            logging.warning(f"Firmware version {firmware_version:.2f} is newer than the latest verified version ({LATEST_VERIFIED_FIRMWARE:.2f}).")
            logging.warning("Using the latest known structure, but it may be incorrect.")
        elif selected_format is None:  # Should be unreachable if STRUCT_FORMATS is correct
            logging.error(f"Internal logic error - could not find struct format for FW {firmware_version:.2f}, even with fallback.")
            # Fallback already assigned, but log the unexpected state.
    logging.debug(f"Final selected struct format for FW {firmware_version:.2f}: '{selected_format}'")

    # Defensive check in case FALLBACK_STRUCT_FORMAT wasn't set correctly or list was empty
    if selected_format is None:
        logging.error(f"No struct format could be determined for FW {firmware_version:.2f}. Cannot proceed.")
        # Returning an empty string will cause struct.calcsize to fail later, which is handled.
        return ""

    return selected_format


def _unpack_keys(firmware_version: float, struct_format: str, data: Union[bytes, mmap.mmap], offset: int) -> Optional[Tuple]:
    """
    Unpacks the key data from the binary data using the specified format.

    Calculates the expected struct size, performs bounds checking, and attempts
    to unpack the data at the given offset.

    Args:
        firmware_version: The detected firmware version (used for logging).
        struct_format: The struct format string to use for unpacking.
        data: The binary data (bytes or mmap object).
        offset: The offset within the data where the struct begins.

    Returns:
        A tuple containing the unpacked key data if successful, None otherwise.
    """

    # Calculate the expected size of the key structure based on the format string.
    logging.debug(f"Attempting to calculate size for struct format: '{struct_format}'")
    try:
        struct_size = struct.calcsize(struct_format)
    except struct.error as e:
        # This indicates an issue with the format string defined in STRUCT_FORMATS.
        logging.error(f"Invalid struct format string generated: '{struct_format}'")
        logging.error(f"Internal Error: {e}")
        return None
    logging.debug(f"Calculated struct size for format '{struct_format}': {struct_size:,} bytes.")

    # Check if the data is large enough to contain the entire key structure at the calculated offset.
    if offset + struct_size > len(data):
        logging.error(f"Calculated key struct size ({struct_size:,} bytes) for FW {firmware_version:.2f} starting at offset 0x{offset:X} exceeds file size ({len(data):,} bytes).")
        return None

    # Attempt to unpack the key data from the calculated offset using the selected format.
    logging.debug(f"Attempting unpack at offset 0x{offset:X} with size {struct_size:,} bytes.")
    try:
        unpacked = struct.unpack_from(struct_format, data, offset)
    except struct.error as e:
        # This usually means the data at the offset doesn't match the expected structure.
        logging.error(f"Failed to unpack data structure at offset 0x{offset:X} for firmware {firmware_version:.2f}.")
        logging.error(f"Struct Format Used: '{struct_format}' (Expected Size: {struct_size:,} bytes)")
        logging.error(f"Original Error: {e}")
        return None
    logging.debug(f"Successfully unpacked {len(unpacked)} items from offset 0x{offset:X}.")

    return unpacked


def _get_keys_dict(firmware_version: float, key_array: Tuple) -> KeysDict:
    """
    Builds the nested dictionary of keys (as hex strings) for JSON output using
    the centralized KEY_DEFINITIONS.

    Args:
        firmware_version: The detected firmware version.
        key_array: The tuple of unpacked key data (bytes).

    Returns:
        A dictionary containing the keys formatted for JSON output.
    """

    logging.debug(f"Building keys dictionary for FW {firmware_version:.2f}.")
    output_dict: KeysDict = {}
    for type_name, definitions in KEY_DEFINITIONS.items():
        json_level1, json_level2 = JSON_KEY_MAP[type_name]
        # e.g., "5.05_SECURE_KERNEL" or "5.05_BIOS"
        fw_key_name = f"{firmware_version:.2f}_{type_name.upper().replace(' ', '_')}"

        key_data = {}
        for index, key_name in definitions:
            if index < len(key_array):
                key_data[key_name] = key_array[index].hex().upper()
            else:
                logging.error(f"Index {index} for {type_name} {key_name} out of bounds in unpacked data. Skipping entry for JSON.")

        # Build nested structure dynamically
        output_dict.setdefault(json_level1, {}).setdefault(json_level2, {})[fw_key_name] = key_data

    logging.debug(f"Generated keys dictionary structure: {list(output_dict.keys())}")

    return output_dict


def _process_data(data: Union[bytes, mmap.mmap]) -> Optional[Tuple[float, Tuple]]:
    """
    Processes the Secure Loader data to extract keys.

    Orchestrates the extraction process from the provided data:
    1. Detects firmware version.
    2. Finds the starting offset for key data.
    3. Selects the appropriate data structure format.
    4. Unpacks the key data.

    Args:
        data: The binary data (bytes or mmap object) of the Secure Loader.

    Returns:
        A tuple containing (firmware_version, unpacked_keys) or None if an
        error occurred during processing.
    """

    logging.debug("Starting data processing...")

    # Determine the firmware version from the data.
    firmware_version = utils.get_firmware(data)
    if firmware_version is None:
        logging.error("Could not determine firmware version.")
        return None
    logging.info(f"Detected Firmware Version: {firmware_version:.2f}")

    # Find the offset where key data should start.
    key_data_offset = _get_key_offset(data)
    if key_data_offset is None:
        return None  # Errors are logged by `_get_key_offset`
    logging.debug(f"Final key data offset determined: 0x{key_data_offset:X}")

    # Get the appropriate struct format string for this firmware version.
    struct_format = _get_struct_format(firmware_version)
    if not struct_format:
        return None  # Errors are logged by `_get_struct_format`

    # Unpack the keys from data, located at the offset, using struct_format
    unpacked_keys = _unpack_keys(firmware_version, struct_format, data, key_data_offset)
    if unpacked_keys is None:
        return None  # Errors are logged by `_unpack_keys`

    logging.info("Successfully extracted keys from data.")
    return firmware_version, unpacked_keys


def _process_input_file(input_path: pathlib.Path) -> Optional[Tuple[float, Tuple]]:
    """
    Handles opening, memory-mapping, and processing the input file.

    Args:
        input_path: The pathlib.Path object representing the input file.

    Returns:
        A tuple (firmware_version, unpacked_keys) if successful, None
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


def _format_keys_string(key_array: Tuple) -> str:
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

    output_lines = []
    # Simplified width calculation
    max_desc_width = max(len(f"{key_name}:") for _, definitions in KEY_DEFINITIONS.items() for _, key_name in definitions)

    # Iterate through the centralized KEY_DEFINITIONS
    for type_name, definitions in KEY_DEFINITIONS.items():
        # Print a header for the key group
        header = f"--- {type_name} Keys "
        output_lines.append(f"{header}{'-' * (70 - len(header))}")
        for index, key_name in definitions:
            description = f"{key_name}:"
            if index < len(key_array):
                output_lines.append(f"{description:<{max_desc_width}} {key_array[index].hex().upper()}")
            else:
                logging.error(f"Index {index} for {type_name} {key_name} out of bounds in unpacked data. Skipping print.")

    return "\n".join(output_lines)


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
    parser = argparse.ArgumentParser(description="Secure Kernel Key Extractor by Al Azif\nExtracts Secure Kernel and BIOS keys from a decrypted Secure Loader binary (`80000001`).", formatter_class=argparse.RawTextHelpFormatter)
    # Verbosity group
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-q", "--quiet", action="store_true", help="Suppress informational messages, show only warnings and errors.")
    verbosity_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output.")
    # Version argument
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # Positional and optional arguments
    parser.add_argument("file", type=pathlib.Path, help="Specify the location of the decrypted Secure Loader binary")
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
    if not utils.validate_input_file(input_path, ANCHOR_LENGTH):
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
        (firmware_version, unpacked_keys) = processed_data
        logging.info("Key extraction process completed successfully.")

        # --- Format and Print Keys ---
        logging.info("Formatted Key Output:")
        logging.info(_format_keys_string(unpacked_keys))

        # --- JSON Output Handling ---
        if output_path:
            # Generate the dictionary for JSON output
            keys_dict = _get_keys_dict(firmware_version, unpacked_keys)
            # Handle writing/merging the JSON file
            if not utils.handle_json_output(output_path, keys_dict, args.merge_json):
                # Errors are logged by `_handle_json_output`
                sys.exit(1)
    except Exception as e:
        # Catch any other unexpected errors
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
