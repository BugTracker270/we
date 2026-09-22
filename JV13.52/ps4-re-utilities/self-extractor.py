#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File name: self-extractor.py
Author: Al Azif
Created: 2021-07-25
Version: 1.0.0
Description:
    Automatically extracts embedded SELF files—such as mini-syscore.elf,
    safemode.elf, and SceSysAvControl.elf—from a decrypted or dumped Kernel ELF
    (80010002). The script assumes there are three embedded SELF files in the
    specified order, though it will extract all of them if more are present.
    Output files should be manually verified to ensure correct naming.
License: GPLv3
Contact: https://github.com/Al-Azif
Dependencies:
    argparse, logging, mmap, os, pathlib, re, sys, typing
Changelog:
    1.0.0
        - Initial Release
"""

import argparse
import logging
import mmap
import os
import pathlib
import re
import sys
from typing import Dict, Optional, Tuple, Union

# Python Version Check
if sys.version_info < (3, 6):
    print("ERROR: This script requires Python 3.6 or later.", file=sys.stderr)
    sys.exit(1)

# Add lib directory to path
sys.path.append(str(pathlib.Path(__file__).parent.resolve()))
from lib import utils

# Script version
__version__ = "1.0.0"


def _process_data(data: Union[bytes, mmap.mmap]) -> Optional[Tuple[float, Dict[str, bytes]]]:
    """
    Extracts embedded SELF files from the provided binary data.

    Searches for SELF magic numbers within the data, validates each potential
    SELF header structure, extracts the SELF file data based on the declared
    size in the header, and returns them in a dictionary mapped to their
    expected filenames.

    Args:
        data: The binary data (bytes or mmap object) to search for embedded
              SELF files.

    Returns:
        A tuple containing (firmware_version, extracted) where firmware_version
        is a float, and extracted is a dictionary mapping filenames (str) to
        their binary data (bytes). Returns None if the input is not a valid ELF
        file, the firmware version cannot be determined, or no valid SELF files
        are found.
    """

    logging.debug("Starting data processing...")

    if not utils.validate_elf(data):
        logging.error("Input data is not a valid ELF file.")
        return None

    # Determine the firmware version from the data.
    firmware_version = utils.get_firmware(data)
    if firmware_version is None:
        logging.error("Could not determine firmware version.")
        return None
    logging.info(f"Detected Firmware Version: {firmware_version:.2f}")

    # Find all occurrences of the SELF magic in the data
    self_magic_offsets = [match.start() for match in re.finditer(re.escape(utils.SELF_MAGIC), data)]
    if not self_magic_offsets:
        logging.error("No SELF files found to validate.")
        return None

    # Validate the SELFs at those offsets are valid
    valid_self_offsets = []
    logging.debug(f"Found {len(self_magic_offsets)} potential SELF magic numbers.")
    for offset in self_magic_offsets:
        if utils.validate_self(data[offset:]):
            logging.debug(f"  Validated SELF header structure at offset 0x{offset:X}")
            valid_self_offsets.append(offset)
        else:
            logging.debug(f"  Skipping offset 0x{offset:X} (failed validation)")
    if not valid_self_offsets:
        logging.error("No validated SELF files found to extract.")
        return None

    if len(valid_self_offsets) < 3:
        logging.warning(f"Found fewer than 3 expected SELF files ({len(valid_self_offsets)} found). Naming might be incorrect or files missing.")

    logging.debug(f"Extracting {len(valid_self_offsets)} validated SELF files...")
    extracted: Dict[str, bytes] = {}
    i = 0
    for offset in valid_self_offsets:
        size_field_offset = offset + 0x10  # Size offset is always at 0x10 of the SELF header
        size_field_length = 4  # Filesize in the header is stored as a uint32_t

        if size_field_offset + size_field_length > len(data):
            logging.error(f"Cannot read size field for SELF at offset 0x{offset:X}. Offset out of bounds.")
            continue

        self_extraction_size = int.from_bytes(data[size_field_offset : size_field_offset + size_field_length], byteorder="little")

        if offset + self_extraction_size > len(data):
            logging.error(f"SELF file at offset 0x{offset:X} with declared size {self_extraction_size:,} bytes would end at offset 0x{offset + self_extraction_size:X}, exceeding input file boundary (Input Size: {len(data):,}).")
            continue
        if self_extraction_size == 0:
            logging.warning(f"SELF file at offset 0x{offset:X} has an extraction size of zero (based on field at 0x{size_field_offset:X}). Skipping.")
            continue

        self_data = bytes(data[offset : offset + self_extraction_size])

        # The file naming is based on order which may not be correct, but determining which is which, while encrypted, is well beyond the scope of this script.
        filename = ""
        if i == 0:
            filename = "mini-syscore.self"
        elif i == 1:
            filename = "safemode.self"
        elif i == 2:
            filename = "SceSysAvControl.self"
        else:
            logging.warning(f"Found extra validated SELF at index {i} (Offset: 0x{offset:X}). Naming scheme might be incorrect.")
            filename = f"extra_{i}.self"

        logging.info(f"  Found SELF {i} (Offset: 0x{offset:X}, Size: {len(self_data):,} bytes) -> {filename}")
        extracted[filename] = self_data

        i += 1

    return (firmware_version, extracted)


def _process_input_file(input_path: pathlib.Path) -> Optional[Tuple[Optional[float], Dict[str, bytes]]]:
    """
    Handles opening, memory-mapping, and processing the input file.

    Opens the specified file in binary read mode, creates a memory map for
    efficient access, and calls the extraction function to find and extract
    embedded SELF files.

    Args:
        input_path: The pathlib.Path object representing the input file to
                    process.

    Returns:
        A tuple containing (firmware_version, extracted_dict) if successful, or
        None if an error occurs during file access or processing.
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


def main() -> None:
    """
    Main execution entry point for the script.

    Handles the overall workflow:
    1. Parses command-line arguments (input file, output directory, verbosity).
    2. Configures logging based on verbosity arguments.
    3. Validates the input file path and basic file properties.
    4. Calls the core processing function to extract the embedded SELF files.
    5. Exits with status code 0 on success, or 1 on failure, logging errors to
       stderr

    Returns:
        None
    """

    # --- Setup argument Parser ---
    parser = argparse.ArgumentParser(description="SELF File Extractor by Al Azif\nExtracts embedded SELF files—such as `mini-syscore.elf`, `safemode.elf`, and `SceSysAvControl.elf`—from a decrypted or dumped Kernel ELF (`80010002`).", formatter_class=argparse.RawTextHelpFormatter)
    # Verbosity group
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-q", "--quiet", action="store_true", help="Suppress informational messages, show only warnings and errors.")
    verbosity_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output.")
    # Version argument
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # Positional and optional arguments
    parser.add_argument("file", type=pathlib.Path, help="Specify the location of the decrypted Kernel ELF")
    parser.add_argument("-o", "--output", type=pathlib.Path, required=False, help="Path to the output directory. If not specified it outputs to current working directory.")
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
    if not utils.validate_input_file(input_path, len(utils.ELF_MAGIC)):
        # Errors are logged by `_validate_input_file`
        sys.exit(1)

    # --- Output Directory Validation ---
    output_path = ""
    if not args.output:
        # No path specified, use CWD
        output_path = pathlib.Path(os.getcwd())
    else:
        output_path = pathlib.Path(args.output)
    if not utils.validate_output_directory(output_path):
        # Errors are logged by `_validate_output_directory`
        sys.exit(1)

    try:
        # --- File Processing ---
        processed_data = _process_input_file(input_path)
        if processed_data is None:
            # Errors are logged by `_process_input_file`
            sys.exit(1)
        (firmware_version, extracted_data) = processed_data
        logging.info(f"Successfully extracted {len(extracted_data)} SELF file(s) from firmware {firmware_version}")

        # --- Output Handling ---
        if not utils.write_files(output_path, extracted_data):
            # Errors are logged by `utils.write_files`
            sys.exit(1)
    except Exception as e:
        # Catch any other unexpected errors
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
