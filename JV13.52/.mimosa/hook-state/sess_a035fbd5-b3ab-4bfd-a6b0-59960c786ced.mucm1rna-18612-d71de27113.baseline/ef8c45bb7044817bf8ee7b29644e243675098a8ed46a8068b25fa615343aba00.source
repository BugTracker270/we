#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File name: split-kernel.py
Author: Al Azif
Created: 2021-07-25
Version: 1.0.0
Description:
    Separates the AMD μBIOS and FreeBSD Kernel from a decrypted Kernel ELF
    (80010002) to mimic the structure of a typical kernel dump. This ensures
    compatibility with debuggers and analysis scripts. While the complete AMD
    μBIOS ELF includes the FreeBSD Kernel ELF appended to it (as indicated by
    the sizes and offsets in the AMD μBIOS ELF header), the FreeBSD Kernel ELF
    itself is a valid standalone file.
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
    Split concatenated ELF files from the provided binary data.

    Searches for ELF magic numbers within the data to locate the boundaries
    between the two concatenated ELF files. It validates each discovered ELF
    file and extracts them separately, returning them as individual binary
    blobs mapped to their respective filenames.

    Args:
        data: The binary data (bytes or mmap object) to search for concatenated
              ELF files.

    Returns:
        A tuple containing (firmware_version, extracted) where firmware_version
        is a float, and extracted is a dictionary mapping filenames
        (str) to their binary data (bytes). Returns None if the input is not a
        valid ELF file, the firmware version cannot be determined, or the ELF
        files cannot be properly split.
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

    extracted: Dict[str, bytes] = {}
    elf_files = [match.start() for match in re.finditer(re.escape(utils.ELF_MAGIC), data)]
    if len(elf_files) >= 2 and utils.validate_elf(data[elf_files[0] : elf_files[1]]) and utils.validate_elf(data[elf_files[1] :]):
        extracted["amd_ubios.elf"] = data[elf_files[0] : elf_files[1]]
        extracted["kernel.elf"] = data[elf_files[1] :]
        logging.info(f"Successfully split ELF into '{list(extracted.keys())[0]}' ({len(extracted['amd_ubios.elf']):,} bytes) and '{list(extracted.keys())[1]}' ({len(extracted['kernel.elf']):,} bytes).")
    else:
        logging.error("Unable to extract AMD μBIOS and FreeBSD Kernel")
        return None

    return (firmware_version, extracted)


def _process_input_file(input_path: pathlib.Path) -> Optional[Tuple[Optional[float], Dict[str, bytes]]]:
    """
    Handles opening, memory-mapping, and processing the input file.

    Opens the specified file in binary read mode, creates a memory map for
    efficient access, and calls the extraction function to find and split the
    concatenated ELF files.

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
    4. Calls the core processing function to split the concatenated ELF files.
    5. Exits with status code 0 on success, or 1 on failure, logging errors to
       stderr

    Returns:
        None
    """

    # --- Setup argument Parser ---
    parser = argparse.ArgumentParser(description="Kernel Splitter by Al Azif\nSeparates the AMD μBIOS and FreeBSD Kernel from a decrypted Kernel ELF (`80010002`) to mimic the structure of a typical kernel dump.", formatter_class=argparse.RawTextHelpFormatter)
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
        logging.info(f"Successfully split AMD μBIOS and Kernel from firmware {firmware_version}")

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
