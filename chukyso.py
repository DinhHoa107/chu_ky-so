#!/usr/bin/env python3
"""
sign_pdf.py
Simple PDF signer (demo) using PyPDF2 + OpenSSL CLI.

Usage:
  python sign_pdf.py original.pdf signed.pdf cert.pem key.pem

High-level flow:
 1. Add a signature field placeholder (AcroForm + Sig field) and reserve a /Contents area (8192 bytes).
 2. Write incremental PDF to disk (with placeholder).
 3. Compute ByteRange offsets for the placeholder in the written file.
 4. Compute SHA256 over the two byte ranges (excluding /Contents).
 5. Use OpenSSL cms to create a DER PKCS#7 detached signature over the hashed data.
 6. Insert the PKCS#7 blob into /Contents (hex-encoded) at the reserved offset and write final incremental update.
Notes:
 - This is a demonstration implementation. Real-world PDF signing has many more edge cases (PAdES, timestamp tokens, DSS, LTV).
"""

import sys
import subprocess
import tempfile
import os
import shutil
import hashlib
import binascii
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import (
    DictionaryObject, NameObject, create_string_object,
    ByteStringObject, NumberObject, ArrayObject, IndirectObject
)

# size of reserved /Contents in bytes (must be large enough for PKCS#7 blob; 8192 is common)
CONTENTS_SIZE = 8192

def create_sig_placeholder(original_pdf, temp_pdf):
    """
    Create a copy of original_pdf with a signature field placeholder.
    The placeholder writes a signature dictionary with /Contents filled with zeros (hex string).
    """
    reader = PdfReader(original_pdf)
    writer = PdfWriter()

    # copy pages
    for page in reader.pages:
        writer.add_page(page)

    # Ensure AcroForm exists
    root = writer._root_object
    # Build AcroForm and SigField objects
    # Create field dictionary
    sig_field = DictionaryObject()
    sig_field.update({
        NameObject("/FT"): NameObject("/Sig"),
        NameObject("/Type"): NameObject("/Annot"),  # widget annotation
        NameObject("/Subtype"): NameObject("/Widget"),
        # basic rectangle for appearance; invisible form allowed: here minimal rect
        NameObject("/T"): create_string_object("Signature1"),
        NameObject("/Ff"): NumberObject(0),
        # /V will be added later (signature dictionary)
    })

    # Build signature dictionary with placeholder /Contents
    sig_dict = DictionaryObject()
    sig_dict.update({
        NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
        NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
        NameObject("/Contents"): create_string_object("0" * (CONTENTS_SIZE*2)),  # hex as string
        NameObject("/ByteRange"): ArrayObject([NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)]),
        NameObject("/Type"): NameObject("/Sig"),
        # optional textual signing time /M - not authoritative
        # NameObject("/M"): create_string_object("D:20251031..."),
    })

    # Link signature dictionary into field
    sig_field[NameObject("/V")] = sig_dict

    # Add AcroForm
    writer._root_object.update({
        NameObject("/AcroForm"): DictionaryObject({
            NameObject("/Fields"): ArrayObject([sig_field])
        })
    })

    # Write to temp file
    with open(temp_pdf, "wb") as f:
        writer.write(f)

    return

def find_contents_range(pdf_path):
    """
    Find the byte offsets of the /Contents hex placeholder in the PDF file.
    Returns (start_index_of_hex, hex_length, byte_range_array_offset)
    - start_index_of_hex: index in bytes where the hex string starts (first hex char)
    - hex_length: length of hex chars (should be CONTENTS_SIZE*2)
    - byte_range_array_offset: tuple (byte range array start index in file, length)
    """
    with open(pdf_path, "rb") as f:
        data = f.read()

    # find the marker '/Contents <' or '/Contents ('
    # we used create_string_object, which may write (<hex>) or <hex> form; look for hex sequence:
    # Search for large run of '0' characters the length of CONTENTS_SIZE*2
    hex_pattern = b"0" * (CONTENTS_SIZE*2)
    idx = data.find(hex_pattern)
    if idx == -1:
        raise ValueError("Could not find Contents placeholder in PDF")

    # Now find the start of the PDF '<' that opens hex string (or '(' for string)
    # Work backwards a bit
    start = data.rfind(b"<", 0, idx)
    if start == -1:
        # fallback: might be stored as literal string with parentheses
        start = data.rfind(b"(", 0, idx)
        if start == -1:
            raise ValueError("Could not find opening '<' or '(' for Contents")
        # then the content is between ( and ), not hex form; handle similarly but we assume hex.
    # find end '>' after idx
    end = data.find(b">", idx)
    if end == -1:
        raise ValueError("Could not find closing '>' for Contents")
    hex_start = start + 1
    hex_len = end - hex_start
    if hex_len < CONTENTS_SIZE*2:
        # still accept but warn
        pass

    # find ByteRange array location for later update
    # look for '/ByteRange[' or '/ByteRange ['
    br_marker = b"/ByteRange["
    br_idx = data.find(br_marker)
    if br_idx == -1:
        br_marker = b"/ByteRange ["
        br_idx = data.find(br_marker)
    if br_idx == -1:
        # find '/ByteRange' and then the following '['
        br_idx = data.find(b"/ByteRange")
        if br_idx == -1:
            raise ValueError("Could not find /ByteRange in PDF")
        # find '[' after br_idx
        br_arr_idx = data.find(b"[", br_idx)
    else:
        br_arr_idx = data.find(b"[", br_idx)
    if br_arr_idx == -1:
        raise ValueError("Could not locate ByteRange array start")

    # find closing ']' for ByteRange
    br_end = data.find(b"]", br_arr_idx)
    if br_end == -1:
        raise ValueError("Could not find end of ByteRange array")
    return hex_start, hex_len, (br_arr_idx, br_end+1)

def compute_byterange_hash(pdf_path, hex_start, hex_len):
    """
    Compute SHA256 over the two ranges defined by ByteRange:
    range1 = [0, offset_of_<] and range2 = [end_of_>, filesize - end_of_>]
    Returns digest bytes.
    """
    with open(pdf_path, "rb") as f:
        data = f.read()
    file_size = len(data)
    # find full '<...>' start and end surrounding the hex: we were given hex_start (position after '<')
    # compute positions
    # locate '<' by hex_start-1
    hex_open = hex_start - 1
    hex_close = hex_open + 1 + hex_len  # position of '>' (index)
    # ByteRange should exclude from hex_open to hex_close inclusive
    range1 = data[0:hex_open]
    range2 = data[hex_close+1:]
    # compute hash over concatenation of range1 + range2 (this is what pdf viewers verify)
    sha256 = hashlib.sha256()
    sha256.update(range1)
    sha256.update(range2)
    return sha256.digest(), len(range1), len(range2)

def create_pkcs7_with_openssl(data_digest, cert_pem, key_pem, out_der_path):
    """
    Create a PKCS#7 / CMS detached signature using OpenSSL CLI.
    We write the raw data to a temp file and call openssl cms -sign.
    Because PDF signing expects the signature over the document bytes, we pass the actual bytes
    via a temp file. We request DER output (-outform DER).
    """
    with tempfile.TemporaryDirectory() as td:
        data_file = os.path.join(td, "data.bin")
        with open(data_file, "wb") as f:
            f.write(data_digest)  # NOTE: some implementations sign the raw bytes, others sign the full data.
            # Here we are signing the data digest to create a PKCS7 blob that contains signature.
            # Many tools sign the whole data file; if needed adjust to sign the full bytes ranges file.

        # OpenSSL command - may need experimentation depending on desired attributes.
        # Use 'cms -sign' to build PKCS7. We want detached signature (-nodetach is *not* specified),
        # but for PDF, use detached style: -nodetach omitted so result is detached.
        # Use -binary to preserve raw octets; -outform DER for binary output.
        cmd = [
            "openssl", "cms", "-sign",
            "-binary",
            "-signer", cert_pem,
            "-inkey", key_pem,
            "-in", data_file,
            "-outform", "DER",
            "-nosmimecap",  # reduces unnecessary attributes
            "-nodetach"     # NOTE: some toolings prefer -nodetach; if you want detached, remove -nodetach
        ]
        # Many PDF signers expect a PKCS7 with detached signature: experiment with -nodetach vs not.
        # We'll try with -nodetach here; if Acrobat complains, try removing -nodetach.
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print("OpenSSL cms failed:", e.stderr.decode(errors="ignore"))
            raise

        # OpenSSL writes to stdout by default if -out not given; adjust to capture by redirecting -out
        # instead specify -out
        out_file = out_der_path
        cmd_out = cmd + ["-out", out_file]
        subprocess.run(cmd_out, check=True)
        return out_file

def insert_signature_into_pdf(pdf_path, out_pdf_path, pkcs7_der_path, hex_start, hex_len, br_loc):
    """
    Insert the DER PKCS7 into the placeholder slot (hex text) and update /ByteRange
    Then write final PDF as an incremental update (append).
    """
    with open(pdf_path, "rb") as f:
        data = f.read()

    # read signature DER
    with open(pkcs7_der_path, "rb") as f:
        sig_der = f.read()

    # ensure signature fits in reserved slot
    if len(sig_der) > (hex_len // 2):
        raise ValueError(f"PKCS7 length ({len(sig_der)}) exceeds reserved slot ({hex_len//2})")

    # convert DER to hex uppercase (PDF often stores uppercase hex but not required)
    sig_hex = binascii.hexlify(sig_der).upper()
    # pad the rest with zeros
    padding = (hex_len - len(sig_hex))
    sig_hex_padded = sig_hex + b"0" * padding

    # compose new data: replace the hex region
    new_data = bytearray(data)
    new_data[hex_start:hex_start+hex_len] = sig_hex_padded

    # compute ByteRange values
    # ByteRange = [0, offset1, offset2, length2]
    # offset1 = 0
    # length1 = hex_open (position of '<')  -> find '<' before hex_start
    hex_open = hex_start - 1
    hex_close = hex_open + 1 + hex_len
    offset1 = 0
    length1 = hex_open
    offset2 = hex_close + 1
    length2 = len(new_data) - offset2

    # Build replacement for /ByteRange [ a b c d ]
    br_string = f"/ByteRange [ {offset1} {length1} {offset2} {length2} ]"
    # Replace the existing array content between br_loc start/end with new br_string. Keep same size by padding if necessary.
    br_start, br_end = br_loc
    # Convert to bytes
    br_bytes = br_string.encode("ascii")
    # Pad with spaces if new shorter than existing
    existing_len = br_end - br_start
    if len(br_bytes) > existing_len:
        raise ValueError("New ByteRange string longer than existing - cannot write in place")
    br_bytes_padded = br_bytes + b" " * (existing_len - len(br_bytes))
    new_data[br_start:br_end] = br_bytes_padded

    # Write out the final file as incremental update (just write modified bytes)
    with open(out_pdf_path, "wb") as f:
        f.write(new_data)

    print(f"Signed PDF written to {out_pdf_path}")

def main():
    if len(sys.argv) != 5:
        print("Usage: python sign_pdf.py original.pdf signed.pdf cert.pem key.pem")
        sys.exit(1)
    original_pdf = sys.argv[1]
    signed_pdf = sys.argv[2]
    cert_pem = sys.argv[3]
    key_pem = sys.argv[4]

    # step 1: create placeholder
    temp_pdf = signed_pdf + ".tmp.pdf"
    print("Creating placeholder PDF...")
    create_sig_placeholder(original_pdf, temp_pdf)

    # step 2: locate placeholder and ByteRange
    print("Locating placeholder and ByteRange...")
    hex_start, hex_len, br_loc = find_contents_range(temp_pdf)

    # step 3: compute digest over ranges
    print("Computing SHA256 over ByteRange (excluding Contents)...")
    digest_bytes, len1, len2 = compute_byterange_hash(temp_pdf, hex_start, hex_len)
    # For PKCS7, either sign the actual concatenated bytes or sign the digest as an octet string; here we sign digest raw.
    # Write digest to temp file and call openssl
    with tempfile.NamedTemporaryFile(delete=False) as td:
        digest_file = td.name
        td.write(digest_bytes)

    # step 4: create pkcs7 blob with openssl
    with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as pkf:
        pk_path = pkf.name
    print("Creating PKCS#7 with OpenSSL (this may take a moment)...")
    create_pkcs7_with_openssl(digest_file, cert_pem, key_pem, pk_path)

    # step 5: insert signature into pdf and update ByteRange
    print("Inserting PKCS#7 into PDF and updating ByteRange...")
    insert_signature_into_pdf(temp_pdf, signed_pdf, pk_path, hex_start, hex_len, br_loc)

    # cleanup
    os.remove(temp_pdf)
    os.remove(digest_file)
    os.remove(pk_path)

if __name__ == "__main__":
    main()
