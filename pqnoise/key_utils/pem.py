"""
This module implements reading and writing PEM files.

PEM files are files that contain "textual encodings".
A textual encoding is a contiguous section of a file that
start with "-----BEGIN <label>-----",
ends with "-----END <label>-----",
and has base64-encoded data in between.
There can be multiple text encodings in a PEM file,
with the same or different labels.

The specifications of PEM files are at https://www.rfc-editor.org/rfc/rfc7468.html
"""

import base64
import itertools
from collections.abc import Iterator
from typing import BinaryIO

from ..types import BytesLike


BEGIN_PREFIX = b'-----BEGIN '
BEGIN_SUFFIX = b'-----'
END_PREFIX = b'-----END '
END_SUFFIX = b'-----'


class BeginMarkerNotFound(ValueError):
    """The begin line (-----BEGIN LABEL-----) is not found."""
    pass


class EndMarkerNotFound(ValueError):
    """The end line (-----END LABEL-----) is not found."""
    pass


def read_next_textual_encoding(file: BinaryIO) -> tuple[bytes, bytes]:
    """
    Read and return the next section of textual encoding from the current position in file.

    Anything outside textual encoding sections are ignored.
    
    :param file: A file open in 'rb' mode.
    :raises BeginMarkerNotFound: if a begin marker is not found
    :raises EndMarkerNotFound: if a begin marker is found, but the matching end marker is not found
    :raises ValueError: if the base64-encoded data is invalid
    :return: tuple of (label, base64-decoded contents)
    """
    begin_found = False
    label = None
    end_line = None
    encoded_lines = []
    for line in file:
        line = line.strip()
        if not begin_found:
            if line.startswith(BEGIN_PREFIX) and line.endswith(BEGIN_SUFFIX):
                label = line[len(BEGIN_PREFIX):-len(BEGIN_SUFFIX)]
                begin_found = True
                end_line = END_PREFIX + label + END_SUFFIX
            continue
        assert begin_found
        assert label is not None
        assert end_line is not None
        if line == end_line:
            return label, base64.b64decode(b''.join(encoded_lines))
        encoded_lines.append(line)
    else:
        if not begin_found:
            raise BeginMarkerNotFound
        raise EndMarkerNotFound(f'End marker not found for label {label}')


def read_all_textual_encodings(file: BinaryIO) -> Iterator[tuple[bytes, bytes]]:
    """
    Read and yield all sections of textual encodings in file, starting from the current position.

    Anything outside textual encoding sections are ignored.

    This method is suitable for reading all sections from a concatenated PEM file.
    
    :param file: A file open in 'rb' mode.
    :raises EndMarkerNotFound: if a begin marker is found, but the matching end marker is not found
    :raises ValueError: if the base64-encoded data is invalid
    :return: Generator yielding tuples of (label, base64-decoded contents)
    """
    while True:
        try:
            yield read_next_textual_encoding(file)
        except BeginMarkerNotFound:
            break


def read_first_textual_encoding_with_label(file: BinaryIO, label: bytes) -> bytes:
    """
    Read and return the first textual encoding in file with the given label.

    Any well-formed textual encodings before one with the given label are skipped.
    Any non-well-formed textual encodings result in exceptions.

    Note: for reading multiple textual encodings from the same file,
    using read_all_textual_encodings is recommended,
    especially if the ordering inside the file is not known in advance.
    As an example, for such a file:

    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----

    read_first_textual_encoding_with_label(file, b'PUBLIC KEY') will skip over the private key
    and return the public key.
    Calling read_first_textual_encoding_with_label(file, b'PRIVATE KEY') without seeking
    will then raise ValueError because it cannot find the private key.
    
    :param file: A file open in 'rb' mode.
    :param label: The label to read, such as b'PRIVATE KEY'. Note this is bytes, not str.
    :raises EndMarkerNotFound: if a begin marker is found, but the matching end marker is not found
    :raises ValueError: if the base64-encoded data is invalid
    :return: the base64-decoded contents.
    """
    for read_label, data in read_all_textual_encodings(file):
        if read_label == label:
            return data
    else:
        raise ValueError('Specified label not found in file')


PEM_LINE_LENGTH = 64


def write_textual_encoding(file: BinaryIO, label: BytesLike, data: BytesLike) -> None:
    """
    Write a textual encoding of data to file, denoted by label.
    
    :param file: A file open in 'wb' mode.
    :param label: The label to write, such as b'PRIVATE KEY'. Note this is bytes, not str.
    :param data: The raw (not base64-encoded) data to write.
    """
    file.writelines([BEGIN_PREFIX, label, BEGIN_SUFFIX, b'\n'])
    base64_encoded = base64.b64encode(data)
    base64_mv = memoryview(base64_encoded)
    base64_lines_gen = (base64_mv[i:i+PEM_LINE_LENGTH] for i in range(0, len(base64_mv), PEM_LINE_LENGTH))
    file.writelines(itertools.chain.from_iterable((line, b'\n') for line in base64_lines_gen))
    file.writelines([END_PREFIX, label, END_SUFFIX, b'\n'])
