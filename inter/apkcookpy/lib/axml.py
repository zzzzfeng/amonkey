from struct import pack, unpack
from xml.sax.saxutils import escape
import collections
from collections import defaultdict

from lxml import etree
import logging
import re
import sys
import binascii

# Type definiton for (type, data) tuples representing a value
# See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#262

# The 'data' is either 0 or 1, specifying this resource is either
# undefined or empty, respectively.
TYPE_NULL = 0x00
# The 'data' holds a ResTable_ref, a reference to another resource
# table entry.
TYPE_REFERENCE = 0x01
# The 'data' holds an attribute resource identifier.
TYPE_ATTRIBUTE = 0x02
# The 'data' holds an index into the containing resource table's
# global value string pool.
TYPE_STRING = 0x03
# The 'data' holds a single-precision floating point number.
TYPE_FLOAT = 0x04
# The 'data' holds a complex number encoding a dimension value
# such as "100in".
TYPE_DIMENSION = 0x05
# The 'data' holds a complex number encoding a fraction of a
# container.
TYPE_FRACTION = 0x06
# The 'data' holds a dynamic ResTable_ref, which needs to be
# resolved before it can be used like a TYPE_REFERENCE.
TYPE_DYNAMIC_REFERENCE = 0x07
# The 'data' holds an attribute resource identifier, which needs to be resolved
# before it can be used like a TYPE_ATTRIBUTE.
TYPE_DYNAMIC_ATTRIBUTE = 0x08
# Beginning of integer flavors...
TYPE_FIRST_INT = 0x10
# The 'data' is a raw integer value of the form n..n.
TYPE_INT_DEC = 0x10
# The 'data' is a raw integer value of the form 0xn..n.
TYPE_INT_HEX = 0x11
# The 'data' is either 0 or 1, for input "false" or "true" respectively.
TYPE_INT_BOOLEAN = 0x12
# Beginning of color integer flavors...
TYPE_FIRST_COLOR_INT = 0x1c
# The 'data' is a raw integer value of the form #aarrggbb.
TYPE_INT_COLOR_ARGB8 = 0x1c
# The 'data' is a raw integer value of the form #rrggbb.
TYPE_INT_COLOR_RGB8 = 0x1d
# The 'data' is a raw integer value of the form #argb.
TYPE_INT_COLOR_ARGB4 = 0x1e
# The 'data' is a raw integer value of the form #rgb.
TYPE_INT_COLOR_RGB4 = 0x1f
# ...end of integer flavors.
TYPE_LAST_COLOR_INT = 0x1f
# ...end of integer flavors.
TYPE_LAST_INT = 0x1f


# Constants for ARSC Files
# see http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#215
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

RES_XML_FIRST_CHUNK_TYPE    = 0x0100
RES_XML_START_NAMESPACE_TYPE= 0x0100
RES_XML_END_NAMESPACE_TYPE  = 0x0101
RES_XML_START_ELEMENT_TYPE  = 0x0102
RES_XML_END_ELEMENT_TYPE    = 0x0103
RES_XML_CDATA_TYPE          = 0x0104
RES_XML_LAST_CHUNK_TYPE     = 0x017f

RES_XML_RESOURCE_MAP_TYPE   = 0x0180

RES_TABLE_PACKAGE_TYPE      = 0x0200
RES_TABLE_TYPE_TYPE         = 0x0201
RES_TABLE_TYPE_SPEC_TYPE    = 0x0202
RES_TABLE_LIBRARY_TYPE      = 0x0203

# Flags in the STRING Section
SORTED_FLAG = 1 << 0
UTF8_FLAG = 1 << 8

# Position of the fields inside an attribute
ATTRIBUTE_IX_NAMESPACE_URI = 0
ATTRIBUTE_IX_NAME = 1
ATTRIBUTE_IX_VALUE_STRING = 2
ATTRIBUTE_IX_VALUE_TYPE = 3
ATTRIBUTE_IX_VALUE_DATA = 4
ATTRIBUTE_LENGHT = 5

# Internally used state variables for AXMLParser
START_DOCUMENT = 0
END_DOCUMENT = 1
START_TAG = 2
END_TAG = 3
TEXT = 4


RADIX_MULTS = [0.00390625, 3.051758E-005, 1.192093E-007, 4.656613E-010]
DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]

COMPLEX_UNIT_MASK = 0x0F


class ResParserError(Exception):
    """Exception for the parsers"""
    pass


def complexToFloat(xcomplex):
    """
    Convert a complex unit into float
    """
    return float(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]


class StringBlock:
    """
    StringBlock is a CHUNK inside an AXML File: `ResStringPool_header`
    It contains all strings, which are used by referecing to ID's

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#436
    """
    def __init__(self, buff, header):
        """
        :param buff: buffer which holds the string block
        :param header: a instance of :class:`~ARSCHeader`
        """
        self._cache = {}
        self.header = header
        # We already read the header (which was chunk_type and chunk_size
        # Now, we read the string_count:
        self.stringCount = unpack('<I', buff.read(4))[0]
        # style_count
        self.styleCount = unpack('<I', buff.read(4))[0]

        # flags
        self.flags = unpack('<I', buff.read(4))[0]
        self.m_isUTF8 = ((self.flags & UTF8_FLAG) != 0)

        # string_pool_offset
        # The string offset is counted from the beginning of the string section
        self.stringsOffset = unpack('<I', buff.read(4))[0]
        # style_pool_offset
        # The styles offset is counted as well from the beginning of the string section
        self.stylesOffset = unpack('<I', buff.read(4))[0]

        # Check if they supplied a stylesOffset even if the count is 0:
        if self.styleCount == 0 and self.stylesOffset > 0:
            print("Styles Offset given, but styleCount is zero. "
                     "This is not a problem but could indicate packers.")

        self.m_stringOffsets = []
        self.m_styleOffsets = []
        self.m_charbuff = ""
        self.m_styles = []

        # Next, there is a list of string following.
        # This is only a list of offsets (4 byte each)
        for i in range(self.stringCount):
            self.m_stringOffsets.append(unpack('<I', buff.read(4))[0])

        # And a list of styles
        # again, a list of offsets
        for i in range(self.styleCount):
            self.m_styleOffsets.append(unpack('<I', buff.read(4))[0])

        # FIXME it is probably better to parse n strings and not calculate the size
        size = self.header.size - self.stringsOffset

        # if there are styles as well, we do not want to read them too.
        # Only read them, if no
        if self.stylesOffset != 0 and self.styleCount != 0:
            size = self.stylesOffset - self.stringsOffset

        if (size % 4) != 0:
            print("Size of strings is not aligned by four bytes.")

        self.m_charbuff = buff.read(size)

        if self.stylesOffset != 0 and self.styleCount != 0:
            size = self.header.size - self.stylesOffset

            if (size % 4) != 0:
                print("Size of styles is not aligned by four bytes.")

            for i in range(0, size // 4):
                self.m_styles.append(unpack('<I', buff.read(4))[0])

    def __repr__(self):
        return "<StringPool #strings={}, #styles={}, UTF8={}>".format(self.stringCount, self.styleCount, self.m_isUTF8)

    def __getitem__(self, idx):
        """
        Returns the string at the index in the string table
        """
        return self.getString(idx)

    def __len__(self):
        """
        Get the number of strings stored in this table
        """
        return self.stringCount

    def __iter__(self):
        """
        Iterable over all strings
        """
        for i in range(self.stringCount):
            yield self.getString(i)

    def getString(self, idx):
        """
        Return the string at the index in the string table

        :param idx: index in the string table
        :return: str
        """
        if idx in self._cache:
            return self._cache[idx]

        if idx < 0 or not self.m_stringOffsets or idx > self.stringCount:
            return ""

        offset = self.m_stringOffsets[idx]

        if self.m_isUTF8:
            self._cache[idx] = self._decode8(offset)
        else:
            self._cache[idx] = self._decode16(offset)

        return self._cache[idx]

    def getStyle(self, idx):
        """
        Return the style associated with the index

        :param idx: index of the style
        :return:
        """
        return self.m_styles[idx]

    def _decode8(self, offset):
        """
        Decode an UTF-8 String at the given offset

        :param offset: offset of the string inside the data
        :return: str
        """
        # UTF-8 Strings contain two lengths, as they might differ:
        # 1) the UTF-16 length
        str_len, skip = self._decode_length(offset, 1)
        offset += skip

        # 2) the utf-8 string length
        encoded_bytes, skip = self._decode_length(offset, 1)
        offset += skip

        data = self.m_charbuff[offset: offset + encoded_bytes]

        if self.m_charbuff[offset + encoded_bytes] != 0:
            raise ResParserError("UTF-8 String is not null terminated! At offset={}".format(offset))

        return self._decode_bytes(data, 'utf-8', str_len)

    def _decode16(self, offset):
        """
        Decode an UTF-16 String at the given offset

        :param offset: offset of the string inside the data
        :return: str
        """
        str_len, skip = self._decode_length(offset, 2)
        offset += skip

        # The len is the string len in utf-16 units
        encoded_bytes = str_len * 2

        data = self.m_charbuff[offset: offset + encoded_bytes]

        if self.m_charbuff[offset + encoded_bytes:offset + encoded_bytes + 2] != b"\x00\x00":
            raise ResParserError("UTF-16 String is not null terminated! At offset={}".format(offset))

        return self._decode_bytes(data, 'utf-16', str_len)

    @staticmethod
    def _decode_bytes(data, encoding, str_len):
        """
        Generic decoding with length check.
        The string is decoded from bytes with the given encoding, then the length
        of the string is checked.
        The string is decoded using the "replace" method.

        :param data: bytes
        :param encoding: encoding name ("utf-8" or "utf-16")
        :param str_len: length of the decoded string
        :return: str
        """
        string = data.decode(encoding, 'replace')
        if len(string) != str_len:
            print("invalid decoded string length")
        return string

    def _decode_length(self, offset, sizeof_char):
        """
        Generic Length Decoding at offset of string

        The method works for both 8 and 16 bit Strings.
        Length checks are enforced:
        * 8 bit strings: maximum of 0x7FFF bytes (See
        http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#692)
        * 16 bit strings: maximum of 0x7FFFFFF bytes (See
        http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#670)

        :param offset: offset into the string data section of the beginning of
        the string
        :param sizeof_char: number of bytes per char (1 = 8bit, 2 = 16bit)
        :returns: tuple of (length, read bytes)
        """
        sizeof_2chars = sizeof_char << 1
        fmt = "<2{}".format('B' if sizeof_char == 1 else 'H')
        highbit = 0x80 << (8 * (sizeof_char - 1))

        length1, length2 = unpack(fmt, self.m_charbuff[offset:(offset + sizeof_2chars)])

        if (length1 & highbit) != 0:
            length = ((length1 & ~highbit) << (8 * sizeof_char)) | length2
            size = sizeof_2chars
        else:
            length = length1
            size = sizeof_char

        # These are true asserts, as the size should never be less than the values
        if sizeof_char == 1:
            assert length <= 0x7FFF, "length of UTF-8 string is too large! At offset={}".format(offset)
        else:
            assert length <= 0x7FFFFFFF, "length of UTF-16 string is too large!  At offset={}".format(offset)

        return length, size

    def show(self):
        """
        Print some information on stdout about the string table
        """
        print("StringBlock(stringsCount=0x%x, "
              "stringsOffset=0x%x, "
              "stylesCount=0x%x, "
              "stylesOffset=0x%x, "
              "flags=0x%x"
              ")" % (self.stringCount,
                     self.stringsOffset,
                     self.styleCount,
                     self.stylesOffset,
                     self.flags))

        if self.stringCount > 0:
            print()
            print("String Table: ")
            for i, s in enumerate(self):
                print("{:08d} {}".format(i, repr(s)))

        if self.styleCount > 0:
            print()
            print("Styles Table: ")
            for i in range(self.styleCount):
                print("{:08d} {}".format(i, repr(self.getStyle(i))))

class SV:

    def __init__(self, size, buff):
        self.__size = size
        self.__value = unpack(self.__size, buff)[0]

    def _get(self):
        return pack(self.__size, self.__value)

    def __str__(self):
        return "0x%x" % self.__value

    def __int__(self):
        return self.__value

    def get_value_buff(self):
        return self._get()

    def get_value(self):
        return self.__value

    def set_value(self, attr):
        self.__value = attr


class BuffHandle:
    """
    BuffHandle is a wrapper around bytes.
    It gives the ability to jump in the byte stream, just like with BytesIO.
    """

    def __init__(self, buff):
        self.__buff = bytearray(buff)
        self.__idx = 0

    def __getitem__(self, item):
        """
        Get the byte at the position `item`

        :param int item: offset in the buffer
        :returns: byte at the position
        :rtype: int
        """
        return self.__buff[item]

    def __len__(self):
        return self.size()

    def size(self):
        """
        Get the total size of the buffer

        :rtype: int
        """
        return len(self.__buff)

    def length_buff(self):
        """
        Alias for :meth:`size`
        """
        return self.size()

    def set_idx(self, idx):
        """
        Set the current offset in the buffer

        :param int idx: offset to set
        """
        self.__idx = idx

    def get_idx(self):
        """
        Get the current offset in the buffer

        :rtype: int
        """
        return self.__idx

    def add_idx(self, idx):
        """
        Advance the current offset by `idx`

        :param int idx: number of bytes to advance
        """
        self.__idx += idx

    def tell(self):
        """
        Alias for :meth:`get_idx`.

        :rtype: int
        """
        return self.__idx

    def readNullString(self, size):
        """
        Read a String with length `size` at the current offset

        :param int size: length of the string
        :rtype: bytearray
        """
        data = self.read(size)
        return data

    def read_b(self, size):
        """
        Read bytes with length `size` without incrementing the current offset

        :param int size: length to read in bytes
        :rtype: bytearray
        """
        return self.__buff[self.__idx:self.__idx + size]

    def peek(self, size):
        """
        Alias for :meth:`read_b`
        """
        return self.read_b(size)

    def read_at(self, offset, size):
        """
        Read bytes from the given offset with length `size` without incrementing
        the current offset

        :param int offset: offset to start reading
        :param int size: length of bytes to read
        :rtype: bytearray
        """
        return self.__buff[offset:offset + size]

    def readat(self, off):
        """
        Read all bytes from the start of `off` until the end of the buffer

        This method can be used to determine a checksum of a buffer from a given
        point on.

        :param int off: starting offset
        :rtype: bytearray
        """
        if isinstance(off, SV):
            off = off.value

        return self.__buff[off:]

    def read(self, size):
        """
        Read from the current offset a total number of `size` bytes
        and increment the offset by `size`

        :param int size: length of bytes to read
        :rtype: bytearray
        """
        if isinstance(size, SV):
            size = size.value

        buff = self.__buff[self.__idx:self.__idx + size]
        self.__idx += size

        return buff

    def end(self):
        """
        Test if the current offset is at the end or over the buffer boundary

        :rtype: bool
        """
        return self.__idx >= len(self.__buff)

    def get_buff(self):
        """
        Return the whole buffer

        :rtype: bytearray
        """
        return self.__buff

    def set_buff(self, buff):
        """
        Overwrite the current buffer with the content of `buff`

        :param bytearray buff: the new buffer
        """
        self.__buff = buff

    def save(self, filename):
        """
        Save the current buffer to `filename`

        Exisiting files with the same name will be overwritten.

        :param str filename: the name of the file to save to
        """
        with open(filename, "wb") as fd:
            fd.write(self.__buff)


class AXMLParser:
    """
    AXMLParser reads through all chunks in the AXML file
    and implements a state machine to return information about
    the current chunk, which can then be read by :class:`~AXMLPrinter`.

    An AXML file is a file which contains multiple chunks of data, defined
    by the `ResChunk_header`.
    There is no real file magic but as the size of the first header is fixed
    and the `type` of the `ResChunk_header` is set to `RES_XML_TYPE`, a file
    will usually start with `0x03000800`.
    But there are several examples where the `type` is set to something
    else, probably in order to fool parsers.

    Typically the AXMLParser is used in a loop which terminates if `m_event` is set to `END_DOCUMENT`.
    You can use the `next()` function to get the next chunk.
    Note that not all chunk types are yielded from the iterator! Some chunks are processed in
    the AXMLParser only.
    The parser will set `is_valid()` to False if it parses something not valid.
    Messages what is wrong are logged.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#563
    """
    def __init__(self, raw_buff):
        self._reset()

        self._valid = True
        self.axml_tampered = False
        self.buff = BuffHandle(raw_buff)

        # Minimum is a single ARSCHeader, which would be a strange edge case...
        if self.buff.size() < 8:
            print("Filesize is too small to be a valid AXML file! Filesize: {}".format(self.buff.size()))
            self._valid = False
            return

        # This would be even stranger, if an AXML file is larger than 4GB...
        # But this is not possible as the maximum chunk size is a unsigned 4 byte int.
        if self.buff.size() > 0xFFFFFFFF:
            print("Filesize is too large to be a valid AXML file! Filesize: {}".format(self.buff.size()))
            self._valid = False
            return

        try:
            axml_header = ARSCHeader(self.buff)
        except ResParserError as e:
            print("Error parsing first resource header: %s", e)
            self._valid = False
            return

        self.filesize = axml_header.size

        if axml_header.header_size == 28024:
            # Can be a common error: the file is not an AXML but a plain XML
            # The file will then usually start with '<?xm' / '3C 3F 78 6D'
            print("Header size is 28024! Are you trying to parse a plain XML file?")

        if axml_header.header_size != 8:
            print("This does not look like an AXML file. header size does not equal 8! header size = {}".format(axml_header.header_size))
            self._valid = False
            return

        if self.filesize > self.buff.size():
            print("This does not look like an AXML file. Declared filesize does not match real size: {} vs {}".format(self.filesize, self.buff.size()))
            self._valid = False
            return

        if self.filesize < self.buff.size():
            # The file can still be parsed up to the point where the chunk should end.
            self.axml_tampered = True
            print("Declared filesize ({}) is smaller than total file size ({}). "
                        "Was something appended to the file? Trying to parse it anyways.".format(self.filesize, self.buff.size()))

        # Not that severe of an error, we have plenty files where this is not
        # set correctly
        if axml_header.type != RES_XML_TYPE:
            self.axml_tampered = True
            print("AXML file has an unusual resource type! "
                        "Malware likes to to such stuff to anti androguard! "
                        "But we try to parse it anyways. Resource Type: 0x{:04x}".format(axml_header.type))

        # Now we parse the STRING POOL
        try:
            header = ARSCHeader(self.buff, expected_type=RES_STRING_POOL_TYPE)
        except ResParserError as e:
            print("Error parsing resource header of string pool: %s", e)
            self._valid = False
            return

        if header.header_size != 0x1C:
            print("This does not look like an AXML file. String chunk header size does not equal 28! header size = {}".format(header.header_size))
            self._valid = False
            return

        self.sb = StringBlock(self.buff, header)

        # Stores resource ID mappings, if any
        self.m_resourceIDs = []

        # Store a list of prefix/uri mappings encountered
        self.namespaces = []

    def is_valid(self):
        """
        Get the state of the AXMLPrinter.
        if an error happend somewhere in the process of parsing the file,
        this flag is set to False.
        """
        return self._valid

    def _reset(self):
        self.m_event = -1
        self.m_lineNumber = -1
        self.m_name = -1
        self.m_namespaceUri = -1
        self.m_attributes = []
        self.m_idAttribute = -1
        self.m_classAttribute = -1
        self.m_styleAttribute = -1

    def __next__(self):
        self._do_next()
        return self.m_event

    def _do_next(self):
        if self.m_event == END_DOCUMENT:
            return

        self._reset()
        while self._valid:
            # Stop at the declared filesize or at the end of the file
            if self.buff.end() or self.buff.get_idx() == self.filesize:
                self.m_event = END_DOCUMENT
                break

            # Again, we read an ARSCHeader
            try:
                h = ARSCHeader(self.buff)
            except ResParserError as e:
                print("Error parsing resource header: %s", e)
                self._valid = False
                return

            # Special chunk: Resource Map. This chunk might be contained inside
            # the file, after the string pool.
            if h.type == RES_XML_RESOURCE_MAP_TYPE:
                #log.debug("AXML contains a RESOURCE MAP")
                # Check size: < 8 bytes mean that the chunk is not complete
                # Should be aligned to 4 bytes.
                if h.size < 8 or (h.size % 4) != 0:
                    print("Invalid chunk size in chunk XML_RESOURCE_MAP")
                    self._valid = False
                    return

                for i in range((h.size - h.header_size) // 4):
                    self.m_resourceIDs.append(unpack('<L', self.buff.read(4))[0])

                continue

            # Parse now the XML chunks.
            # unknown chunk types might cause problems, but we can skip them!
            if h.type < RES_XML_FIRST_CHUNK_TYPE or h.type > RES_XML_LAST_CHUNK_TYPE:
                # h.size is the size of the whole chunk including the header.
                # We read already 8 bytes of the header, thus we need to
                # subtract them.
                print("Not a XML resource chunk type: 0x{:04x}. Skipping {} bytes".format(h.type, h.size))
                self.buff.set_idx(h.end)
                continue

            # Check that we read a correct header
            if h.header_size != 0x10:
                print("XML Resource Type Chunk header size does not match 16! " \
                "At chunk type 0x{:04x}, declared header size={}, chunk size={}".format(h.type, h.header_size, h.size))
                self._valid = False
                return

            # Line Number of the source file, only used as meta information
            self.m_lineNumber, = unpack('<L', self.buff.read(4))

            # Comment_Index (usually 0xFFFFFFFF)
            self.m_comment_index, = unpack('<L', self.buff.read(4))

            if self.m_comment_index != 0xFFFFFFFF and h.type in [RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE]:
                print("Unhandled Comment at namespace chunk: '{}'".format(self.sb[self.m_comment_index]))

            if h.type == RES_XML_START_NAMESPACE_TYPE:
                prefix, = unpack('<L', self.buff.read(4))
                uri, = unpack('<L', self.buff.read(4))

                s_prefix = self.sb[prefix]
                s_uri = self.sb[uri]

                #log.debug("Start of Namespace mapping: prefix {}: '{}' --> uri {}: '{}'".format(prefix, s_prefix, uri, s_uri))

                if s_uri == '':
                    print("Namespace prefix '{}' resolves to empty URI. "
                                "This might be a packer.".format(s_prefix))

                if (prefix, uri) in self.namespaces:
                    print("Namespace mapping ({}, {}) already seen! "
                             "This is usually not a problem but could indicate packers or broken AXML compilers.".format(prefix, uri))
                self.namespaces.append((prefix, uri))

                # We can continue with the next chunk, as we store the namespace
                # mappings for each tag
                continue

            if h.type == RES_XML_END_NAMESPACE_TYPE:
                # END_PREFIX contains again prefix and uri field
                prefix, = unpack('<L', self.buff.read(4))
                uri, = unpack('<L', self.buff.read(4))

                # We remove the last namespace mapping matching
                if (prefix, uri) in self.namespaces:
                    self.namespaces.remove((prefix, uri))
                else:
                    print("Reached a NAMESPACE_END without having the namespace stored before? "
                                "Prefix ID: {}, URI ID: {}".format(prefix, uri))

                # We can continue with the next chunk, as we store the namespace
                # mappings for each tag
                continue

            # START_TAG is the start of a new tag.
            if h.type == RES_XML_START_ELEMENT_TYPE:
                # The TAG consists of some fields:
                # * (chunk_size, line_number, comment_index - we read before)
                # * namespace_uri
                # * name
                # * flags
                # * attribute_count
                # * class_attribute
                # After that, there are two lists of attributes, 20 bytes each

                # Namespace URI (String ID)
                self.m_namespaceUri, = unpack('<L', self.buff.read(4))
                # Name of the Tag (String ID)
                self.m_name, = unpack('<L', self.buff.read(4))
                # FIXME: Flags
                _ = self.buff.read(4)
                # Attribute Count
                attributeCount, = unpack('<L', self.buff.read(4))
                # Class Attribute
                self.m_classAttribute, = unpack('<L', self.buff.read(4))

                self.m_idAttribute = (attributeCount >> 16) - 1
                self.m_attribute_count = attributeCount & 0xFFFF
                self.m_styleAttribute = (self.m_classAttribute >> 16) - 1
                self.m_classAttribute = (self.m_classAttribute & 0xFFFF) - 1

                # Now, we parse the attributes.
                # Each attribute has 5 fields of 4 byte
                for i in range(0, self.m_attribute_count * ATTRIBUTE_LENGHT):
                    # Each field is linearly parsed into the array
                    # Each Attribute contains:
                    # * Namespace URI (String ID)
                    # * Name (String ID)
                    # * Value
                    # * Type
                    # * Data
                    self.m_attributes.append(unpack('<L', self.buff.read(4))[0])

                # Then there are class_attributes
                for i in range(ATTRIBUTE_IX_VALUE_TYPE, len(self.m_attributes), ATTRIBUTE_LENGHT):
                    self.m_attributes[i] = self.m_attributes[i] >> 24

                self.m_event = START_TAG
                break

            if h.type == RES_XML_END_ELEMENT_TYPE:
                self.m_namespaceUri, = unpack('<L', self.buff.read(4))
                self.m_name, = unpack('<L', self.buff.read(4))

                self.m_event = END_TAG
                break

            if h.type == RES_XML_CDATA_TYPE:
                # The CDATA field is like an attribute.
                # It contains an index into the String pool
                # as well as a typed value.
                # usually, this typed value is set to UNDEFINED

                # ResStringPool_ref data --> uint32_t index
                self.m_name, = unpack('<L', self.buff.read(4))

                # Res_value typedData:
                # uint16_t size
                # uint8_t res0 -> always zero
                # uint8_t dataType
                # uint32_t data
                # For now, we ingore these values
                size, res0, dataType, data = unpack("<HBBL", self.buff.read(8))

                # #log.debug("found a CDATA Chunk: "
                #           "index={: 6d}, size={: 4d}, res0={: 4d}, dataType={: 4d}, data={: 4d}".format(self.m_name,
                #                                                                                         size,
                #                                                                                         res0,
                #                                                                                         dataType,
                #                                                                                         data))

                self.m_event = TEXT
                break

            # Still here? Looks like we read an unknown XML header, try to skip it...
            print("Unknown XML Chunk: 0x{:04x}, skipping {} bytes.".format(h.type, h.size))
            self.buff.set_idx(h.end)

    @property
    def name(self):
        """
        Return the String assosciated with the tag name
        """
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG):
            return ''

        return self.sb[self.m_name]

    @property
    def comment(self):
        """
        Return the comment at the current position or None if no comment is given

        This works only for Tags, as the comments of Namespaces are silently dropped.
        Currently, there is no way of retrieving comments of namespaces.
        """
        if self.m_comment_index == 0xFFFFFFFF:
            return None

        return self.sb[self.m_comment_index]

    @property
    def namespace(self):
        """
        Return the Namespace URI (if any) as a String for the current tag
        """
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG):
            return ''

        # No Namespace
        if self.m_namespaceUri == 0xFFFFFFFF:
            return ''

        return self.sb[self.m_namespaceUri]

    @property
    def nsmap(self):
        """
        Returns the current namespace mapping as a dictionary

        there are several problems with the map and we try to guess a few
        things here:

        1) a URI can be mapped by many prefixes, so it is to decide which one to take
        2) a prefix might map to an empty string (some packers)
        3) uri+prefix mappings might be included several times
        4) prefix might be empty
        """

        NSMAP = dict()
        # solve 3) by using a set
        for k, v in set(self.namespaces):
            s_prefix = self.sb[k]
            s_uri = self.sb[v]
            # Solve 2) & 4) by not including
            if s_uri != "" and s_prefix != "":
                # solve 1) by using the last one in the list
                NSMAP[s_prefix] = s_uri

        return NSMAP

    @property
    def text(self):
        """
        Return the String assosicated with the current text
        """
        if self.m_name == -1 or self.m_event != TEXT:
            return ''

        return self.sb[self.m_name]

    def getName(self):
        """
        Legacy only!
        use :py:attr:`~androguard.core.bytecodes.AXMLParser.name` instead
        """
        return self.name

    def getText(self):
        """
        Legacy only!
        use :py:attr:`~androguard.core.bytecodes.AXMLParser.text` instead
        """
        return self.text

    def getPrefix(self):
        """
        Legacy only!
        use :py:attr:`~androguard.core.bytecodes.AXMLParser.namespace` instead
        """
        return self.namespace

    def _get_attribute_offset(self, index):
        """
        Return the start inside the m_attributes array for a given attribute
        """
        if self.m_event != START_TAG:
            print("Current event is not START_TAG.")

        offset = index * ATTRIBUTE_LENGHT
        if offset >= len(self.m_attributes):
            print("Invalid attribute index")

        return offset

    def getAttributeCount(self):
        """
        Return the number of Attributes for a Tag
        or -1 if not in a tag
        """
        if self.m_event != START_TAG:
            return -1

        return self.m_attribute_count

    def getAttributeUri(self, index):
        """
        Returns the numeric ID for the namespace URI of an attribute
        """
        offset = self._get_attribute_offset(index)
        uri = self.m_attributes[offset + ATTRIBUTE_IX_NAMESPACE_URI]

        return uri

    def getAttributeNamespace(self, index):
        """
        Return the Namespace URI (if any) for the attribute
        """
        uri = self.getAttributeUri(index)

        # No Namespace
        if uri == 0xFFFFFFFF:
            return ''

        return self.sb[uri]

    def getAttributeName(self, index):
        """
        Returns the String which represents the attribute name
        """
        offset = self._get_attribute_offset(index)
        name = self.m_attributes[offset + ATTRIBUTE_IX_NAME]

        res = self.sb[name]
        # If the result is a (null) string, we need to look it up.
        # if not res:
        #     attr = self.m_resourceIDs[name]
        #     if attr in public.SYSTEM_RESOURCES['attributes']['inverse']:
        #         res = 'android:' + public.SYSTEM_RESOURCES['attributes']['inverse'][attr]
        #     else:
        #         # Attach the HEX Number, so for multiple missing attributes we do not run
        #         # into problems.
        #         res = 'android:UNKNOWN_SYSTEM_ATTRIBUTE_{:08x}'.format(attr)

        return res

    def getAttributeValueType(self, index):
        """
        Return the type of the attribute at the given index

        :param index: index of the attribute
        """
        offset = self._get_attribute_offset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]

    def getAttributeValueData(self, index):
        """
        Return the data of the attribute at the given index

        :param index: index of the attribute
        """
        offset = self._get_attribute_offset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_DATA]

    def getAttributeValue(self, index):
        """
        This function is only used to look up strings
        All other work is done by
        :func:`~androguard.core.bytecodes.axml.format_value`
        # FIXME should unite those functions
        :param index: index of the attribute
        :return:
        """
        offset = self._get_attribute_offset(index)
        valueType = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]
        if valueType == TYPE_STRING:
            valueString = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_STRING]
            return self.sb[valueString]
        return ''


def format_value(_type, _data, lookup_string=lambda ix: "<string>"):
    """
    Format a value based on type and data.
    By default, no strings are looked up and "<string>" is returned.
    You need to define `lookup_string` in order to actually lookup strings from
    the string table.

    :param _type: The numeric type of the value
    :param _data: The numeric data of the value
    :param lookup_string: A function how to resolve strings from integer IDs
    """

    # Function to prepend android prefix for attributes/references from the
    # android library
    fmt_package = lambda x: "android:" if x >> 24 == 1 else ""

    # Function to represent integers
    fmt_int = lambda x: (0x7FFFFFFF & x) - 0x80000000 if x > 0x7FFFFFFF else x

    if _type == TYPE_STRING:
        return lookup_string(_data)

    elif _type == TYPE_ATTRIBUTE:
        return "?{}{:08X}".format(fmt_package(_data), _data)

    elif _type == TYPE_REFERENCE:
        return "@{}{:08X}".format(fmt_package(_data), _data)

    elif _type == TYPE_FLOAT:
        return "%f" % unpack("=f", pack("=L", _data))[0]

    elif _type == TYPE_INT_HEX:
        return "0x%08X" % _data

    elif _type == TYPE_INT_BOOLEAN:
        if _data == 0:
            return "false"
        return "true"

    elif _type == TYPE_DIMENSION:
        return "{:f}{}".format(complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])

    elif _type == TYPE_FRACTION:
        return "{:f}{}".format(complexToFloat(_data) * 100, FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])

    elif TYPE_FIRST_COLOR_INT <= _type <= TYPE_LAST_COLOR_INT:
        return "#%08X" % _data

    elif TYPE_FIRST_INT <= _type <= TYPE_LAST_INT:
        return "%d" % fmt_int(_data)

    return "<0x{:X}, type 0x{:02X}>".format(_data, _type)


class AXMLPrinter:
    """
    Converter for AXML Files into a lxml ElementTree, which can easily be
    converted into XML.

    A Reference Implementation can be found at http://androidxref.com/9.0.0_r3/xref/frameworks/base/tools/aapt/XMLNode.cpp
    """
    __charrange = None
    __replacement = None

    def __init__(self, raw_buff):
        self.axml = AXMLParser(raw_buff)

        self.root = None
        self.packerwarning = False
        cur = []

        while self.axml.is_valid():
            _type = next(self.axml)

            if _type == START_TAG:
                uri = self._print_namespace(self.axml.namespace)
                uri, name = self._fix_name(uri, self.axml.name)
                tag = "{}{}".format(uri, name)

                comment = self.axml.comment
                if comment:
                    if self.root is None:
                        print("Can not attach comment with content '{}' without root!".format(comment))
                    else:
                        cur[-1].append(etree.Comment(comment))

                #log.debug("START_TAG: {} (line={})".format(tag, self.axml.m_lineNumber))
                elem = etree.Element(tag, nsmap=self.axml.nsmap)

                for i in range(self.axml.getAttributeCount()):
                    uri = self._print_namespace(self.axml.getAttributeNamespace(i))
                    uri, name = self._fix_name(uri, self.axml.getAttributeName(i))
                    value = self._fix_value(self._get_attribute_value(i))

                    #log.debug("found an attribute: {}{}='{}'".format(uri, name, value.encode("utf-8")))
                    if "{}{}".format(uri, name) in elem.attrib:
                        print("Duplicate attribute '{}{}'! Will overwrite!".format(uri, name))
                    elem.set("{}{}".format(uri, name), value)

                if self.root is None:
                    self.root = elem
                else:
                    if not cur:
                        # looks like we lost the root?
                        print("No more elements available to attach to! Is the XML malformed?")
                        break
                    cur[-1].append(elem)
                cur.append(elem)

            if _type == END_TAG:
                if not cur:
                    print("Too many END_TAG! No more elements available to attach to!")

                name = self.axml.name
                uri = self._print_namespace(self.axml.namespace)
                tag = "{}{}".format(uri, name)
                if cur[-1].tag != tag:
                    print("Closing tag '{}' does not match current stack! At line number: {}. Is the XML malformed?".format(self.axml.name, self.axml.m_lineNumber))
                cur.pop()
            if _type == TEXT:
                #log.debug("TEXT for {}".format(cur[-1]))
                cur[-1].text = self.axml.text
            if _type == END_DOCUMENT:
                # Check if all namespace mappings are closed
                if len(self.axml.namespaces) > 0:
                    print("Not all namespace mappings were closed! Malformed AXML?")
                break

    def get_buff(self):
        """
        Returns the raw XML file without prettification applied.

        :returns: bytes, encoded as UTF-8
        """
        return self.get_xml(pretty=False)

    def get_xml(self, pretty=True):
        """
        Get the XML as an UTF-8 string

        :returns: bytes encoded as UTF-8
        """
        return etree.tostring(self.root, encoding="utf-8", pretty_print=pretty)

    def get_xml_obj(self):
        """
        Get the XML as an ElementTree object

        :returns: :class:`lxml.etree.Element`
        """
        return self.root

    def is_valid(self):
        """
        Return the state of the AXMLParser.
        If this flag is set to False, the parsing has failed, thus
        the resulting XML will not work or will even be empty.
        """
        return self.axml.is_valid()

    def is_packed(self):
        """
        Returns True if the AXML is likely to be packed

        Packers do some weird stuff and we try to detect it.
        Sometimes the files are not packed but simply broken or compiled with
        some broken version of a tool.
        Some file corruption might also be appear to be a packed file.

        :returns: True if packer detected, False otherwise
        """
        return self.packerwarning

    def _get_attribute_value(self, index):
        """
        Wrapper function for format_value to resolve the actual value of an attribute in a tag
        :param index: index of the current attribute
        :return: formatted value
        """
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)

        return format_value(_type, _data, lambda _: self.axml.getAttributeValue(index))

    def _fix_name(self, prefix, name):
        """
        Apply some fixes to element named and attribute names.
        Try to get conform to:
        > Like element names, attribute names are case-sensitive and must start with a letter or underscore.
        > The rest of the name can contain letters, digits, hyphens, underscores, and periods.
        See: https://msdn.microsoft.com/en-us/library/ms256152(v=vs.110).aspx

        This function tries to fix some broken namespace mappings.
        In some cases, the namespace prefix is inside the name and not in the prefix field.
        Then, the tag name will usually look like 'android:foobar'.
        If and only if the namespace prefix is inside the namespace mapping and the actual prefix field is empty,
        we will strip the prefix from the attribute name and return the fixed prefix URI instead.
        Otherwise replacement rules will be applied.

        The replacement rules work in that way, that all unwanted characters are replaced by underscores.
        In other words, all characters except the ones listed above are replaced.

        :param name: Name of the attribute or tag
        :param prefix: The existing prefix uri as found in the AXML chunk
        :return: a fixed version of prefix and name
        :rtype: tuple
        """
        if not name[0].isalpha() and name[0] != "_":
            print("Invalid start for name '{}'. "
                        "XML name must start with a letter.".format(name))
            self.packerwarning = True
            name = "_{}".format(name)
        if name.startswith("android:") and prefix == '' and 'android' in self.axml.nsmap:
            # Seems be a common thing...
            print("Name '{}' starts with 'android:' prefix but 'android' is a known prefix. Replacing prefix.".format(name))
            prefix = self._print_namespace(self.axml.nsmap['android'])
            name = name[len("android:"):]
            # It looks like this is some kind of packer... Not sure though.
            self.packerwarning = True
        elif ":" in name and prefix == '':
            self.packerwarning = True
            embedded_prefix, new_name = name.split(":", 1)
            if embedded_prefix in self.axml.nsmap:
                print("Prefix '{}' is in namespace mapping, assume that it is a prefix.")
                prefix = self._print_namespace(self.axml.nsmap[embedded_prefix])
                name = new_name
            else:
                # Print out an extra warning
                print("Confused: name contains a unknown namespace prefix: '{}'. "
                            "This is either a broken AXML file or some attempt to break stuff.".format(name))
        if not re.match(r"^[a-zA-Z0-9._-]*$", name):
            print("Name '{}' contains invalid characters!".format(name))
            self.packerwarning = True
            name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)

        return prefix, name

    def _fix_value(self, value):
        """
        Return a cleaned version of a value
        according to the specification:
        > Char	   ::=   	#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]

        See https://www.w3.org/TR/xml/#charsets

        :param value: a value to clean
        :return: the cleaned value
        """
        if not self.__charrange or not self.__replacement:
            self.__charrange = re.compile('^[\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]*$')
            self.__replacement = re.compile('[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]')

        # Reading string until \x00. This is the same as aapt does.
        if "\x00" in value:
            self.packerwarning = True
            print("Null byte found in attribute value at position {}: "
                        "Value(hex): '{}'".format(
                value.find("\x00"),
                binascii.hexlify(value.encode("utf-8"))))
            value = value[:value.find("\x00")]

        if not self.__charrange.match(value):
            print("Invalid character in value found. Replacing with '_'.")
            self.packerwarning = True
            value = self.__replacement.sub('_', value)
        return value

    def _print_namespace(self, uri):
        if uri != "":
            uri = "{{{}}}".format(uri)
        return uri


class ARSCHeader:
    """
    Object which contains a Resource Chunk.
    This is an implementation of the `ResChunk_header`.

    It will throw an :class:`ResParserError` if the header could not be read successfully.

    It is not checked if the data is outside the buffer size nor if the current
    chunk fits into the parent chunk (if any)!

    The parameter `expected_type` can be used to immediately check the header for the type or raise a :class:`ResParserError`.
    This is useful if you know what type of chunk must follow.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#196
    :raises: ResParserError
    """

    # This is the minimal size such a header must have. There might be other header data too!
    SIZE = 2 + 2 + 4

    def __init__(self, buff, expected_type=None):
        """
        :param androguard.core.bytecode.BuffHandle buff: the buffer set to the position where the header starts.
        :param int expected_type: the type of the header which is expected.
        """
        self.start = buff.get_idx()
        # Make sure we do not read over the buffer:
        if buff.size() < self.start + self.SIZE:
            raise ResParserError("Can not read over the buffer size! Offset={}".format(self.start))

        self._type, self._header_size, self._size = unpack('<HHL', buff.read(self.SIZE))

        if expected_type and self._type != expected_type:
            raise ResParserError("Header type is not equal the expected type: Got 0x{:04x}, wanted 0x{:04x}".format(self._type, expected_type))

        # Assert that the read data will fit into the chunk.
        # The total size must be equal or larger than the header size
        if self._header_size < self.SIZE:
            raise ResParserError(
                "declared header size is smaller than required size of {}! Offset={}".format(self.SIZE, self.start))
        if self._size < self.SIZE:
            raise ResParserError(
                "declared chunk size is smaller than required size of {}! Offset={}".format(self.SIZE, self.start))
        if self._size < self._header_size:
            raise ResParserError(
                "declared chunk size ({}) is smaller than header size ({})! Offset={}".format(self._size,
                                                                                              self._header_size,
                                                                                              self.start))

    @property
    def type(self):
        """
        Type identifier for this chunk
        """
        return self._type

    @property
    def header_size(self):
        """
        Size of the chunk header (in bytes).  Adding this value to
        the address of the chunk allows you to find its associated data
        (if any).
        """
        return self._header_size

    @property
    def size(self):
        """
        Total size of this chunk (in bytes).  This is the chunkSize plus
        the size of any data associated with the chunk.  Adding this value
        to the chunk allows you to completely skip its contents (including
        any child chunks).  If this value is the same as chunkSize, there is
        no data associated with the chunk.
        """
        return self._size

    @property
    def end(self):
        """
        Get the absolute offset inside the file, where the chunk ends.
        This is equal to `ARSCHeader.start + ARSCHeader.size`.
        """
        return self.start + self.size

    def __repr__(self):
        return "<ARSCHeader idx='0x{:08x}' type='{}' header_size='{}' size='{}'>".format(self.start,
                                                                                         self.type,
                                                                                         self.header_size,
                                                                                         self.size)

