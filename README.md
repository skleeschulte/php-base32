php-base32
==========

PHP base32 encoding/decoding class (RFC 4648 standard and extended hex, Crockford, z-base-32/Zooko)

This class provides static methods to encode and decode data to/from the
following encodings:
- base32 (RFC 4648)
- base32 extended hex (RFC 4648)
- base32 Crockford
- base32 Zooko (z-base-32)

For each encoding, there are methods for encoding/decoding byte-strings and
for encoding/decoding non-negative integers of arbitrary length. To handle
integers of arbitrary length, PHP's BC Math extension is used whenever PHP's
internal integer type is not sufficient to store/process the data.

All exceptions thrown by this class will have an exception code corresponding
to one of the codes defined in the class constants at the beginning of the
class.

This class is designed to be fast and memory efficient and is fully
documented using PHPDoc-blocks.

If you find any bugs or have suggestions for improvements, you are welcome to
create a new issue at https://github.com/skleeschulte/php-base32/issues .
