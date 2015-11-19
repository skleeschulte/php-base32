<?php
/**
 * Copyright (c) 2013 Stefan Kleeschulte
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * @author Stefan Kleeschulte <stefan.kleeschulte@smk.biz>
 * @copyright Copyright (c) 2013, Stefan Kleeschulte
 * @license http://opensource.org/licenses/MIT MIT
 */

namespace SKleeschulte;

use \InvalidArgumentException;
use \RuntimeException;
use \UnexpectedValueException;

/**
 * Base32 encoding and decoding class.
 * 
 * This class provides static methods to encode and decode data to/from the
 * following encodings:
 * - base32 (RFC 4648)
 * - base32 extended hex (RFC 4648)
 * - base32 Crockford
 * - base32 Zooko (z-base-32)
 * 
 * For each encoding, there are methods for encoding/decoding byte-strings and
 * for encoding/decoding non-negative integers of arbitrary length. To handle
 * integers of arbitrary length, PHP's BC Math extension is used whenever PHP's
 * internal integer type is not sufficient to store/process the data.
 * 
 * All exceptions thrown by this class will have an exception code corresponding
 * to one of the codes defined in the class constants at the beginning of the
 * class.
 * 
 * This class is designed to be fast and memory efficient and is fully
 * documented using PHPDoc-blocks.
 * 
 * If you find any bugs or have suggestions for improvements, you are welcome to
 * create a new issue at
 * {@link https://github.com/skleeschulte/php-base32/issues}.
 * 
 * @version 0.0.2
 * @author Stefan Kleeschulte <stefan.kleeschulte@smk.biz>
 * @link https://github.com/skleeschulte/php-base32 Git repository
 */
class Base32 {
    
    /**
     * Exception code.
     * A variable which is no non-negative integer and no string representation
     * of a non-negative integer was passed to a method expecting a non-negative
     * integer.
     */
    const E_NO_NON_NEGATIVE_INT = 1;
    
    /**
     * Exception code.
     * An empty byte-string was passed to a method which expects a non empty
     * byte-string.
     */
    const E_EMPTY_BYTESTRING = 2;
    
    /**
     * Exception code.
     * A variable of a type other than string was passed to a method expecting
     * a variable of type string.
     */
    const E_NO_STRING = 3;
    
    /**
     * Exception code.
     * There was an error trying to match a regular expression pattern. This
     * might for example happen if the subject string is too long.
     */
    const E_PATTERN_MATCHING_FAILED = 4;
    
    /**
     * Exception code.
     * The provided string argument does not have the expected syntax (including
     * wrong characters, wrong (padding) length).
     */
    const E_INVALID_SYNTAX = 5;
    
    /**
     * Exception code.
     * An operation needs PHP's BC Math extension, but it is not available.
     */
    const E_NO_BCMATH = 6;
    
    /**
     * Exception code.
     * Supplied Crockford check symbol does not match encoded data.
     */
    const E_CHECKSYMBOL_DOES_NOT_MATCH_DATA = 7;
    
    /**
     * @var string RFC 4648 base32 alphabet
     * @link http://tools.ietf.org/html/rfc4648#page-9
     */
    private static $_commonAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';
    /**
     * @var array Flipped RFC 4648 base32 alphabet
     */
    private static $_commonFlippedAlphabet = array(
        'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, 'E' => 4, 'F' => 5,
        'G' => 6, 'H' => 7, 'I' => 8, 'J' => 9, 'K' => 10, 'L' => 11,
        'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15, 'Q' => 16, 'R' => 17,
        'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23,
        'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29,
        '6' => 30, '7' => 31, '=' => 0
    );
    
    /**
     * @var string RFC 4648 base32 extended hex alphabet
     * @link http://tools.ietf.org/html/rfc4648#page-10
     */
    private static $_hexAlphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV=';
    /**
     * @var array Flipped RFC 4648 base32 extended hex alphabet
     */
    private static $_hexFlippedAlphabet = array(
        '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5,
        '6' => 6, '7' => 7, '8' => 8, '9' => 9, 'A' => 10, 'B' => 11,
        'C' => 12, 'D' => 13, 'E' => 14, 'F' => 15, 'G' => 16, 'H' => 17,
        'I' => 18, 'J' => 19, 'K' => 20, 'L' => 21, 'M' => 22, 'N' => 23,
        'O' => 24, 'P' => 25, 'Q' => 26, 'R' => 27, 'S' => 28, 'T' => 29,
        'U' => 30, 'V' => 31, '=' => 0
    );
    
    /**
     * @var string Crockford base32 alphabet
     * @link http://www.crockford.com/wrmg/base32.html
     */
    private static $_crockfordAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U';
    /**
     * @var array Flipped Crockford base32 alphabet
     */
    private static $_crockfordFlippedAlphabet = array(
        '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5,
        '6' => 6, '7' => 7, '8' => 8, '9' => 9, 'A' => 10, 'B' => 11,
        'C' => 12, 'D' => 13, 'E' => 14, 'F' => 15, 'G' => 16, 'H' => 17,
        'J' => 18, 'K' => 19, 'M' => 20, 'N' => 21, 'P' => 22, 'Q' => 23,
        'R' => 24, 'S' => 25, 'T' => 26, 'V' => 27, 'W' => 28, 'X' => 29,
        'Y' => 30, 'Z' => 31, '*' => 32, '~' => 33, '$' => 34, '=' => 35,
        'U' => 36
    );
    /**
     * @var array Crockford's additional character mapping for decoding
     */
    private static $_crockfordAdditionalCharMapping = array(
        // Small letters from Crockford alphabet.
        'a' => 10, 'b' => 11, 'c' => 12, 'd' => 13, 'e' => 14, 'f' => 15,
        'g' => 16, 'h' => 17, 'j' => 18, 'k' => 19, 'm' => 20, 'n' => 21,
        'p' => 22, 'q' => 23, 'r' => 24, 's' => 25, 't' => 26, 'v' => 27,
        'w' => 28, 'x' => 29, 'y' => 30, 'z' => 31, 'u' => 36,
        // Additional characters.
        'O' => 0, 'o' => 0, 'I' => 1, 'i' => 1, 'L' => 1, 'l' => 1
    );
    
    /**
     * @var string Zooko base32 alphabet
     * @link http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
     */
    private static $_zookoAlphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769';
    /**
     * @var array Flipped Zooko base32 alphabet
     */
    private static $_zookoFlippedAlphabet = array(
        'y' => 0, 'b' => 1, 'n' => 2, 'd' => 3, 'r' => 4, 'f' => 5,
        'g' => 6, '8' => 7, 'e' => 8, 'j' => 9, 'k' => 10, 'm' => 11,
        'c' => 12, 'p' => 13, 'q' => 14, 'x' => 15, 'o' => 16, 't' => 17,
        '1' => 18, 'u' => 19, 'w' => 20, 'i' => 21, 's' => 22, 'z' => 23,
        'a' => 24, '3' => 25, '4' => 26, '5' => 27, 'h' => 28, '7' => 29,
        '6' => 30, '9' => 31
    );
    
    /**
     * Returns the number of bytes in the given string.
     * 
     * @param string $byteString The string whose bytes to count.
     * @return int Number of bytes in given string.
     */
    private static function _byteCount($byteString) {
        if (function_exists('mb_strlen')) {
            return mb_strlen($byteString, '8bit');
        }
        return strlen($byteString);
    }

    /**
     * Returns the bytes of the given string specified by the start and length 
     * parameters. 
     * 
     * @param string $byteString The string from which to extract the bytes.
     * @param int $start Start position.
     * @param int $length Number of bytes to extract.
     * @return string Subset of bytes from given string.
     */
    private static function _extractBytes($byteString, $start, $length) {
        if (function_exists('mb_substr')) {
            return mb_substr($byteString, $start, $length, '8bit');
        }
        return substr($byteString, $start, $length);
    }
    
    /**
     * Converts an integer into a byte-string.
     * 
     * Stores the bits representing the given non-negative integer in the
     * smallest sufficient number of bytes, padding the left side with zeros.
     * Uses PHP's BC Math library if the given integer string is too large to be
     * processed with PHP's internal string type.
     * 
     * Example: $intStr = 16706 => chr(16706 >> 8 & 255) . chr(16706 & 255) =
     * 'AB'
     * 
     * @param mixed $intStr Non-negative integer or string representing a
     *        non-negative integer.
     * @return string Byte-string containing the bits representing the given
     *         integer.
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    private static function _intStrToByteStr($intStr) {
        // Check if given value is a positive integer (string).
        if (!preg_match('/[0-9]+/', (string) $intStr)) {
            $msg = 'Argument 1 must be a non-negative integer or a string representing a non-negative integer.';
            throw new InvalidArgumentException($msg, self::E_NO_NON_NEGATIVE_INT);
        }
        $byteStr = '';
        // If possible, use integer type for conversion.
        $int = (int) $intStr;
        if ((string) $int == (string) $intStr) {
            // Use of integer type is possible.
            // Convert integer to byte-string.
            while ($int > 0) {
                $byteStr = chr($int & 255) . $byteStr;
                $int >>= 8;
            }
        } else {
            // Cannot use integer type, use BC Math library.
            if (extension_loaded('bcmath')) {
                // Convert integer to byte-string.
                while ((int) $intStr > 0) {
                    $byteStr = chr(bcmod($intStr, '256')) . $byteStr;
                    $intStr = bcdiv($intStr, '256', 0);
                }
            } else {
                throw new RuntimeException('BC Math functions are not available.', self::E_NO_BCMATH);
            }
        }
        if ($byteStr == '')
            $byteStr = chr(0);
        return $byteStr;
    }

    /**
     * Converts a byte-string into a non-negative integer.
     * 
     * Uses PHP's BC Math library if the integer represented by the given bytes
     * is too big to be stored in PHP's internal integer type. In this case a
     * string containing the integer is returned, otherwise a native integer.
     * 
     * Example: $byteStr = 'AB' => ord($byteStr[0]) << 8 | ord($byteStr[1]) =
     * 16706
     * 
     * @param string $byteStr Byte-string whose binary content shall be
     *        converted to an integer.
     * @return mixed Non-negative integer or string representing a non-negative
     *         integer.
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    private static function _byteStrToIntStr($byteStr) {
        // Get byte count.
        $byteCount = self::_byteCount($byteStr);

        // Check if byte count is not 0.
        if ($byteCount == 0) {
            $msg = 'Empty byte-string cannot be convertet to integer.';
            throw new InvalidArgumentException($msg, self::E_EMPTY_BYTESTRING);
        }

        // Try to use PHP's internal integer type.
        if ($byteCount <= PHP_INT_SIZE) {
            $int = 0;
            for ($i = 0; $i < $byteCount; $i++) {
                $int <<= 8;
                $int |= ord($byteStr[$i]);
            }
            if ($int >= 0)
                return $int;
        }

        // If we did not already return here, either the byte-string has more
        // characters (bytes) than PHP_INT_SIZE, or the conversion resulted in a
        // negative integer. In both cases, we need to use PHP's BC Math library and
        // return the integer as string.
        if (extension_loaded('bcmath')) {
            $intStr = '0';
            for ($i = 0; $i < $byteCount; $i++) {
                $intStr = bcmul($intStr, '256', 0);
                $intStr = bcadd($intStr, (string) ord($byteStr[$i]), 0);
            }
            return $intStr;
        } else {
            throw new RuntimeException('BC Math functions are not available.', self::E_NO_BCMATH);
        }
    }

    /**
     * Calculates dividend modulus divisor.
     * 
     * Uses PHP's BC Math library if the dividend is too big to be processed
     * with PHP's internal integer type.
     * 
     * @param mixed $intStr Dividend as integer or as string representing an
     *        integer.
     * @param int $divisor Divisor.
     * @return mixed Remainder as integer or as string representing an integer.
     * @throws RuntimeException
     */
    private static function _intStrModulus($intStr, $divisor) {
        // If possible, use integer type for calculation.
        $int = (int) $intStr;
        if ((string) $int == (string) $intStr) {
            // Use of integer type is possible.
            return $int % $divisor;
        } else {
            // Cannot use integer type, use BC Math library.
            if (extension_loaded('bcmath')) {
                return bcmod($intStr, (string) $divisor);
            } else {
                throw new RuntimeException('BC Math functions are not available.', self::E_NO_BCMATH);
            }
        }
    }

    /**
     * Encodes the bytes in the given byte-string according to the base 32
     * encoding described in RFC 4648 p. 8f
     * (http://tools.ietf.org/html/rfc4648#page-8).
     * 
     * @param string $byteStr String containing the bytes to be encoded.
     * @param bool $omitPadding If true, no padding characters are appended to
     *        the encoded string. Defaults to false.
     * @return string The encoded string.
     */
    public static function encodeByteStr($byteStr, $omitPadding = false) {
        return self::_encodeByteStr($byteStr, self::$_commonAlphabet, !$omitPadding);
    }

    /**
     * Converts the given non-negative integer into a byte-string and passes it
     * to encodeByteStr().
     * 
     * The bits representing the given integer are stored in the smallest
     * sufficient number of bytes, padding the left side with zeros.
     * 
     * Integers of arbitrary length can be passed to this method as string. If
     * The given integer is too large to be stored in PHP's internal integer
     * type, PHP's BC Math extension is used for processing.
     * 
     * @see encodeByteStr()
     * @param mixed $intStr A non-negative integer or a string representing a 
     *        non-negative integer to be encoded.
     * @param bool $omitPadding If true, no padding characters are appended to
     *        the encoded string. Defaults to false.
     * @return string The encoded string.
     */
    public static function encodeIntStr($intStr, $omitPadding = false) {
        $byteStr = self::_intStrToByteStr($intStr);
        return self::encodeByteStr($byteStr, $omitPadding);
    }

    /**
     * Encodes the bytes in the given byte-string according to the base 32
     * encoding described in RFC 4648 p. 8f
     * (http://tools.ietf.org/html/rfc4648#page-8), using the base 32 extended
     * hex alphabet specified in RFC 4648 p. 10
     * (http://tools.ietf.org/html/rfc4648#page-10).
     * 
     * @param string $byteStr String containing the bytes to be encoded.
     * @param bool $omitPadding If true, no padding characters are appended to
     *        the encoded string. Defaults to false.
     * @return string The encoded string.
     */
    public static function encodeByteStrToHex($byteStr, $omitPadding = false) {
        return self::_encodeByteStr($byteStr, self::$_hexAlphabet, !$omitPadding);
    }

    /**
     * Converts the given non-negative integer into a byte-string and passes it
     * to encodeByteStrToHex().
     * 
     * The bits representing the given integer are stored in the smallest
     * sufficient number of bytes, padding the left side with zeros.
     * 
     * Integers of arbitrary length can be passed to this method as string. If
     * The given integer is too large to be stored in PHP's internal integer
     * type, PHP's BC Math extension is used for processing.
     * 
     * @see encodeByteStrToHex()
     * @param mixed $intStr A non-negative integer or a string representing a 
     *        non-negative integer to be encoded.
     * @param bool $omitPadding If true, no padding characters are appended to
     *        the encoded string. Defaults to false.
     * @return string The encoded string.
     */
    public static function encodeIntStrToHex($intStr, $omitPadding = false) {
        $byteStr = self::_intStrToByteStr($intStr);
        return self::encodeByteStrToHex($byteStr, $omitPadding);
    }

    /**
     * Encodes the bytes in the given byte-string according to the base 32
     * encoding exposed by Douglas Crockford
     * (http://www.crockford.com/wrmg/base32.html).
     * 
     * This procedure is not described by Crockford, but makes sense if an
     * arbitrary stream of octets (bytes) shall be encoded using Crockford's
     * base 32 encoding (alphabet). If a check symbol shall be appended, it is
     * calculatet from the integer represented by the bits in the byte-string.
     * 
     * @param string $byteStr String containing the bytes to be encoded.
     * @param bool $appendCheckSymbol If true, a check symbol is appended to the
     *        encoded string. Defaults to false.
     * @return string The encoded string.
     */
    public static function encodeByteStrToCrockford($byteStr, $appendCheckSymbol = false) {
        $encodedStr = self::_encodeByteStr($byteStr, self::$_crockfordAlphabet, false);
        if ($appendCheckSymbol) {
            $intStr = self::_byteStrToIntStr($byteStr);
            $modulus = (int) self::_intStrModulus($intStr, 37);
            $encodedStr .= self::$_crockfordAlphabet[$modulus];
        }
        return $encodedStr;
    }

    /**
     * Encodes the given integer according to the base 32 encoding exposed by
     * Douglas Crockford (http://www.crockford.com/wrmg/base32.html).
     * 
     * Integers of arbitrary length can be passed to this method as string. If
     * The given integer is too large to be stored in PHP's internal integer
     * type, PHP's BC Math extension is used for processing.
     * 
     * @param mixed $intStr A non-negative integer or a string representing a 
     *        non-negative integer to be encoded.
     * @param bool $appendCheckSymbol If true, a check symbol is appended to the
     *        encoded string. Defaults to false.
     * @return string The encoded string.
     */
    public static function encodeIntStrToCrockford($intStr, $appendCheckSymbol = false) {
        $encodedStr = self::_crockfordEncodeIntStr($intStr, self::$_crockfordAlphabet);
        if ($appendCheckSymbol) {
            $modulus = (int) self::_intStrModulus($intStr, 37);
            $encodedStr .= self::$_crockfordAlphabet[$modulus];
        }
        return $encodedStr;
    }

    /**
     * Encodes the bytes in the given byte-string according to the base 32
     * encoding exposed by Zooko O'Whielacronx
     * (http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt).
     * 
     * This implementation will always encode full bytes (analog to the base 32
     * encoding described in RFC 4648), which is one possible proceeding
     * mentioned in the referred document.
     * 
     * @param string $byteStr String containing the bytes to be encoded.
     * @return string The encoded string.
     */
    public static function encodeByteStrToZooko($byteStr) {
        return self::_encodeByteStr($byteStr, self::$_zookoAlphabet, false);
    }

    /**
     * Converts the given non-negative integer into a byte-string and passes it
     * to encodeByteStrToZooko().
     * 
     * The bits representing the given integer are stored in the smallest
     * sufficient number of bytes, padding the left side with zeros.
     * 
     * Integers of arbitrary length can be passed to this method as string. If
     * The given integer is too large to be stored in PHP's internal integer
     * type, PHP's BC Math extension is used for processing.
     * 
     * @see encodeByteStrToZooko()
     * @param mixed $intStr A non-negative integer or a string representing a 
     *        non-negative integer to be encoded.
     * @return string The encoded string.
     */
    public static function encodeIntStrToZooko($intStr) {
        $byteStr = self::_intStrToByteStr($intStr);
        return self::encodeByteStrToZooko($byteStr);
    }

    /**
     * Base 32 encodes the given byte-string using the given alphabet.
     * 
     * @param string $byteStr String containing the bytes to be encoded.
     * @param string $alphabet The alphabet to be used for encoding.
     * @param bool $pad If true, the encoded string is padded using the padding
     *        character specified in the given alphabet to have a length which
     *        is evenly divisible by 8.
     * @return string The encoded string.
     * @throws InvalidArgumentException
     */
    private static function _encodeByteStr($byteStr, $alphabet, $pad) {
        // Check if argument is a string.
        if (!is_string($byteStr)) {
            $msg = 'Supplied argument 1 is not a string.';
            throw new InvalidArgumentException($msg, self::E_NO_STRING);
        }

        // Get byte count.
        $byteCount = self::_byteCount($byteStr);

        // Make byte count divisible by 5.
        $remainder = $byteCount % 5;
        $fillbyteCount = ($remainder) ? 5 - $remainder : 0;
        if ($fillbyteCount > 0)
            $byteStr .= str_repeat(chr(0), $fillbyteCount);

        // Iterate over blocks of 5 bytes and build encoded string.
        $encodedStr = '';
        for ($i = 0; $i < ($byteCount + $fillbyteCount); $i = $i + 5) {
            // Convert chars to bytes.
            $byte1 = ord($byteStr[$i]);
            $byte2 = ord($byteStr[$i + 1]);
            $byte3 = ord($byteStr[$i + 2]);
            $byte4 = ord($byteStr[$i + 3]);
            $byte5 = ord($byteStr[$i + 4]);
            // Read first 5 bit group.
            $bitGroup = $byte1 >> 3;
            $encodedStr .= $alphabet[$bitGroup];
            // Read second 5 bit group.
            $bitGroup = ($byte1 & ~(31 << 3)) << 2 | $byte2 >> 6;
            $encodedStr .= $alphabet[$bitGroup];
            // Read third 5 bit group.
            $bitGroup = $byte2 >> 1 & ~(3 << 5);
            $encodedStr .= $alphabet[$bitGroup];
            // Read fourth 5 bit group.
            $bitGroup = ($byte2 & 1) << 4 | $byte3 >> 4;
            $encodedStr .= $alphabet[$bitGroup];
            // Read fifth 5 bit group.
            $bitGroup = ($byte3 & ~(15 << 4)) << 1 | $byte4 >> 7;
            $encodedStr .= $alphabet[$bitGroup];
            // Read sixth 5 bit group.
            $bitGroup = $byte4 >> 2 & ~(1 << 5);
            $encodedStr .= $alphabet[$bitGroup];
            // Read seventh 5 bit group.
            $bitGroup = ($byte4 & ~(63 << 2)) << 3 | $byte5 >> 5;
            $encodedStr .= $alphabet[$bitGroup];
            // Read eighth 5 bit group.
            $bitGroup = $byte5 & ~(7 << 5);
            $encodedStr .= $alphabet[$bitGroup];
        }

        // Replace fillbit characters at the end of the encoded string.
        $encodedStrLen = ($byteCount + $fillbyteCount) * 8 / 5;
        $fillbitCharCount = (int) ($fillbyteCount * 8 / 5);
        $encodedStr = substr($encodedStr, 0, $encodedStrLen - $fillbitCharCount);
        if ($pad)
            $encodedStr .= str_repeat($alphabet[32], $fillbitCharCount);

        // Return encoded string.
        return $encodedStr;
    }

    /**
     * Encodes the given integer using the procedure described by Douglas
     * Crockford (http://www.crockford.com/wrmg/base32.html), using the given
     * alphabet.
     * 
     * Rather than encoding a stream of octets (bytes), this algorithm encodes
     * a sequence of 5-bit-groups. If the count of the bits representing the
     * given integer is not evenly divisible by 5, the bit sequence is padded
     * with zero-bits at the left side (4 at a maximum).
     * 
     * Integers of arbitrary length can be passed to this method as string. If
     * The given integer is too large to be stored in PHP's internal integer
     * type, PHP's BC Math extension is used for processing.
     * 
     * @param mixed $intStr A non-negative integer or a string representing a 
     *        non-negative integer to be encoded.
     * @param string $alphabet The alphabet to be used for encoding.
     * @return string The encoded string.
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    private static function _crockfordEncodeIntStr($intStr, $alphabet) {
        // Check if given value is a non-negative integer(-string).
        if (!preg_match('/[0-9]+/', (string) $intStr)) {
            $msg = 'Argument 1 must be a non-negative integer or a string representing a non-negative integer.';
            throw new InvalidArgumentException($msg, self::E_NO_NON_NEGATIVE_INT);
        }
        $encodedStr = '';
        // If possible, use integer type for encoding.
        $int = (int) $intStr;
        if ((string) $int == (string) $intStr) {
            // Use of integer type is possible.
            while ($int > 0) {
                $encodedStr = $alphabet[$int % 32] . $encodedStr;
                $int = (int) ($int / 32);
            }
        } else {
            // Cannot use integer type, use BC Math library.
            if (extension_loaded('bcmath')) {
                while ((int) $intStr > 0) {
                    $encodedStr = $alphabet[bcmod($intStr, '32')] . $encodedStr;
                    $intStr = bcdiv($intStr, '32', 0);
                }
            } else {
                throw new RuntimeException('BC Math functions are not available.', self::E_NO_BCMATH);
            }
        }
        if ($encodedStr == '')
            $encodedStr = $alphabet[0];
        return $encodedStr;
    }

    /**
     * Checks if argument 1 is of type string. If optional $pattern is given,
     * also checks if string matches pattern. Throws an exception if a check is
     * not passed.
     * 
     * @param mixed $string The variable to be checked.
     * @param string $pattern Optional pattern to be used to check string's
     *        syntax.
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    private static function _checkEncodedString($string, $pattern = null) {
        // Check if argument is a string.
        if (!is_string($string)) {
            $msg = 'Supplied encoded data is not of type string.';
            throw new InvalidArgumentException($msg, self::E_NO_STRING);
        }
        // If pattern are supplied, check if string matches pattern.
        if ($pattern !== null) {
            $patternMatched = preg_match($pattern, $string);
            if ($patternMatched === false) {
                $msg = 'Error while trying to check encoded string syntax.';
                throw new RuntimeException($msg, self::E_PATTERN_MATCHING_FAILED);
            }
            if (!$patternMatched) {
                $msg = 'Supplied encoded string has invalid syntax.';
                throw new InvalidArgumentException($msg, self::E_INVALID_SYNTAX);
            }
        }
    }

    /**
     * Decodes a RFC 4646 base32 encoded string to a byte-string.
     * 
     * Expects an encoded string according to the base 32 encoding described in
     * RFC 4648 p. 8f (http://tools.ietf.org/html/rfc4648#page-8). Throws an
     * exception if the encoded string is malformed.
     * 
     * @param string $encodedStr The encoded string.
     * @param bool $allowOmittedPadding If true, missing padding characters at
     *        the end of the encoded string will not lead to an exception.
     *        Defaults to false.
     * @return string The decoded byte-string.
     */
    public static function decodeToByteStr($encodedStr, $allowOmittedPadding = false) {
        // Check input string.
        $pattern = '/[A-Z2-7]*([A-Z2-7]={0,6})?/';
        self::_checkEncodedString($encodedStr, $pattern);

        // Get length (byte count) of encoded string.
        $encodedStrLen = self::_byteCount($encodedStr);

        // Get decoded byte-string.
        $byteStr = self::_decodeToByteStr($encodedStr, $encodedStrLen, self::$_commonFlippedAlphabet, '=', $allowOmittedPadding);

        // Return byte-string.
        return $byteStr;
    }

    /**
     * Uses decodeToByteStr() to decode the given encoded string and converts
     * the resulting byte-string into a non-negative integer.
     * 
     * Uses PHP's BC Math library if the integer represented by the given bytes
     * is too big to be stored in PHP's internal integer type. In this case a
     * string containing the integer is returned, otherwise a native integer.
     * 
     * @see decodeToByteStr()
     * @param string $encodedStr The encoded string.
     * @param bool $allowOmittedPadding If true, missing padding characters at
     *        the end of the encoded string will not lead to an exception.
     *        Defaults to false.
     * @return mixed A non-negative integer or a string representing a 
     *         non-negative integer.
     */
    public static function decodeToIntStr($encodedStr, $allowOmittedPadding = false) {
        // Get byte-string.
        $byteStr = self::decodeToByteStr($encodedStr, $allowOmittedPadding);
        // Conver byte-string to integer (string) and return it.
        return self::_byteStrToIntStr($byteStr);
    }

    /**
     * Decodes a RFC 4646 base32 extended hex encoded string to a byte-string.
     * 
     * Expects an encoded string according to the base 32 extended hex encoding
     * described in RFC 4648 p. 10 (http://tools.ietf.org/html/rfc4648#page-10).
     * Throws an exception if the encoded string is malformed.
     * 
     * @param string $encodedStr The encoded string.
     * @param bool $allowOmittedPadding If true, missing padding characters at
     *        the end of the encoded string will not lead to an exception.
     *        Defaults to false.
     * @return string The decoded byte-string.
     */
    public static function decodeHexToByteStr($encodedStr, $allowOmittedPadding = false) {
        // Check input string.
        $pattern = '/[0-9A-V]*([0-9A-V]={0,6})?/';
        self::_checkEncodedString($encodedStr, $pattern);

        // Get length (byte count) of encoded string.
        $encodedStrLen = self::_byteCount($encodedStr);

        // Get decoded byte-string.
        $byteStr = self::_decodeToByteStr($encodedStr, $encodedStrLen, self::$_hexFlippedAlphabet, '=', $allowOmittedPadding);

        // Return byte-string.
        return $byteStr;
    }

    /**
     * Uses decodeHexToByteStr() to decode the given encoded string and converts
     * the resulting byte-string into a non-negative integer.
     * 
     * Uses PHP's BC Math library if the integer represented by the given bytes
     * is too big to be stored in PHP's internal integer type. In this case a
     * string containing the integer is returned, otherwise a native integer.
     * 
     * @see decodeHexToByteStr()
     * @param string $encodedStr The encoded string.
     * @param bool $allowOmittedPadding If true, missing padding characters at
     *        the end of the encoded string will not lead to an exception.
     *        Defaults to false.
     * @return mixed A non-negative integer or a string representing a 
     *         non-negative integer.
     */
    public static function decodeHexToIntStr($encodedStr, $allowOmittedPadding = false) {
        // Get byte-string.
        $byteStr = self::decodeHexToByteStr($encodedStr, $allowOmittedPadding);
        // Conver byte-string to integer (string) and return it.
        return self::_byteStrToIntStr($byteStr);
    }

    /**
     * Decodes a Crockford base32 encoded string.
     * 
     * Expects an encoded string according to the base 32 encoding exposed by
     * Douglas Crockford (http://www.crockford.com/wrmg/base32.html). Throws an
     * exception if the encoded string is malformed.
     * 
     * If a check symbol is provided and does not match the decoded data, an
     * exception is thrown.
     * 
     * @param string $to String to specify whether to decode to an integer 
     *        ('intStr') or to a byte-string ('byteStr').
     * @param string $encodedStr The encoded string.
     * @param bool $hasCheckSymbol If true, the last character of the encoded
     *        string is regarded as check symbol.
     * @return mixed A byte-string (for $to = 'byteStr') or a non-negative
     *         integer or a string representing a non-negative integer (for $to
     *         = 'intStr').
     * @throws UnexpectedValueException
     */
    private static function _decodeCrockford($to, $encodedStr, $hasCheckSymbol = false) {
        // Check input string.
        if ($hasCheckSymbol) {
            $pattern = '/[0-9A-TV-Z-]*[0-9A-Z*~$=]-*/i';
        } else {
            $pattern = '/[0-9A-TV-Z-]*/i';
        }
        self::_checkEncodedString($encodedStr, $pattern);

        // Remove hyphens from encoded string.
        $encodedStr = str_replace('-', '', $encodedStr);

        // Get length (byte count) of encoded string.
        $encodedStrLen = self::_byteCount($encodedStr);

        // If the last character is a valid Crockford check symbol, remove it from
        // the encoded string.
        if ($hasCheckSymbol) {
            $checkSymbol = $encodedStr[$encodedStrLen - 1];
            $encodedStr = self::_extractBytes($encodedStr, 0, $encodedStrLen - 1);
            $encodedStrLen--;
        }

        // Compose Crockford decoding mapping.
        $mapping = self::$_crockfordFlippedAlphabet + self::$_crockfordAdditionalCharMapping + array('_' => 0);

        // Get decoded content.
        if ($to == 'byteStr') {
            $decoded = self::_decodeToByteStr($encodedStr, $encodedStrLen, $mapping, '_', true);
        } elseif ($to == 'intStr') {
            $decoded = self::_crockfordDecodeToIntStr($encodedStr, $encodedStrLen, $mapping);
        }

        // If check symbol is present, check if decoded string is correct.
        if ($hasCheckSymbol) {
            if ($to == 'byteStr') {
                $intStr = self::_byteStrToIntStr($decoded);
            } elseif ($to == 'intStr') {
                $intStr = $decoded;
            }
            $modulus = (int) self::_intStrModulus($intStr, 37);
            if ($modulus != $mapping[$checkSymbol]) {
                throw new UnexpectedValueException('Check symbol does not match data.', self::E_CHECKSYMBOL_DOES_NOT_MATCH_DATA);
            }
        }

        // Return byte-string.
        return $decoded;
    }

    /**
     * Decodes a Crockford base32 encoded string to a byte-string.
     * 
     * This procedure is not described by Crockford, but makes sense if an
     * arbitrary stream of octets (bytes) has been encoded using Crockford's
     * base 32 encoding (alphabet). If a check symbol shall be appended, it is
     * calculatet from the integer represented by the bits in the byte-string.
     * 
     * Expects an encoded string according to the base 32 encoding exposed by
     * Douglas Crockford (http://www.crockford.com/wrmg/base32.html). Throws an
     * exception if the encoded string is malformed.
     * 
     * If a check symbol is provided, it is matched against the integer
     * represented by the bits in the byte-string. If it does not match, an
     * exception is thrown.
     * 
     * @param string $encodedStr The encoded string.
     * @param bool $hasCheckSymbol If true, the last character of the encoded
     *        string is regarded as check symbol.
     * @return string The decoded byte-string.
     */
    public static function decodeCrockfordToByteStr($encodedStr, $hasCheckSymbol = false) {
        return self::_decodeCrockford('byteStr', $encodedStr, $hasCheckSymbol);
    }

    /**
     * Decodes a Crockford base32 encoded string to a non-negative integer.
     * 
     * Expects an encoded string according to the base 32 encoding exposed by
     * Douglas Crockford (http://www.crockford.com/wrmg/base32.html). Throws an
     * exception if the encoded string is malformed.
     * 
     * If a check symbol is provided and does not match the decoded data, an
     * exception is thrown.
     * 
     * Uses PHP's BC Math library if the integer represented by the given bytes
     * is too big to be stored in PHP's internal integer type. In this case a
     * string containing the integer is returned, otherwise a native integer.
     * 
     * @param string $encodedStr The encoded string.
     * @param bool $hasCheckSymbol If true, the last character of the encoded
     *        string is regarded as check symbol.
     * @return mixed A non-negative integer or a string representing a 
     *         non-negative integer.
     */
    public static function decodeCrockfordToIntStr($encodedStr, $hasCheckSymbol = false) {
        return self::_decodeCrockford('intStr', $encodedStr, $hasCheckSymbol);
    }

    /**
     * Decodes a Zooko encoded string to a byte-string.
     * 
     * Expects an encoded string according to the base 32 encoding exposed by
     * Zooko O'Whielacronx
     * (http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt).
     * Throws an exception if the encoded string is malformed.
     * 
     * This implementation will always decode full bytes (analog to the base 32
     * encoding described in RFC 4648), which is one possible proceeding
     * mentioned in the referred document.
     * 
     * @param string $encodedStr The encoded string.
     * @return string The decoded byte-string.
     */
    public static function decodeZookoToByteStr($encodedStr) {
        // Check input string.
        $pattern = '/[a-km-uw-z13-9]*/';
        self::_checkEncodedString($encodedStr, $pattern);

        // Get length (byte count) of encoded string.
        $encodedStrLen = self::_byteCount($encodedStr);

        // Add padding character to mapping.
        $mapping = self::$_zookoFlippedAlphabet + array('_' => 0);

        // Get decoded byte-string.
        $byteStr = self::_decodeToByteStr($encodedStr, $encodedStrLen, $mapping, '_', true);
        
        // Return byte-string.
        return $byteStr;
    }

    /**
     * Uses decodeZookoToByteStr() to decode the given encoded string and
     * converts the resulting byte-string into a non-negative integer.
     * 
     * Uses PHP's BC Math library if the integer represented by the given bytes
     * is too big to be stored in PHP's internal integer type. In this case a
     * string containing the integer is returned, otherwise a native integer.
     * 
     * @see decodeZookoToByteStr()
     * @param string $encodedStr The encoded string.
     * @return mixed A non-negative integer or a string representing a 
     *         non-negative integer.
     */
    public static function decodeZookoToIntStr($encodedStr) {
        // Get byte-string.
        $byteStr = self::decodeZookoToByteStr($encodedStr);
        // Conver byte-string to integer (string) and return it.
        return self::_byteStrToIntStr($byteStr);
    }

    /**
     * Decodes the given base32 encoded string using the given character
     * mapping to a byte-string.
     * 
     * @param string $encodedStr The encoded string.
     * @param int $encodedStrLen Length of the encoded string.
     * @param array $mapping Associative array mapping the characters in the
     *        encoded string to the values they represent.
     * @param string $paddingChar The padding character used by the current
     *        encoding. (If the current encoding does not use a padding
     *        character, a non-conflicting temporary padding character must be
     *        specified here and in the mapping.)
     * @param bool $allowOmittedPadding If false, a missing padding (e.g. an
     *        encoded string length which is not evenly divisible by 8) will
     *        lead to an exception.
     * @return string The decoded byte-string.
     * @throws InvalidArgumentException
     */
    private static function _decodeToByteStr($encodedStr, $encodedStrLen, $mapping, $paddingChar, $allowOmittedPadding) {
        // Get padding length.
        $i = $encodedStrLen;
        $paddingLen = 0;
        while ($i-- >= 0 && $encodedStr[$i] == $paddingChar) {
            $paddingLen++;
        }

        // Check padding length.
        if (!in_array($paddingLen, array(0, 1, 3, 4, 6))) {
            throw new InvalidArgumentException('Invalid padding length.', self::E_INVALID_SYNTAX);
        }

        // Check encoded string length.
        $remainder = $encodedStrLen % 8;
        if (!in_array($remainder, array(0, 2, 4, 5, 7)) || (!$allowOmittedPadding && $remainder != 0)) {
            throw new InvalidArgumentException('Invalid encoded string length.', self::E_INVALID_SYNTAX);
        }

        // Add padding if necessary.
        if ($remainder != 0) {
            $paddingLen = 8 - $remainder;
            $encodedStr .= str_repeat($paddingChar, $paddingLen);
            $encodedStrLen += $paddingLen;
        }

        // Iterate over blocks of 8 characters and build decoded byte-string.
        $byteStr = '';
        for ($i = 0; $i < $encodedStrLen; $i = $i + 8) {
            // Convert chars to bit-groups.
            $bitGroup1 = $mapping[$encodedStr[$i]];
            $bitGroup2 = $mapping[$encodedStr[$i + 1]];
            $bitGroup3 = $mapping[$encodedStr[$i + 2]];
            $bitGroup4 = $mapping[$encodedStr[$i + 3]];
            $bitGroup5 = $mapping[$encodedStr[$i + 4]];
            $bitGroup6 = $mapping[$encodedStr[$i + 5]];
            $bitGroup7 = $mapping[$encodedStr[$i + 6]];
            $bitGroup8 = $mapping[$encodedStr[$i + 7]];
            // Assemble first byte.
            $byte = $bitGroup1 << 3 | $bitGroup2 >> 2;
            $byteStr .= chr($byte);
            // Assemble second byte.
            $byte = ($bitGroup2 & ~(7 << 2)) << 6 | $bitGroup3 << 1 | $bitGroup4 >> 4;
            $byteStr .= chr($byte);
            // Assemble third byte.
            $byte = ($bitGroup4 & ~(1 << 4)) << 4 | $bitGroup5 >> 1;
            $byteStr .= chr($byte);
            // Assemble fourth byte.
            $byte = ($bitGroup5 & 1) << 7 | $bitGroup6 << 2 | $bitGroup7 >> 3;
            $byteStr .= chr($byte);
            // Assemble fifth byte.
            $byte = ($bitGroup7 & ~(3 << 3)) << 5 | $bitGroup8;
            $byteStr .= chr($byte);
        }

        // Remove fillbytes from byte-string.
        $fillbyteCount = (int) ceil($paddingLen * 5 / 8);
        if ($fillbyteCount > 0) {
            $byteCount = self::_byteCount($byteStr);
            $byteStr = self::_extractBytes($byteStr, 0, $byteCount - $fillbyteCount);
        }

        // Return decoded byte-string.
        return $byteStr;
    }

    /**
     * Decodes the given base32 encoded string using the given character
     * mapping to an integer.
     * 
     * Expects the given encoded string to be padding free!
     * 
     * Uses PHP's BC Math library if the integer represented by the given bytes
     * is too big to be stored in PHP's internal integer type. In this case a
     * string containing the integer is returned, otherwise a native integer.
     * 
     * @param string $encodedStr The encoded string.
     * @param int $encodedStrLen Length of the encoded string.
     * @param array $mapping Associative array mapping the characters in the
     *        encoded string to the values they represent.
     * @return mixed A non-negative integer or a string representing a 
     *         non-negative integer.
     * @throws RuntimeException
     */
    private static function _crockfordDecodeToIntStr($encodedStr, $encodedStrLen, $mapping) {
        // Try to use PHP's internal integer type.
        if (($encodedStrLen * 5 / 8) <= PHP_INT_SIZE) {
            $int = 0;
            for ($i = 0; $i < $encodedStrLen; $i++) {
                $int <<= 5;
                $int |= $mapping[$encodedStr[$i]];
            }
            if ($int >= 0)
                return $int;
        }

        // If we did not already return here, PHP's internal integer type can not
        // hold the encoded value. Now we use PHP's BC Math library instead and
        // return the integer as string.
        if (extension_loaded('bcmath')) {
            $intStr = '0';
            for ($i = 0; $i < $encodedStrLen; $i++) {
                $intStr = bcmul($intStr, '32', 0);
                $intStr = bcadd($intStr, (string) $mapping[$encodedStr[$i]], 0);
            }
            return $intStr;
        } else {
            throw new RuntimeException('BC Math functions are not available.', self::E_NO_BCMATH);
        }
    }

}
