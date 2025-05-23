/*
 * Copyright 2016 Juraj Durech <durech.juraj@gmail.com>
 * Copyright 2025 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cc7/Base64.h>
#include <cc7/Utilities.h>

namespace cc7 {

// -----------------------------------------------------------------
// BASE64 conversions
//
// Just for curiosity, following routines are based on my previous
// work created for Intype text editor :)
// -----------------------------------------------------------------

// MARK: - Internals

enum Result
{
    RESULT_OK,
    RESULT_WRONG_DATA,
    RESULT_WRONG_WRAP,
    RESULT_INTERNAL,
};

struct Spec
{
    std::string name;
    const char* enc_table;
    const byte* dec_table;
    char padding;
    bool multiline;
};

static const char * s_ENC_BASE64     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char * s_ENC_BASE64URL  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*
 Decoder table contains conversion from arbitrary 8 bit character to radix value.
 If the translated value is equal to 0xff then the original character is invalid.
 */
static const byte s_DEC_BASE64[256] =
{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static const byte s_DEC_BASE64URL[256] =
{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0x3f,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static const Spec spec_BASE64 {
    "Base64", s_ENC_BASE64, s_DEC_BASE64, '=', true
};

static const Spec spec_BASE64_URL {
    "Base64Url", s_ENC_BASE64URL, s_DEC_BASE64URL, 0, false
};

// MARK: - Encoder


static size_t _EstimateEncodedLength(size_t len, size_t wrap_output)
{
    size_t n = ((len + 2) / 3) * 4;
    if (wrap_output > 0) {
        n += strlen("\n") * ((n / wrap_output) + 1);
    }
    return n;
}

static Result Base64Impl_Encode(const Spec & s, const ByteRange & range, size_t wrap_size, std::string & out_string) noexcept
{
    out_string.clear();
    
    if (wrap_size > 0) {
        if (utilities::AlignValue<4>(wrap_size) != wrap_size) {
            return RESULT_WRONG_WRAP;
        }
    }
    
    out_string.reserve(_EstimateEncodedLength(range.size(), wrap_size));
    
    char block_4[4];
    const byte * in_p   = range.data();
    size_t in_len       = range.size();
    size_t wrap_pos     = 0;
    
    while (in_len >= 3) {
        // Process all aligned triplets
        block_4[0] = s.enc_table[  (in_p[0] & 0xfc) >> 2                            ];
        block_4[1] = s.enc_table[ ((in_p[0] & 0x03) << 4) + ((in_p[1] & 0xf0) >> 4) ];
        block_4[2] = s.enc_table[ ((in_p[1] & 0x0f) << 2) + ((in_p[2] & 0xc0) >> 6) ];
        block_4[3] = s.enc_table[   in_p[2] & 0x3f                                  ];
        in_len -= 3;
        in_p   += 3;
        out_string.append(block_4, 4);
        if (wrap_size) {
            wrap_pos += 4;
            if (wrap_pos >= wrap_size) {
                out_string.append("\n");
                wrap_pos = 0;
            }
        }
    }
    if (in_len > 0) {
        // Process the rest of unaligned bytes
        block_4[0] = s.enc_table[  (in_p[0] >> 2) & 0x3f ];
        block_4[1] = s.enc_table[ ((in_p[0] << 4) + (--in_len ? in_p[1] >> 4 : 0)) & 0x3f ];
        block_4[2] = (in_len ? s.enc_table[ ((in_p[1] << 2) + (--in_len ? (in_p[2]) >> 6 : 0)) & 0x3f ] : s.padding);
        block_4[3] = s.padding;
        if (s.padding) {
            out_string.append(block_4, 4);
        } else {
            out_string.append(block_4, block_4[2] ? 3 : 2);
        }
    }
    return RESULT_OK;
}


// MARK: - Decoder

static Result Base64Impl_DecodeNoWrap(const Spec & s,
                                      const std::string & str, size_t sequence_start, size_t sequence_length,
                                      ByteArray & out_data,
                                      bool & end_marker) noexcept
{
    if (sequence_length == 0) {
        // Not a real end marker, but this is an end of processing.
        end_marker = true;
        return RESULT_OK;
    }
    
    // Check sequence length.
    const auto leftover_bytes = sequence_length & 3;
    if (leftover_bytes != 0) {
        if (s.padding) {
            // Wrong size of the sequence. No assertion, because we're using
            // this routine also for non-wrapped strings.
            // This is valid only if specification contains padding character
            return RESULT_WRONG_DATA;
        } else {
            // If no padding is specified, then end_marker is defined by remainder of size. The number of blocks
            // should be correct in this case.
            end_marker = true;
        }
    }
    if (sequence_start + sequence_length > str.length()) {
        // Internal error. The provided sequence is out of the input string's range.
        CC7_ASSERT(false, "Internal error. Provided block size is too long");
        return RESULT_INTERNAL;
    }
    
    //
    // Reserve bytes in the byte array. The produced_size is a worst case
    // estimation for length of final data.
    //
    size_t blocks_count  = sequence_length / 4;
    size_t block_size    = blocks_count * 3;
    out_data.reserve(out_data.size() + block_size);
    
    // Input pointer
    const byte * block_4 = reinterpret_cast<const byte*>(str.c_str()) + sequence_start;
    
    if (s.padding) {
        // If padding character is specified, then check if last block contains padding and thus requires
        // additional processing.
        end_marker = block_4[sequence_length - 1] == s.padding || block_4[sequence_length - 2] == s.padding;
        if (end_marker) {
            // Decrease number of "fast" blocks. We will process last one in a separate branch.
            blocks_count--;
        }
    }
    
    // Process all non-padded blocks in fast way, without padding validation.
    // If this sequence will contain padding then this will be treated as error.
    byte c[4];
    while (blocks_count > 0) {
        
        c[0] = s.dec_table[ block_4[0] ];
        c[1] = s.dec_table[ block_4[1] ];
        c[2] = s.dec_table[ block_4[2] ];
        c[3] = s.dec_table[ block_4[3] ];
        if (c[0] == 0xff || c[1] == 0xff ||
            c[2] == 0xff || c[3] == 0xff) {
            return RESULT_WRONG_DATA;
        }
        
        out_data.push_back((c[0] << 2) | (c[1] >> 4));
        out_data.push_back((c[1] << 4) | (c[2] >> 2));
        out_data.push_back((c[2] << 6) |  c[3]);
        
        blocks_count--;
        block_4 += 4;
    }
    
    if (end_marker) {
        if (s.padding) {
            // Last block contains a padding marker and requires more checks for correct processing.
            c[0] = s.dec_table[ block_4[0] ];
            c[1] = s.dec_table[ block_4[1] ];
            if (c[0] == 0xff || c[1] == 0xff) {
                return RESULT_WRONG_DATA;
            }
            // First byte should be always decoded
            out_data.push_back((c[0] << 2) | (c[1] >> 4));
            
            // Padding mode
            if (block_4[2] == s.padding) {
                // Last two characters should be padding markers
                if (block_4[3] != s.padding) {
                    // Wrong. Seqence like 'XY=Z'
                    return RESULT_WRONG_DATA;
                }
                // the rest is correct, last byte is already decoded
                //
            } else if (block_4[3] == s.padding) {
                // Last char is padding marker, translate 3rd. character in the block
                c[2] = s.dec_table[ block_4[2] ];
                
                if (c[2] == 0xff) {
                    // Last non-padded character is invalid. Sequence like 'XY?='
                    return RESULT_WRONG_DATA;
                }
                // c3 is correct and last character is padding
                out_data.push_back((c[1] << 4) | (c[2] >> 2));
            } else {
                // This might never happen. The 'end_marker' claims that the sequence
                // contains padding marker, but the deep inspection is telling something else.
                // Seems that we somehow processed less or more bytes as was planned.
                return RESULT_INTERNAL;
            }
        } else {
            // For non-padding mode, the processing is slightly different. We have to determine
            // number of remained characters.
            if (leftover_bytes == 0) {
                // End marker detection is wrong. This block should be processed as aligned.
                return RESULT_INTERNAL;
            }
            if (leftover_bytes == 1) {
                // Not sufficient data provided.
                return RESULT_WRONG_DATA;
            }
            // Remaining 2 or 3
            c[0] = s.dec_table[ block_4[0] ];
            c[1] = s.dec_table[ block_4[1] ];
            if (c[0] == 0xff || c[1] == 0xff) {
                return RESULT_WRONG_DATA;
            }
            // First byte should be always decoded}
            out_data.push_back((c[0] << 2) | (c[1] >> 4));
            if (leftover_bytes == 3) {
                // One more character is remaining
                c[2] = s.dec_table[ block_4[2] ];
                if (c[2] == 0xff) {
                    // Last character is invalid. Sequence like 'XY?'
                    return RESULT_WRONG_DATA;
                }
                // c3 is correct and this is the last character
                out_data.push_back((c[1] << 4) | (c[2] >> 2));
            }
        }
    }
    return RESULT_OK;
}

static Result Base64Impl_Decode(const Spec& s, const std::string & string, size_t wrap_size, ByteArray & out_data) noexcept
{
    Result result = RESULT_WRONG_DATA;
    out_data.clear();
    if (wrap_size > 0) {
        if (!s.multiline) {
            // This specification doesn't support multiline encodings
            return RESULT_INTERNAL;
        }
        //
        // wrap impl.
        //
        if (utilities::AlignValue<4>(wrap_size) != wrap_size) {
            return RESULT_WRONG_WRAP;
        }

        // Calculate estimated data size (just to eliminate multiple reallocations in the data buffer)
        size_t size = string.size();
        size_t div = size / (wrap_size + 1);
        size_t rem = size % (wrap_size + 1);
        // subtract a number of possible new line characters
        size -= div + (rem > 0 ? 1 : 0);
        // final expected size of data
        size_t byte_size = ((size + 3) / 4) * 3;
        out_data.reserve(byte_size);
        
        // Current & End pointer
        const char * str_p   = string.c_str();
        const char * str_end = string.c_str() + string.length();
        result = RESULT_OK;
        
        bool end_marker = false;
        while ((result == RESULT_OK) && str_p < str_end) {
            // Find begin of the line, by skipping leading whitespaces
            while (str_p < str_end) {
                char c = *str_p;
                if (!isspace(c)) {
                    break;
                }
                str_p++;
            }
            // Find end of the line, by skipping non-whitespace characters
            const char * line_begin = str_p;
            while (str_p < str_end) {
                char c = *str_p;
                if (isspace(c)) {
                    break;
                }
                str_p++;
            }
            const char * line_end = str_p;
            size_t line_length = line_end - line_begin;
            if (line_length > 0) {
                // There's some sequence of non-space characters.
                if (end_marker) {
                    // previous line did end with end-marker. If there's a next line, then this is an error.
                    out_data.clear();
                    return RESULT_WRONG_DATA;
                }
                // The rest of the decoding is handled in the "NoWrap" routine.
                result = Base64Impl_DecodeNoWrap(s, string, line_begin - string.c_str(), line_length, out_data, end_marker);
            }
        }
        //
    } else {
        //
        // no wrap impl.
        //
        bool foo;
        result = Base64Impl_DecodeNoWrap(s, string, 0, string.length(), out_data, foo);
    }
    if (result != RESULT_OK) {
        out_data.clear();
    }
    return result;
}


// MARK: - Base64 class

static void throwIfNOK(Result r, const Spec& s)
{
    switch (r) {
        case RESULT_OK: return;
        case RESULT_WRONG_DATA: throw std::domain_error("Wrong " + s.name + " string");
        case RESULT_WRONG_WRAP: throw std::invalid_argument("wrap_size must be divisible by 4");
        default: throw std::logic_error("Internal error in " + s.name + " routine");
    }
}

std::string Base64::encode(const ByteRange &data, size_t wrap_size)
{
    std::string out;
    throwIfNOK(Base64Impl_Encode(spec_BASE64, data, wrap_size, out), spec_BASE64);
    return out;
}

ByteArray Base64::decode(const std::string& data, size_t wrap_size)
{
    ByteArray out;
    throwIfNOK(Base64Impl_Decode(spec_BASE64, data, wrap_size, out), spec_BASE64);
    return out;
}

std::string Base64::urlEncode(const ByteRange& data) noexcept
{
    std::string out;
    Base64Impl_Encode(spec_BASE64_URL, data, 0, out);
    return out;
}

ByteArray Base64::urlDecode(const std::string& data)
{
    ByteArray out;
    throwIfNOK(Base64Impl_Decode(spec_BASE64_URL, data, 0, out), spec_BASE64_URL);
    return out;
}



// MARK: - Legacy functions

bool Base64_Encode(const ByteRange & in_data, size_t wrap_size, std::string & out_string) noexcept
{
    return Base64Impl_Encode(spec_BASE64, in_data, wrap_size, out_string) == RESULT_OK;
}

bool Base64_Decode(const std::string & in_string, size_t wrap_size, ByteArray & out_data) noexcept
{
    return Base64Impl_Decode(spec_BASE64, in_string, wrap_size, out_data) == RESULT_OK;
}

std::string ToBase64String(const ByteRange & data, size_t wrap_size) noexcept
{
    std::string result;
    Base64Impl_Encode(spec_BASE64, data, wrap_size, result);
    return result;
}

ByteArray FromBase64String(const std::string & string, size_t wrap_size) noexcept
{
    ByteArray result;
    Base64Impl_Decode(spec_BASE64, string, wrap_size, result);
    return result;
}


} // cc7
