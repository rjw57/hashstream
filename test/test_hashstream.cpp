//  Copyright (c) 2011, Rich Wareham <rjw57@cam.ac.uk>
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//      * Redistributions of source code must retain the above copyright
//	notice, this list of conditions and the following disclaimer.
//      * Redistributions in binary form must reproduce the above copyright
//	notice, this list of conditions and the following disclaimer in the
//	documentation and/or other materials provided with the distribution.
//      * Neither the name of the hashstream library nor the
//	names of its contributors may be used to endorse or promote products
//	derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL RICH WAREHAM BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <iostream>
#include <sstream>

#include <hashstream.hpp>

void report_fail(const std::string f_name,
                 const std::string& input, const std::string& expected_hex_digest,
                 const std::string& got_digest)
{
    std::cerr << "     got " << f_name << "(\"" << input << "\") = " << got_digest << std::endl;
    std::cerr << "expected " << f_name << "(\"" << input << "\") = " << expected_hex_digest << std::endl;
}

bool test_standard_hash(hashstream::standard_hash f, const std::string f_name,
                        const std::string& input, const std::string& expected_hex_digest)
{
    bool passed(true);
    std::string temp_digest;

    // test hashstream functionality
    hashstream::hashstream hs(f);
    hs << input;

    if(hs.hex_digest() != expected_hex_digest)
    {
        std::cerr << "using hashstream::ostream:" << std::endl;
        report_fail(f_name, input, expected_hex_digest, hs.hex_digest());
        passed = false;
    }

    // test ostream operators
    std::stringstream oss;
    oss << hs;
    if(oss.str() != expected_hex_digest)
    {
        std::cerr << "using operator<<(ostream, hashstream):" << std::endl;
        report_fail(f_name, input, expected_hex_digest, oss.str());
        passed = false;
    }

    // test convenience istream wrappers
    std::stringstream ss(input);
    if((temp_digest = hashstream::hex_digest(f, ss)) != expected_hex_digest)
    {
        std::cerr << "using hashstream::hex_digest(std::istream&):" << std::endl;
        report_fail(f_name, input, expected_hex_digest, temp_digest);
        passed = false;
    }

    // test convenience string wrapper
    if((temp_digest = hashstream::hex_digest(f, input)) != expected_hex_digest)
    {
        std::cerr << "using hashstream::hex_digest(const std::string&):" << std::endl;
        report_fail(f_name, input, expected_hex_digest, temp_digest);
        passed = false;
    }

    return passed;
}

bool test_md5(const std::string& input, const std::string& expected_hex_digest)
{
    bool passed = true;

    passed = passed && test_standard_hash(hashstream::MD5, "MD5", input, expected_hex_digest);

    return passed;
}

bool test_sha1(const std::string& input, const std::string& expected_hex_digest)
{
    bool passed = true;

    passed = passed && test_standard_hash(hashstream::SHA1, "SHA1", input, expected_hex_digest);

    return passed;
}

bool test_sha256(const std::string& input, const std::string& expected_hex_digest)
{
    bool passed = true;

    passed = passed && test_standard_hash(hashstream::SHA256, "SHA256", input, expected_hex_digest);

    return passed;
}

bool test_sha384(const std::string& input, const std::string& expected_hex_digest)
{
    bool passed = true;

    passed = passed && test_standard_hash(hashstream::SHA384, "SHA384", input, expected_hex_digest);

    return passed;
}

bool test_sha512(const std::string& input, const std::string& expected_hex_digest)
{
    bool passed = true;

    passed = passed && test_standard_hash(hashstream::SHA512, "SHA512", input, expected_hex_digest);

    return passed;
}

bool test_endl()
{
    bool passed = true;

    hashstream::hashstream hs(hashstream::SHA1);
    hs << "You can hash strings, or numbers: " << 34 << ", or even new-lines." << std::endl;

    std::string hd(hs.hex_digest());
    std::string expect("fe7613e7bc321648ddbc98c61b52fc4692b5c20a");
    if(hd != expect)
    {
        std::cerr << "using hashstream << std::string << int << std::string << std::endl:" << std::endl;
        report_fail("SHA1", "<input>", expect, hd);
        passed = false;
    }

    return passed;
}

int main(int argc, char** argv)
{
    bool passed = true;

    // ////// MD5 //////

    // from wikipedia
    passed = passed && test_md5("", "d41d8cd98f00b204e9800998ecf8427e");
    passed = passed && test_md5("The quick brown fox jumps over the lazy dog",
                                "9e107d9d372bb6826bd81d3542a419d6");
    passed = passed && test_md5("The quick brown fox jumps over the lazy dog.",
                                "e4d909c290d0fb1ca068ffaddf22cbd0");

    // ////// SHA1 //////

    // from wikipedia
    passed = passed && test_sha1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    passed = passed && test_sha1("The quick brown fox jumps over the lazy dog",
                                 "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    passed = passed && test_sha1("The quick brown fox jumps over the lazy cog",
                                 "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");

    // ////// SHA256 //////

    // from wikipedia
    passed = passed && test_sha256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    passed = passed && test_sha256("The quick brown fox jumps over the lazy dog",
                                   "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    passed = passed && test_sha256("The quick brown fox jumps over the lazy dog.",
                                   "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c");

    // from https://www.dlitz.net/crypto/shad256-test-vectors/
    passed = passed && test_sha256("abc",
                                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // from http://www.bichlmeier.info/sha256test.html
    passed = passed && test_sha256("message digest",
                                   "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
    passed = passed && test_sha256("secure hash algorithm",
                                   "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d");

    // ////// SHA384 //////

    // from wikipedia
    passed = passed && test_sha384("",
                                   "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
                                   "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    passed = passed && test_sha384("The quick brown fox jumps over the lazy dog",
                                   "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c49"
                                   "4011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");
    passed = passed && test_sha384("The quick brown fox jumps over the lazy dog.",
                                   "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6"
                                   "c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7");


    // ////// SHA512 //////

    // from wikipedia
    passed = passed && test_sha512("",
                                   "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                                   "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    passed = passed && test_sha512("The quick brown fox jumps over the lazy dog",
                                   "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64"
                                   "2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
    passed = passed && test_sha512("The quick brown fox jumps over the lazy dog.",
                                   "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb"
                                   "c6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed");

    // ////// MISC TESTS //////

    passed = passed && test_endl();

    return passed ? 0 : 1;
}
