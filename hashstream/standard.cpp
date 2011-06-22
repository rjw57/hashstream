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
//      * Neither the name of the <organization> nor the
//	names of its contributors may be used to endorse or promote products
//	derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <istream>

#include "hashstream.hpp"

// Aladdin licensed MD5 implementation, see md5.c
#include "md5.h"

// Steve Reid's public domain implementation, see sha1.c
#include "sha1.h"

// Aaron D. Gifford's sha2 implementation, BSD licensed, see sha2.c
#include "sha2.h"

namespace hashstream
{
    /// @brief Standard hash function implementations
    /// @ingroup hash
    namespace standard
    {
        /// @addtogroup hash
        /// @{

        /// @brief Implementation of MD5 hash function.
        class md5_hashbuf : public hashbuf
        {
            public:
                md5_hashbuf()
                    : hashbuf()
                {
                    md5_init(&state_);
                }

                ~md5_hashbuf()
                { }

            protected:
                virtual std::streamsize xsputn(const char* s, std::streamsize n)
                {
                    md5_append(&state_, reinterpret_cast<const md5_byte_t*>(s), n);
                    return n;
                }

                virtual void xfinal()
                {
                    uint8_t digest[16];
                    md5_finish(&state_, digest);
                    set_digest(digest, 16);
                }

                md5_state_t  state_;
        };

        /// @brief Implementation of SHA-1 hash function.
        class sha1_hashbuf : public hashbuf
        {
            public:
                sha1_hashbuf()
                    : hashbuf()
                {
                    SHA1_Init(&ctx_);
                }

                ~sha1_hashbuf()
                { }

            protected:
                virtual std::streamsize xsputn(const char* s, std::streamsize n)
                {
                    SHA1_Update(&ctx_, reinterpret_cast<const uint8_t*>(s), n);
                    return n;
                }

                virtual void xfinal()
                {
                    uint8_t digest[SHA1_DIGEST_SIZE];
                    SHA1_Final(&ctx_, digest);
                    set_digest(digest, SHA1_DIGEST_SIZE);
                }

                SHA1_CTX  ctx_;
        };

        /// @brief Implementation of SHA-256 hash function.
        class sha256_hashbuf : public hashbuf
        {
            public:
                sha256_hashbuf()
                    : hashbuf()
                {
                    SHA256_Init(&ctx_);
                }

                ~sha256_hashbuf()
                { }

            protected:
                virtual std::streamsize xsputn(const char* s, std::streamsize n)
                {
                    SHA256_Update(&ctx_, reinterpret_cast<const uint8_t*>(s), n);
                    return n;
                }

                virtual void xfinal()
                {
                    uint8_t digest[SHA256_DIGEST_LENGTH];
                    SHA256_Final(digest, &ctx_);
                    set_digest(digest, SHA256_DIGEST_LENGTH);
                }

                SHA256_CTX  ctx_;
        };

        /// @brief Implementation of SHA-384 hash function.
        class sha384_hashbuf : public hashbuf
        {
            public:
                sha384_hashbuf()
                    : hashbuf()
                {
                    SHA384_Init(&ctx_);
                }

                ~sha384_hashbuf()
                { }

            protected:
                virtual std::streamsize xsputn(const char* s, std::streamsize n)
                {
                    SHA384_Update(&ctx_, reinterpret_cast<const uint8_t*>(s), n);
                    return n;
                }

                virtual void xfinal()
                {
                    uint8_t digest[SHA384_DIGEST_LENGTH];
                    SHA384_Final(digest, &ctx_);
                    set_digest(digest, SHA384_DIGEST_LENGTH);
                }

                SHA384_CTX  ctx_;
        };

        /// @brief Implementation of SHA-512 hash function.
        class sha512_hashbuf : public hashbuf
        {
            public:
                sha512_hashbuf()
                    : hashbuf()
                {
                    SHA512_Init(&ctx_);
                }

                ~sha512_hashbuf()
                { }

            protected:
                virtual std::streamsize xsputn(const char* s, std::streamsize n)
                {
                    SHA512_Update(&ctx_, reinterpret_cast<const uint8_t*>(s), n);
                    return n;
                }

                virtual void xfinal()
                {
                    uint8_t digest[SHA512_DIGEST_LENGTH];
                    SHA512_Final(digest, &ctx_);
                    set_digest(digest, SHA512_DIGEST_LENGTH);
                }

                SHA512_CTX  ctx_;
        };

        ///@}
    }

    boost::shared_ptr<hashbuf> make_standard_hashbuf(standard_hash hf)
    {
        switch(hf)
        {
            case MD5:
                return boost::shared_ptr<hashbuf>(new standard::md5_hashbuf());
            case SHA1:
                return boost::shared_ptr<hashbuf>(new standard::sha1_hashbuf());
            case SHA256:
                return boost::shared_ptr<hashbuf>(new standard::sha256_hashbuf());
            case SHA384:
                return boost::shared_ptr<hashbuf>(new standard::sha384_hashbuf());
            case SHA512:
                return boost::shared_ptr<hashbuf>(new standard::sha512_hashbuf());
            default:
                throw std::invalid_argument("unknown hash type passed to make_standard_hashbuf().");
        }

        /* unreachable */
    }
}
