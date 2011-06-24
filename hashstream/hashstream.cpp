//  Copyright (c) 2011, Rich Wareham <rjw57@cam.ac.uk>
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//      * Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//      * Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
//      * Neither the name of the hashstream library nor the
//      names of its contributors may be used to endorse or promote products
//      derived from this software without specific prior written permission.
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

#include <istream>
#include <sstream>
#include <string>

#include <cstring> // for memcpy

#include "hashstream.hpp"

namespace hashstream
{
    // ////// hashbuf implementation //////

    hashbuf::hashbuf()
        : std::streambuf()
        , is_finalised_(false)
        , digest_size_(0)
    { }

    hashbuf::~hashbuf()
    { }

    const uint8_t* hashbuf::digest_bytes() const
    {
        if(!is_finalised_)
            throw std::runtime_error("hash not finalised when calling hashbuf::digest_bytes()");
        return digest_bytes_.get();
    }

    size_t hashbuf::digest_size() const
    {
        if(!is_finalised_)
            throw std::runtime_error("hash not finalised when calling hashbuf::digest_size()");
        return digest_size_;
    }

    void hashbuf::finalise()
    {
        if(is_finalised_)
            throw std::runtime_error("hashes may only be finalised once");
        this->xfinal();
        if(digest_size_ == 0)
            throw std::runtime_error("internal hash implementation did not set digest");
        is_finalised_ = true;
    }

    void hashbuf::ensure_finalised()
    {
        if(!is_finalised_)
            finalise();
    }

    bool hashbuf::is_finalised() const
    {
        return is_finalised_;
    }

    void hashbuf::set_digest(const uint8_t* bytes, size_t n_bytes)
    {
        digest_bytes_ = boost::shared_ptr<uint8_t>(new uint8_t[n_bytes]);
        memcpy(digest_bytes_.get(), bytes, n_bytes);
        digest_size_ = n_bytes;
    }

    int hashbuf::overflow(int c)
    {
        if((c >= 0) && (c <= 127))
        {
            char ch(c);
            this->xsputn(&ch, 1);
        }
        return 0;
    }

    // ////// hashstream implementation //////

    hashstream::hashstream(standard_hash hf)
        : std::ostream()
        , hb_(make_standard_hashbuf(hf))
    {
        // poke our hashbuf into the ostream
        std::ostream::rdbuf(hb_.get());
    }

    hashstream::hashstream(boost::shared_ptr<hashbuf> hb)
        : std::ostream(hb.get())
        , hb_(hb)
    { }

    hashstream::~hashstream()
    { }

    hashbuf* hashstream::rdbuf() const
    {
        return hb_.get();
    }

    std::string hashstream::hex_digest() const
    {
        hb_->ensure_finalised();
        size_t digest_size(hb_->digest_size());
        const uint8_t* digest_bytes(hb_->digest_bytes());

        if((digest_size == 0) || (digest_bytes == NULL))
            throw std::runtime_error("internal error: hash digest was NULL or zero-bytes in length.");

        std::stringstream ss;
        ss << std::hex;
        for(size_t i=0; i<digest_size; ++i)
        {
            ss << (digest_bytes[i] >> 4) << (digest_bytes[i] & 0xf);
        }

        return ss.str();
    }

    // ////// convenience wrappers //////

    std::istream& operator >> (std::istream& is, hashstream& hs)
    {
        hs << is.rdbuf();
        return is;
    }

    std::string hex_digest(standard_hash hf, const std::istream& is)
    {
        hashstream hs(hf);
        hs << is.rdbuf();
        return hs.hex_digest();
    }

    std::string hex_digest(standard_hash hf, const std::string& s)
    {
        hashstream hs(hf);
        hs << s;
        return hs.hex_digest();
    }

    std::ostream& operator<< (std::ostream& os, const hashbuf& hb)
    {
        os.write(reinterpret_cast<const char*>(hb.digest_bytes()), hb.digest_size());
        return os;
    }

    std::ostream& operator<< (std::ostream& os, const hashstream& hs)
    {
        os << hs.hex_digest();
        return os;
    }
}
