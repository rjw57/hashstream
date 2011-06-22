#ifndef __HASH_HPP
#define __HASH_HPP

#include <string>
#include <streambuf>
#include <istream>

#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>

/// @brief Cryptographic hash functions.
namespace hashstream
{
    /// @addtogroup hash
    /// @{

    /// @brief An enumeration of all standard hash functions supported by the hash library
    enum standard_hash
    {
        MD5,            ///< The venerable MD5 (not cryptographically safe)
        SHA1,           ///< SHA-1 (not cryptographically safe)
        SHA256,         ///< SHA-256 variant of SHA-2
        SHA384,         ///< SHA-384 variant of SHA-2
        SHA512,         ///< SHA-512 variant of SHA-2
    };

    /// @brief A std::streambuf implementation which computes the hash of its input.
    ///
    /// Each hash implementation within the hash library will implement a derived class from this one. This
    /// class provides the infrastructure to interface a hash function with the C++ standard iostream library.
    ///
    /// New hash functions should be added to the library by deriving from this class and implementing the
    /// xsputn and xfinal abstract virtual member functions.
    ///
    /// A user may define their own hash function and use it with a hashstream via the
    /// hashstream::hashstream(boost::shared_ptr< hashbuf >) constructor.
    ///
    /// @note The hashbuf class has the concept of 'finalisation'. Once a hash has been finalised it is no
    /// longer valid to attempt to push more data into it. Attempts at doing so will result in a
    /// std::runtime_error being thrown.
    class hashbuf : public std::streambuf
    {
        public:
            hashbuf();
            ~hashbuf();

            /// @brief Obtain a pointer to the computed digest.
            ///
            /// @throw std::runtime_error if called before finalise().
            const uint8_t*  digest_bytes() const;

            /// @brief Return the number of bytes in the computed digest.
            ///
            /// @throw std::runtime_error if called before finalise().
            size_t          digest_size() const;

            /// @brief Finalise the hash computation.
            ///
            /// For hashes which require a finalise step, this member function performs it and extracts the
            /// digest. Calls to digest_bytes() and digest_size() are only valid if this member function has
            /// been called.
            ///
            /// @throw std::runtime_error if finalise() has already been called.
            void finalise();

            /// @brief Ensure the hash computation has been finalised.
            ///
            /// It is valid to call ensure_finalised() multiple times. On the first invocation, finalise()
            /// will be called. Subsequent invocations will have no effect.
            void ensure_finalised();

            /// @brief Query if this hash has been finalised.
            bool is_finalised() const;

        protected:
            bool                        is_finalised_;      ///< Flag indicating if we're finalised.
            boost::shared_ptr<uint8_t>  digest_bytes_;      ///< Pointer to the digest.
            size_t                      digest_size_;       ///< Size of the digest.

            /// @brief Set the cached digest.
            ///
            /// Implementations of xfinal() should call this function to set the digest once it has been
            /// computed. The digest is copied locally and hence the memory referenced by \p bytes may be
            /// freed after this function returns.
            ///
            /// @param bytes A pointer to the computed digest.
            /// @param n_bytes The number of bytes in this digest.
            void set_digest(const uint8_t* bytes, size_t n_bytes);

            /// @brief Update the hash with a set of bytes.
            ///
            /// Overrides the std::streambuf::xsputn member function/
            ///
            /// @sa The C++ standard library.
            ///
            /// @param s
            /// @param n
            virtual std::streamsize xsputn(const char* s, std::streamsize n) = 0;

            /// @brief Finalise the hash and compute the digest.
            ///
            /// Called once via finalise(). Implementations may assume this will only be called once.
            /// Implementations should call set_digest() after computing the digest.
            virtual void xfinal() = 0;
    };

    /// @brief Construct a hashbuf representing a standard hash function.
    ///
    /// @param hf Which hash function to return.
    ///
    /// @return A boost::shared_ptr pointing to the new hashbuf.
    boost::shared_ptr<hashbuf> make_standard_hashbuf(standard_hash hf);

    /// @brief std::ostream derived class which can compute a hash
    ///
    /// Computing hashes is best done via the hashstream class. A hashstream can be used where any
    /// std::ostream instance could and allows for the querying of the digest via the hex_digest() member
    /// function.
    ///
    /// An example of using this class:
    ///
    /// @code
    /// hash::hashstream hs(hash::SHA256);
    /// hs << "The quick brown fox " << "jumps over the lazy dog";
    /// std::cout << hs; // prints "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    /// @endcode
    ///
    /// @note Attempting to insert more data to the hash after calling hex_digest() will result in Bad Things
    /// Happening.
    class hashstream : public std::ostream
    {
        public:
            /// @brief Construct a hashstream from a standard hash function.
            ///
            /// @param hf Which hash function to use.
            explicit hashstream(standard_hash hf);

            /// @brief Construct a hashstream from a custom hash function.
            ///
            /// Given a boost::shared_ptr to a custom hashbuf, make use of it to compute hashes for this
            /// stream.
            ///
            /// @param hb
            explicit hashstream(boost::shared_ptr<hashbuf> hb);

            ~hashstream();

            /// @brief Obtain the hashbuf instance associated with this stream.
            ///
            /// This overrides the std::ostream::rdbuf() member function.
            ///
            /// @sa The std::ostream::rdbuf() member function.
            hashbuf* rdbuf() const;

            /// @brief Compute the hash function.
            ///
            /// This is a convenience member function for those who simply need to output the digest to the
            /// user. If you want to get at the underlying digest's bytes, make use of the hashbuf pointer
            /// returned by rdbuf().
            ///
            /// @return A string giving the hexadecimal representation of the digest.
            std::string hex_digest() const;

        protected:
            boost::shared_ptr<hashbuf> hb_;     ///< The hashbuf used by this stream.
    };

    /// @brief Return a hex string giving the digest computed from a std::ifstream.
    ///
    /// Read bytes from \p is until the EOF condition is met and return a character string giving the
    /// hexadecimal representation of the SHA256 digest for the stream.
    ///
    /// @param hf Which function to compute.
    /// @param is A std::ifstream to read bytes from.
    std::string hex_digest(standard_hash hf, const std::istream& is);

    /// @brief Return a hex string giving the digest computed from the contents of a string.
    ///
    /// @param hf Which function to compute.
    /// @param s A reference to a string containing the data to compute a digest of.
    std::string hex_digest(standard_hash hf, const std::string& s);

    /// @brief Write the raw digest bytes for a hash to an output stream.
    ///
    /// @note This will write the raw digest bytes to some output. If you want the human-readable hex-string,
    /// use operator<< (std::ostream&, const hashstream&).
    ///
    /// @param os
    /// @param hb
    std::ostream& operator<< (std::ostream& os, const hashbuf& hb);

    /// @brief Write human-readable hex-formatted digest to an output stream.
    ///
    /// @param os
    /// @param hs
    std::ostream& operator<< (std::ostream& os, const hashstream& hs);

    /// @}
}

#endif // __HASH_HPP
