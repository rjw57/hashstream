The `hashstream` library
========================

This is a library that wraps up implementations of various standard hashing
functions into one library integrating with the C++ standard library.

Basic usage
-----------

See the `test/test_hashstream.cpp` file for a full example of usage. The gist
is:

    #include <iostream>
    #include <string>

    #include <hashstream/hashstream.hpp>

    int main(int argc, char** argv)
    {
      hashstream::hashstream hs(hashstream::SHA1);
      hs << "You can has strings, or numbers: " << 34 << ", or even new-lines." << std::endl;

      std::cout << hs; // print the hexadecimal digest.
      std::string hd(hs.hex_digest()); // or get it as a string.

      return 0;
    }

License
-------

The majority of this code is under a permissive BSD-style license. See the
`LICENSE` file for full details.
