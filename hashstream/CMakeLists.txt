#  Copyright (c) 2011, Rich Wareham <rjw57@cam.ac.uk>
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#      * Redistributions of source code must retain the above copyright
#	notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#	notice, this list of conditions and the following disclaimer in the
#	documentation and/or other materials provided with the distribution.
#      * Neither the name of the hashstream library nor the
#	names of its contributors may be used to endorse or promote products
#	derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL RICH WAREHAM BE LIABLE FOR ANY
#  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# We require the boost::shared_ptr class
find_package(Boost REQUIRED COMPONENTS system)
include_directories(${Boost_INCLUDE_DIRS})

# sha2 requires that the BYTE_ORDER macro be set appropriately to reflect the target machine endianness.
# This macro need only be set when compiling sha2.c itself though.
include(TestBigEndian)
test_big_endian(_is_big_endian)
if(_is_big_endian)
    set(_sha2_defines "-DBYTE_ORDER=BIG_ENDIAN")
else(_is_big_endian)
    set(_sha2_defines "-DBYTE_ORDER=LITTLE_ENDIAN")
endif(_is_big_endian)

# The hashstream library itself
add_library(hashstream
  hashstream.cpp
  standard.cpp
  md5.c
  sha1.c
  sha2.c
)
target_link_libraries(hashstream ${Boost_LIBRARIES})
set_target_properties(hashstream PROPERTIES COMPILE_FLAGS ${_sha2_defines})

# vim:sw=2:sts=2:et
