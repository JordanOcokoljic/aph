aph
=====
Copyright 2020 Jordan Ocokoljic
Version 0.1.0, 7.6.2020

aph is a small command line tool that allows users to generate argon2id hashes
from the command line. It also includes utilities to measure how much time the
hash took to generate with the provided settings and the length of the
resulting as it would need to be stored in a database.


Usage
-------
When calling aph, you must provide the necessary parameters to use for the
generation of the hash. These are, the time, threads, memory and hash length.
For example:

aph 1s 2 64MB 32 mypassword

This call would generate a hash with the time parameter set to 1 second (the 
command line can also parse ms for milliseconds), the thread count parameter
set to 2 the memory parameter set to 64 megabytes (the command line can also
parse GB for gigabytes and KB for kilobytes), and a length of 32 bytes. The
basis of the hash is the final parameter "mypassword".

Optionally, a salt can be provided to be used in the hashing, rather than a
random salt being generated. For example:

aph 1s 2 64MB 32 mypassword mysalt

This call would use the salt "mysalt" when generating the hash.


Building
----------
To build aph, use the Go build command.

go build -o aph ./cmd

This will create an executable called aph.