## Tell the compiler where to find <openssl/pem.h> and <cryptlib.h>
#INCLUDES = -I/usr/local/openssl/include -I/usr/local/include

## Tell the compiler where to find the OpenSSL libraries.
#LIBS = -L/usr/local/openssl/lib

## Where is libcl.a?
CRYPTLIB = /usr/local/lib/libcl.a

## Cryptlib is usually linked with these libraries:
EXTRA_LIBS = -lresolv -lpthread

INCLUDES = -I/home/ams/build/cryptlib
CRYPTLIB = /home/ams/build/cryptlib/libcl.a

pemtrans: pemtrans.c
	cc $(INCLUDES) $(LIBS) -o pemtrans pemtrans.c $(CRYPTLIB) \
	-lssl $(EXTRA_LIBS)
