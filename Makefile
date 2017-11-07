COSE_RUST_PATH?=../cose-rust/target/debug/
NSS_LIB_DIR?=../dist/Debug/lib/
NSS_INCLUDE_DIR?=../dist/public/nss/
NSPR_INCLUDE_DIR?=../dist/Debug/include/nspr/
COSE_RUST_LIB=cose

all:
	g++ main.cc -Werror -Wall -Wextra -o cose -L$(NSS_LIB_DIR) \
	-L$(COSE_RUST_PATH) -l$(COSE_RUST_LIB) -lnss3 -I$(NSS_INCLUDE_DIR) \
	-I$(NSPR_INCLUDE_DIR)

clean:
	rm -rf cose a.out
