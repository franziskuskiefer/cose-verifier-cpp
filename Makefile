COSE_RUST_PATH=/home/franziskus/Code/cose-rust/target/debug/
COSE_RUST_LIB=cose

all:
	g++ main.cc -Werror -Wall -Wextra -o cose -L=$(COSE_RUST_PATH) -l$(COSE_RUST_LIB)

clean:
	rm -rf cose a.out
