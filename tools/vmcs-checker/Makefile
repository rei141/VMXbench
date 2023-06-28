# Compiler settings
CC=gcc
CFLAGS=-fprofile-arcs -ftest-coverage
LDFLAGS=-lgcov --coverage

# Source files
SRC = main.c vmx.c
OBJ = $(SRC:.c=.o)

# Output binary
OUT = vmcscov

all: $(OUT)

# General rule for building object files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

coverage: clean all
	sudo ./$(OUT) # Assuming this runs your tests
	lcov --directory . --capture --output-file coverage.info
	genhtml coverage.info -s --output-directory out

clean:
	rm -f $(OBJ) $(OUT) *.gcda *.gcno *.gcov coverage.info
	rm -rf out

.PHONY: all clean coverage