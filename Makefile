CC     = gcc
CFLAGS = -Wall -Wextra -O2 -g

sniffer: sniffer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sniffer

.PHONY: clean
