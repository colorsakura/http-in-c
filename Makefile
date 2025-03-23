all:
	clang --std=gnu23 -o server src/main.c

clean:
	rm server
