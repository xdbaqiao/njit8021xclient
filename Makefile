all:
	gcc -lpcap main.c aut.c -o h3c
clean:
	rm h3c
