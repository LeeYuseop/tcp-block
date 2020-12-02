all: tcp-block

tcp-block: tcp-block.cpp
	g++ -o tcp-block tcp-block.cpp -lpcap

clean:
	rm -f tcp-block *.o
