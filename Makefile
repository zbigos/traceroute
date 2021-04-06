all:
	g++ -g -fsanitize=address -Wall -Wextra -c main.cpp
	g++ -g -Wall -Wextra -c netutils.cpp
	g++ -fsanitize=address -o main netutils.o main.o

clean:
	rm *.o
	rm main