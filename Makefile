all:
	g++ -g -fpermissive -fsanitize=address -c main.cpp
	g++ -g -c netutils.cpp
	g++ -g -c -fsanitize=address test.cpp


test:
	make all
	g++ -o tester netutils.o test.o
	./tester

run:
	make all
	g++ -fsanitize=address -o main netutils.o main.o
	./main


clean:
	rm *.o
	rm main
	rm tester