all:
	g++ -g -fpermissive -c main.cpp
	g++ -g -c netutils.cpp
	g++ -g -c test.cpp
	g++ -g -c listener.cpp


test:
	make all
	g++ -o tester netutils.o test.o
	./tester

run:
	make all
	g++ -o main netutils.o main.o listener.o
	./main

clean:
	rm *.o
	rm main
	rm tester