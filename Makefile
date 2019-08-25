
nfqnl_test:
	gcc -o nfqnl_test main.cpp -lnetfilter_queue

clean:
	rm -rf nfqnl_test 
