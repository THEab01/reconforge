setup:
	pip install -r requirements.txt
	$(MAKE) build

build:
	gcc -O2 -o binary/fast_scan binary/fast_scan.c

clean:
	rm -f binary/fast_scan
