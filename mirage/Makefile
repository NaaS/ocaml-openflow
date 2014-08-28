build:
	cd switch && make build

mirage/switch/Makefile: configure

configure:
	mirage configure --unix switch/config.ml

depend:
	cd switch && make depend

clean:
	cd switch && make clean

distclean:
	$(RM) log
	$(RM) switch/main.ml switch/Makefile switch/*.xl switch/mir-*
