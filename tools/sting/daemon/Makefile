all:

install:
	install -d -m 755 /usr/local/bin
	install -c -m 755 stingd /usr/local/bin/
	install -c -m 755 stingd_lib /usr/local/bin/
	install -m 755 sting /etc/init.d/
	ln -sf ../init.d/sting /etc/rc2.d/S00stingd
	install -m 755 sting_stop /etc/init.d/
	ln -sf ../init.d/sting_stop /etc/rc6.d/S35stingd
	ln -sf ../init.d/sting_stop /etc/rc0.d/S35stingd
clean:

uninstall: 
	rm -f /usr/local/bin/stingd
	rm -f /usr/local/bin/stingd_lib
	rm -f /etc/rc2.d/S00stingd
	rm -f /etc/rc6.d/S35stingd
	rm -f /etc/rc0.d/S35stingd
	rm -f /etc/init.d/sting
	rm -f /etc/init.d/sting_stop
