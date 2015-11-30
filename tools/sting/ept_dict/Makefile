all:
	$(CC) $(CFLAGS) -static read_ept_dict.c -o sting_read_ept_dict
	$(CC) $(CFLAGS) -static restore_ept_dict.c -o sting_restore_ept_dict

install:
	install -d -m 755 /usr/local/bin
	install -c -m 755 sting_read_ept_dict /usr/local/bin/
	install -c -m 755 sting_restore_ept_dict /usr/local/bin/
	install -c -m 755 sting_save_ept_dict /usr/local/bin/

clean:
	rm sting_read_ept_dict
	rm sting_restore_ept_dict

uninstall:
	rm /usr/local/bin/sting_read_ept_dict
	rm /usr/local/bin/sting_restore_ept_dict
	rm /usr/local/bin/sting_save_ept_dict
