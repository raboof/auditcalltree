all: clean auditcalltree restart

clean: 
	rm -f auditcalltree

auditcalltree: auditcalltree.c
	gcc -o auditcalltree auditcalltree.c -laudit

restart:
	sudo chown root auditcalltree
	sudo /etc/init.d/auditd restart
	sudo auditctl -w /etc/resolv.conf -p wr -k dns
