#include <sys/cdefs.h>
/*
	nologin shell from FreeBSD
	Compiler run: cc -static -o nologin nologin.c
*/

#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#define MESSAGE "This account is currently not available.\n"

int main(int argc, char *argv[])
{
        const char *user, *tt;

        if ((tt = ttyname(0)) == NULL)
                tt = "UNKNOWN";
        if ((user = getlogin()) == NULL)
                user = "UNKNOWN";
        openlog("nologin", LOG_CONS, LOG_AUTH);
        syslog(LOG_CRIT, "Attempted login by %s on %s", user, tt);
        closelog();

        printf("%s", MESSAGE);
        return 1;
}

