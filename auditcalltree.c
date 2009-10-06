#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "auditcalltree.h"

char * getstat (char * pid) {
        int filenamelen = 11 + strlen(pid) + 1;
        int bufsize = 80;
        char buffer [bufsize];
        char * filename = (char *) malloc (filenamelen);
        snprintf (filename, filenamelen, "/proc/%s/stat", pid);
        int fd = open(filename, O_RDONLY);
        if (fd < 0) {
                fprintf (stderr, "Error opening %s: %s\n", filename, strerror(errno));
                free (filename);
                exit(3);
                return NULL;
        }
        int length = read (fd, buffer, bufsize);
        if (close (fd)) {
                fprintf(stderr, "Error closing file: %s\n", strerror(errno));
                exit(34);
        }
        free (filename);
        if (length < bufsize - 1)
                buffer[length]='\0';
	else
                buffer[bufsize - 1]='\0';

        return strdup(buffer);
}

char * getstatname (char * stat) {
	char* name = (char*) calloc(16, sizeof(char));

	if (sscanf(stat, "%*d (%15[^)]", name) == 1)
	{
		return name;
	}
	else
	{
		return NULL;
	}
}


char * getstatppid (char * stat) {
	char* ppid = (char*) calloc(16, sizeof(char));

	if (sscanf(stat, "%*d (%*15[^)]) %*c %[^ ]", ppid) == 1)
	{
		return ppid;
	}
	else
	{
		return NULL;
	}
}


static void logpidtrace(char* pid)
{
	char* stat = getstat(pid);
	char* progname = getstatname(stat);
	pid = strdup(pid);
	syslog(LOG_NOTICE,"pid %s (%s)", pid, progname);
	free(progname);

	char* ppid = getstatppid(stat);

	while (ppid != NULL && ppid[0] != '0')
	{
		progname = getstatname(stat);
		syslog(LOG_NOTICE,"pid %s has parent %s (%s)", pid, ppid, progname);
		free(progname);

		// move to next ancestor
		free(pid);
		pid = ppid;
		free(stat);
		stat = getstat(ppid);
		ppid = getstatppid(stat);
	}
	if (ppid != NULL)
	{
		free(ppid);
	}
	free(stat);
}

// handle events here. Writes the event plus process hierarchy to syslog
void handleevent(struct audit_dispatcher_header hdr, char* data) {
	char * piddata;

	syslog(LOG_NOTICE,"type=%d, payload size=%d", 
		hdr.type, hdr.size);
	syslog(LOG_NOTICE,"data=\"%.*s\"", hdr.size,
		data);
	if (hdr.size == MAX_AUDIT_MESSAGE_LENGTH)
	{
		data[MAX_AUDIT_MESSAGE_LENGTH - 1] = '\0';
	}
	else
	{
		data[hdr.size - 1] = '\0';
	}
	piddata = strstr(data, " pid=");
	if (piddata != NULL) {
		piddata = piddata + 5;
		*(strchr(piddata, ' ')) = '\0';
		logpidtrace(piddata);
	}
}
