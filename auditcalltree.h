#include "libaudit.h"

/*
 * Handle 1 audit event. Called from the main auditing loop whenever and 
 * audited resource is triggered.
 */
void handleevent(struct audit_dispatcher_header hdr, char* data);
