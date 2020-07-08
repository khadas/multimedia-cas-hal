#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "UniversalClient_API.h"

#include "am_cas.h"
#include "ird_cas.h"

static char *errorCode[] = {
	ERR_MSG_D029,
	ERR_MSG_D100,
	ERR_MSG_E015,
	ERR_MSG_E016,
	ERR_MSG_E017,
	ERR_MSG_E018,
	ERR_MSG_E030,
	ERR_MSG_E031,
	ERR_MSG_E032,
	ERR_MSG_E600,
};

static char *screenText[] = {
	"D029-0  Service is currently descrambled.",
	"D100-0  EMM service OK or FTA service.",
	"E015-0  No valid entitlement found.",
	"E016-0  No valid entitlement found.",
	"E017-0  No valid sector found.",
	"E018-0  Product blackout.",
	"E030-0  P-Key mismatch.",
	"E031-0  G-Key mismatch.",
	"E032-0  TG mismatch.",
	"E600-0  Initialization has not been performed yet.",
};

int _find_errorcode_index(char *statusMsg)
{
	int index = 0;
	int total = sizeof(errorCode)/sizeof(char *);

	for (index = 0; index < total; index++)
	{
		if (strncmp(errorCode[index], statusMsg, strlen(errorCode[0])) == 0)
		{
			break;
		}
	}

	if (index == total)
	{
		return -1;
	}

	return index;
}

char* ird_get_screen_text(char *statusMsg, int *index)
{
	int error_index = -1;

	error_index = _find_errorcode_index(statusMsg);
	*index = error_index;

	return (error_index == -1)?AML_NULL:screenText[error_index];
}
