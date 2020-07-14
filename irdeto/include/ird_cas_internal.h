/*
 * Copyright (C) 2015 Amlogic, Inc.
 *
 *
 */
#ifndef IRD_CAS_INTERNAL_H
#define IRD_CAS_INTERNAL_H

typedef enum
{
	IRD_PLAY_EMM = 0,
	IRD_PLAY_LIVE = 1,
	IRD_PLAY_PVR  = 2,
	IRD_PLAY_TIMESHIFT  = 3,
} IRD_SERVICE_TYPE;

typedef struct _service_monitor
{
    struct _service_monitor	*next;
    char	*monitorStr;
} service_monitor_st;

#endif // IRD_CAS_INTERNAL_H

