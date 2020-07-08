#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>

#include "UniversalClient_API.h"
#include "UniversalClient_Common_SPI.h"
#include "UniversalClient_IPTV_API.h"
#include "UniversalClient_Stdlib.h"
#include "UniversalClient_Common_API.h"
#include "UniversalClient_DVB_API.h"
#include "UniversalClient_SPI.h"
#include "UniversalClient_Types.h"

//#undef ANDROID

#include "am_cas.h"
#include "caclientapi.h"
#include "ird_cas.h"


#define NULL 0
#define MAX_TASK_NAME 128


static uint32_t cas_task_num = 0;


typedef enum {
	DKI_TASK_STATE_RUNNING = 0,
	DKI_TASK_STATE_STOPPED,
	DKI_TASK_STATE_INVALID,
}task_status;

struct task_ctx {
	DKI_tid_t		taskid;
	char			*name;
	uint32_t		count;
	task_status	status;
	struct task_ctx *next;
};

struct task_ctx *task_head = NULL;
pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;

Ird_status_t task_ctx_init(void)
{
	task_head = (struct task_ctx *)malloc(sizeof(*task_head));
	if (task_head == NULL)
	{
		return IRD_FAILURE;
	}

	task_head->taskid = 0;
	task_head->next = NULL;
	task_head->count = 0;
	task_head->status = DKI_TASK_STATE_INVALID;
	task_head->name = NULL;

	return IRD_NO_ERROR;
}

Ird_status_t task_ctx_insert(DKI_tid_t taskid, const char *name)
{
	struct task_ctx *new_task, *tmp;
	if (task_head == NULL)
	{
		task_ctx_init();
	}

	new_task = (struct task_ctx *)malloc(sizeof(*new_task));
	if (new_task == NULL)
	{
		return IRD_FAILURE;
	}

	new_task->taskid = taskid;
	new_task->next = NULL;
	new_task->count = task_head->count;
	task_head->status = DKI_TASK_STATE_RUNNING;
	new_task->name = (char *)malloc(strlen(name) + 1);
	memcpy(new_task->name, name, strlen(name));
	(task_head->count)++;

	tmp = task_head;
	while (tmp->next != NULL)
	{
		tmp = tmp->next;
	}

	tmp->next = new_task;

	return IRD_NO_ERROR;
}

void task_ctx_delete(DKI_tid_t taskid)
{
	struct task_ctx *tmp = task_head;
	struct task_ctx *delete_task;

	while (tmp->next != NULL && tmp->next->taskid != taskid)
	{
		tmp = tmp->next;
	}

	if (tmp->next != NULL)
	{
		delete_task = tmp->next;
		tmp->next = delete_task->next;

		if (delete_task->name)
		{
			free(delete_task->name);
		}

		free(delete_task);
	}

	return;
}

struct task_ctx *task_ctx_find(DKI_tid_t taskid)
{
	struct task_ctx *tmp = task_head;

	while (tmp->next != NULL && tmp->next->taskid != taskid)
	{
		tmp = tmp->next;
	}

	tmp = tmp->next;

	return tmp;
}

void set_task_status(DKI_tid_t taskid, task_status status)
{
	struct task_ctx *tmp;
	tmp = task_ctx_find(taskid);
	if (tmp != NULL)
	{
		tmp->status = status;
	}

	return ;
}

task_status get_task_status(DKI_tid_t taskid)
{
	struct task_ctx *tmp;
	tmp = task_ctx_find(taskid);
	if (tmp != NULL)
	{
	    return tmp->status;
	}

	return DKI_TASK_STATE_INVALID;
}

void* UniversalClientSPI_Memory_Malloc(uc_uint32 bytes)
{
	return malloc(bytes);
}

void UniversalClientSPI_Memory_Free(void * lpVoid)
{
	free(lpVoid);
	return;
}

void UniversalClientSPI_FatalError(uc_fatal_error_type type, void* lpVoid)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(3, "%s error_type: %d, %s", __FUNCTION__, type, lpVoid);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return;
}

uc_result UniversalClientSPI_Semaphore_Open(uc_uint32 initialValue,
                                             uc_semaphore_handle * pSemaphoreHandle)
{
	sem_t *sem = NULL;
	int err;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	sem = (sem_t *)malloc(sizeof(sem_t));
	if (sem != NULL)
	{
		err = sem_init(sem, 0, initialValue);
		if (err != 0)
		{
			free(sem);
			sem = NULL;
		}
	}

	if (sem == NULL)
	{
		CA_DEBUG(0, "[%s]: Failed to init semaphore\n", __FUNCTION__);
		return UC_ERROR_OUT_OF_MEMORY;
	}

	*pSemaphoreHandle = (uc_semaphore_handle *)sem;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Semaphore_Post(uc_semaphore_handle semaphoreHandle)
{
	int err;

	//CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (semaphoreHandle != NULL)
	{
		err = sem_post((sem_t *)semaphoreHandle);
		if (err != 0)
		{
			CA_DEBUG(0, "[%s]: Failed to unlock semaphore 0x%p, error %d", __FUNCTION__, semaphoreHandle, errno);
		}
	}
	else
	{
		CA_DEBUG(0, "[%s]: NULL semaphore", __FUNCTION__);
	}

	//CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}


uc_result UniversalClientSPI_Semaphore_Wait(uc_semaphore_handle semaphoreHandle)
{
	int err;

	//CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (semaphoreHandle != NULL)
	{
		err = sem_wait((sem_t *)semaphoreHandle);
		if (err != 0)
		{
			CA_DEBUG(0, "[%s]: Failed to lock semaphore 0x%p, error %d", __FUNCTION__, semaphoreHandle, errno);
		}
	}
	else
	{
		CA_DEBUG(0, "[%s]: NULL semaphore", __FUNCTION__);
	}

	//CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Semaphore_WaitTimeout(uc_semaphore_handle semaphoreHandle, uc_uint32 milliseconds)
{
   struct timeval tv;
   struct timespec abs_timeout;
   uint32_t usec;
   int err;
   uc_result result = UC_ERROR_SUCCESS;

   CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

   if (semaphoreHandle != NULL)
   {
		gettimeofday(&tv, NULL);
		usec = tv.tv_usec + (1000 * milliseconds);
		while (usec >= 1000000)
		{
			usec -= 1000000;
			tv.tv_sec++;
		}
		abs_timeout.tv_sec = tv.tv_sec;
		abs_timeout.tv_nsec = 1000 * usec;

		do
		{
			err = sem_timedwait((sem_t *)semaphoreHandle, &abs_timeout);
		} while (err == -1 && errno == EINTR);   /* Restart when interrupted by handler */

		if (err != 0)
		{
			result = UC_ERROR_NULL_PARAM;
			if (errno != ETIMEDOUT)
			{
				CA_DEBUG(0, "[%s]: Failed to lock semaphore 0x%p, error %d", __FUNCTION__, semaphoreHandle, errno);
			}
		}
	}
	else
	{
		CA_DEBUG(0, "[%s]: NULL semaphore", __FUNCTION__);
		result = UC_ERROR_NULL_PARAM;
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return result;
}

uc_result UniversalClientSPI_Semaphore_Close(uc_semaphore_handle * pSemaphoreHandle)
{
	int err;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	printf("*pSemaphoreHandle; %x \n", *pSemaphoreHandle);

	if (*pSemaphoreHandle != NULL)
	{
		err = sem_destroy((sem_t *)*pSemaphoreHandle);
		if (err != 0)
		{
			CA_DEBUG(0, "[%s]: Failed to destroy semaphore 0x%x, error %d", __FUNCTION__, pSemaphoreHandle, errno);
		}

		free(*pSemaphoreHandle);
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Mutex_Open(uc_mutex_handle * pMutexHandle)
{
	int ret;
	pthread_mutex_t *mutex = NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));

	ret = pthread_mutex_init(mutex, NULL);
	if (ret != 0)
	{
		free(mutex);
		return UC_ERROR_OUT_OF_MEMORY ;
	}

	*pMutexHandle = mutex;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Mutex_Lock(uc_mutex_handle mutexHandle)
{
	//CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (mutexHandle != NULL)
	{
		pthread_mutex_lock(mutexHandle);
	}

	//CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Mutex_Unlock(uc_mutex_handle mutexHandle)
{
	//CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (mutexHandle != NULL)
	{
		pthread_mutex_unlock(mutexHandle);
	}

	//CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Mutex_Close(uc_mutex_handle * pMutexHandle)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (*pMutexHandle != NULL)
	{
		pthread_mutex_unlock(*pMutexHandle);
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Thread_Open(uc_threadproc threadProc,
                                       void* lpVoid, uc_thread_handle * pThreadHandle)
{
	DKI_tid_t pthread_id;
	char taskName[MAX_TASK_NAME];

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (pthread_create(&pthread_id, NULL,
				  (void *(* _Nonnull)(void *))threadProc, lpVoid) != 0)
	{
		CA_DEBUG(0, "[%s]: pthread_create error\n", __FUNCTION__);
		return UC_ERROR_NULL_PARAM;
	}

#if 0
	pthread_attr_t thread_attr;
	struct sched_param schedule_param;

	pthread_attr_init(&thread_attr);
	schedule_param.sched_priority = 50;
	pthread_attr_setinheritsched(&thread_attr, PTHREAD_EXPLICIT_SCHED); //有这行，设置优先级才会生效
	pthread_attr_setschedpolicy(&thread_attr,SCHED_RR);
	pthread_attr_setschedparam(&thread_attr, &schedule_param);

	pthread_create(&pthread_id, &thread_attr, threadProc, lpVoid);
#endif

	sprintf(taskName, "Cloaked_CA_TASK_%d", cas_task_num);

	pthread_mutex_lock(&task_mutex);
	task_ctx_insert(pthread_id, taskName);
	pthread_mutex_unlock(&task_mutex);

	CA_DEBUG(0, "[%s]: pthread_create success: %s\n", __FUNCTION__, taskName);

	*pThreadHandle = &pthread_id;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}


uc_result UniversalClientSPI_Thread_Sleep(uc_thread_handle hThreadHandle, uc_uint16 wDelay)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	usleep(wDelay * 1000);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Thread_Close(uc_thread_handle * pThreadHandle)
{
	struct task_ctx *tmp, *delete_task;
	DKI_tid_t pthread_id;
	void *status;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	pthread_id = (DKI_tid_t)*pThreadHandle;

	if (*pThreadHandle != NULL)
	{
		pthread_join(pthread_id, &status);
	}

	pthread_mutex_lock(&task_mutex);
	set_task_status(pthread_id, DKI_TASK_STATE_STOPPED);
	task_ctx_delete(pthread_id);
	pthread_mutex_unlock(&task_mutex);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}


