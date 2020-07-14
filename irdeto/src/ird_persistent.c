#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>

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
#include "ird_cas.h"

#define MAX_FILENAME_LEN  (256)
#define RESET_BUFFER_SIZE (1024)
#define INVALID_NUM     0xFF

#define PS_SOURCE_FILEPATH       "/vendor/etc/cas/irdeto/cadata"
//#define PS_FILEPATH              "/data/vendor/cas/irdeto/cadata"
#define PS_FILEPATH              "/data/vendor/irdeto/cadata"

#define PS_EXTENSION             "dat"

/*
** For cloaked ca 4.12.x with 2 operators, there are 11 (if nb_operators = 2) storages to support,
** if we also want to support watermarking feature.
** ((3*N+3) + 2 (for wma) (with N=nb_operators))
*/
#define NB_CLIENT_STORAGES   (11)

#define PS_FILENAME0         "cloaked_ca_0"
#define PS_FILESIZE0_LIMIT   (128*1024)
#define PS_SPECIFIED_INDEX0  (0)

#define PS_FILENAME1         "cloaked_ca_1"
#define PS_FILESIZE1_LIMIT   (640*1024)
#define PS_SPECIFIED_INDEX1  (1)

#define PS_FILENAME2         "cloaked_ca_2"
#define PS_FILESIZE2_LIMIT   (640*1024)
#define PS_SPECIFIED_INDEX2  (2)

#define PS_FILENAME9         "cloaked_ca_9"
#define PS_FILESIZE9_LIMIT   (4*1024)
#define PS_SPECIFIED_INDEX9  (9)

#define PS_FILENAME31        "cloaked_ca_31"
#define PS_FILESIZE31_LIMIT  (640*1024)
#define PS_SPECIFIED_INDEX31 (31)

#define PS_FILENAME32        "cloaked_ca_32"
#define PS_FILESIZE32_LIMIT  (640*1024)
#define PS_SPECIFIED_INDEX32 (32)

#define PS_FILENAME41         "cloaked_ca_41"
#define PS_FILESIZE41_LIMIT   (128*1024)
#define PS_SPECIFIED_INDEX41  (41)

#define PS_FILENAME51        "cloaked_ca_51"
#define PS_FILESIZE51_LIMIT  (128*1024)
#define PS_SPECIFIED_INDEX51 (51)

#define PS_FILENAME61        "cloaked_ca_61"
#define PS_FILESIZE61_LIMIT  (128*1024)
#define PS_SPECIFIED_INDEX61 (61)

#define PS_FILENAME62        "cloaked_ca_62"
#define PS_FILESIZE62_LIMIT  (128*1024)
#define PS_SPECIFIED_INDEX62 (62)

#define PS_FILENAME72        "cloaked_ca_72"
#define PS_FILESIZE72_LIMIT  (128*1024)
#define PS_SPECIFIED_INDEX72 (72)


struct IRD_sid_s
{
	char  filename[MAX_FILENAME_LEN];
	uint32_t spec_idx;
	uint32_t max_size;
};

static struct IRD_sid_s _storage[NB_CLIENT_STORAGES];

static uint8_t _reset_buffer[RESET_BUFFER_SIZE];

static uint32_t current_init_file_done = 0;
static uint32_t init_file_done_value = 0;


/*
** Function declaration.
*/
static uint32_t get_num_from_index(uint32_t index);
static Ird_status_t _reset_file(uint32_t index);
static Ird_status_t _init_file(uint32_t index);


/* Functions -------------------------------------------------------------- */
static uint32_t get_num_from_index(uint32_t index)
{
	uint32_t i, num = INVALID_NUM;

	for (i = 0; i < NB_CLIENT_STORAGES; i++)
	{
		if (_storage[i].spec_idx == index)
		{
			/* got it */
			num = i;
			goto end;
		}
	}

end:
	return num;
}

static Ird_status_t _copy_file_from(uint32_t num, char* path)
{
	char	mkcmd[MAX_FILENAME_LEN + 10]; /* +10 because strlen("mkdir -p") = 9 */
	char	cpcmd[MAX_FILENAME_LEN * 2 + 4]; /* +4 because strlen("cp") = 3 */

	if ( !access(_storage[num].filename, F_OK))
		return IRD_NO_ERROR;

	sprintf(mkcmd, "mkdir -p %s", PS_FILEPATH);

	/* Create directory (and all parents) if not exist */
	if (0 != system(mkcmd))
	{
		CA_DEBUG(0, "[%s]: cannot create dir %s (can be already existing)\n",
	            __FUNCTION__, PS_FILEPATH);
	}
	else
	{
		CA_DEBUG(0, "[%s]: dir %s created\n", __FUNCTION__, PS_FILEPATH);
	}

	sprintf(cpcmd, "cp %s %s", path, PS_FILEPATH);

	/* Copy files from source file path if they exist under PS_SOURCE_FILEPATH */
	if (0 != system(cpcmd))
	{
		CA_DEBUG(0, "[%s]: cannot copy file %s from %s\n", __FUNCTION__,
                    _storage[num].filename, PS_SOURCE_FILEPATH);
		return IRD_FAILURE;
	}
	else
	{
		CA_DEBUG(0, "[%s]: successfully copy file %s from %s\n", __FUNCTION__,
                    _storage[num].filename, PS_SOURCE_FILEPATH);
		return IRD_NO_ERROR;
	}
}

static Ird_status_t _reset_file(uint32_t num)
{
	uint32_t	i, nb_chunks;
	uint32_t	offset;
	int     	file_handle;
	int     	writtenLength;
	uint32_t  	chunkSize;
	char    	mkcmd[MAX_FILENAME_LEN + 10]; /* +10 because strlen("mkdir -p") = 9 */

	sprintf(mkcmd, "mkdir -p %s", PS_FILEPATH);

	/* Create directory (and all parents) if not exist */
	if (0 != system(mkcmd))
	{
		CA_DEBUG(0, "[%s]: cannot create dir %s (can be already existing)\n",
		                __FUNCTION__, PS_FILEPATH);
	}
	else
	{
		CA_DEBUG(0, "[%s]: dir %s created\n", __FUNCTION__, PS_FILEPATH);
	}

	/* create new file */
	if ((file_handle = open(_storage[num].filename,
	                      O_WRONLY|O_CREAT|O_TRUNC,
	                      S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be opened\n",
		                __FUNCTION__, _storage[num].filename);
		return IRD_FAILURE;
	}

	/* fill entire file with reset buffer contents (0xFF) */
	if (_storage[num].max_size < RESET_BUFFER_SIZE)
	{
		chunkSize = _storage[num].max_size;
	}
	else
	{
		/* ! _storage[index].max_size has to be multiple of RESET_BUFFER_SIZE */
		chunkSize = RESET_BUFFER_SIZE;
	}

	nb_chunks = _storage[num].max_size / chunkSize;
	for (i = 0, offset = 0; i < nb_chunks; i++)
	{
		writtenLength = write(file_handle, (void *)_reset_buffer, chunkSize);
		if (writtenLength != (int)chunkSize)
		{
			CA_DEBUG(0, "[%s]: failed to write %d bytes at offset %d"
			              " into file %s\n",
			              __FUNCTION__, chunkSize, offset, _storage[num].filename);
			close(file_handle);
			return IRD_FAILURE;
		}

		offset += writtenLength;
	}

	close(file_handle);

	return IRD_NO_ERROR;
}

static Ird_status_t _init_file(uint32_t num)
{
	Ird_status_t  status = IRD_NO_ERROR;
	int     file_handle;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	/* Try init only NB_CLIENT_STORAGES times.
	* (if the init fails, then it won't be retry, but then
	* the mw is expected to perform persistent reset if read/write
	* functions are failing) */
	if (current_init_file_done == init_file_done_value)
	{
		CA_DEBUG(0, "[%s]: index=%d, current_init_file_done=%d, "
                    "init_file_done_value=%d (init done)\n",
                    __FUNCTION__, num, current_init_file_done, init_file_done_value);
		goto end;
	}

	current_init_file_done |= 1 << num;

	/* Do nothing if file already exist */
	if ((file_handle = open(_storage[num].filename,
                          O_RDWR,
                          S_IRWXU | S_IRWXG | S_IRWXO)) >= 0)
	{
		/* File exists, ok */
	    CA_DEBUG(0, "[%s]: file %s exist, ok\n",
	                    __FUNCTION__, _storage[num].filename);
		close(file_handle);
		goto end;
	}

	CA_DEBUG(0, "[%s] : _init_file: file %s does not exist, "
                  "create it\n",
                  __FUNCTION__, _storage[num].filename);

	/* Create new file and fill with initial content */
	if (IRD_NO_ERROR != _reset_file(num))
	{
		CA_DEBUG(0, "[%s]: failed to create new file %s\n",
	                    __FUNCTION__, _storage[num].filename);
		status = IRD_FAILURE;
		goto end;
	}

end:
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return status;
}


uc_result UniversalClientSPI_PS_Delete(uc_uint32 index)
{
	uc_result	status = UC_ERROR_NULL_PARAM;
	uint32_t	num = get_num_from_index(index);

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	/* Check valid Storage ID */
	if (INVALID_NUM == num)
	{
		CA_DEBUG(0, "[%s]: invalid id %p\n", __FUNCTION__, index);
		status = UC_ERROR_RESOURCE_NOT_FOUND;
		goto end;
	}

	/* Reset the file */
	if (IRD_NO_ERROR != _reset_file(num))
	{
		CA_DEBUG(0, "[%s]: failed to reset file\n", __FUNCTION__);
		goto end;
	}

	status = UC_ERROR_SUCCESS;

end:
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return status;
}


uc_result UniversalClientSPI_PS_Write(uc_uint32 index, uc_uint32 offset, const uc_buffer_st *pData)
{
	uc_result	status = UC_ERROR_NULL_PARAM;
	uint32_t	num = get_num_from_index(index);
	int			file_handle;
	int			writtenLength;
	uint32_t	num_bytes = 0;
	uint32_t	first_byte = 0;
	uint8_t		*p_buffer;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	first_byte = offset;
	num_bytes = pData->length;
	p_buffer = pData->bytes;

	/* Check valid Storage ID */
	if (INVALID_NUM == num)
	{
		CA_DEBUG(0, "[%s]: invalid id %p\n", __FUNCTION__, index);
		status = UC_ERROR_RESOURCE_NOT_FOUND;
		goto end;
	}

	/* Initial storage file creation (done only once)
	* (Delayed due to modules dependency in the init sequence) */
	_init_file(num);

	/* check file boundary */
	if (num_bytes + first_byte > _storage[num].max_size)
	{
		CA_DEBUG(0, "[%s]: limit reached: first_byte=%d + num_bytes=%d > %d\n",
						__FUNCTION__, first_byte, num_bytes, _storage[num].max_size);
		goto end;
	}

	/* open existing file */
	if ((file_handle = open(_storage[num].filename,
							  O_RDWR,
							  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be created\n",
						__FUNCTION__, _storage[num].filename);
		goto end;
	}

	/* write at wanted offset */
	if (lseek((int)file_handle, first_byte, SEEK_SET) == -1)
	{
		CA_DEBUG(0, "[%s]: file %s could not be seeked\n",
						__FUNCTION__, _storage[num].filename);
		close(file_handle);
		goto end;
	}

	writtenLength = write(file_handle, (void *)p_buffer, num_bytes);
	if (writtenLength != (int)num_bytes)
	{
		CA_DEBUG(0, "[%s]: failed to write %d bytes at offset %d into"
						" file %s\n",
						__FUNCTION__, num_bytes, first_byte, _storage[num].filename);
		close(file_handle);
		goto end;
	}

	/* close file */
	if (0 != close(file_handle))
	{
		CA_DEBUG(0, "[%s]: failed to close file %s\n",
						__FUNCTION__,  _storage[num].filename);
		goto end;
	}

	status = UC_ERROR_SUCCESS;

end:
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return status;
}


uc_result UniversalClientSPI_PS_Read(uc_uint32 index, uc_uint32 offset, uc_buffer_st *pData)
{
	uc_result	status = UC_ERROR_NULL_PARAM;
	uint32_t	num = get_num_from_index(index);
	int			readLength = 0;
	int			file_handle;
	uint32_t	num_bytes = 0;
	uint32_t	first_byte = 0;
	uint8_t		*p_buffer;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	first_byte = offset;
	num_bytes = pData->length;
	p_buffer = pData->bytes;

	/* Check valid Storage ID */
	if (INVALID_NUM == num)
	{
		CA_DEBUG(0, "[%s]: invalid id %p\n", __FUNCTION__, index);
		status = UC_ERROR_RESOURCE_NOT_FOUND;
		goto end;
	}

	/* Initial storage file creation (done only once)
	** (Delayed due to modules dependency in the init sequence)
	*/
	_init_file(num);

	/* check file boundary */
	if (num_bytes + first_byte > _storage[num].max_size)
	{
		CA_DEBUG(0, "[%s]: limit reached: first_byte=%d + num_bytes=%d > %d\n",
					__FUNCTION__, first_byte, num_bytes, _storage[num].max_size);
		goto end;
	}

	/* open existing file */
	if ((file_handle = open(_storage[num].filename, O_RDONLY,
							  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be opened\n",
						__FUNCTION__, _storage[num].filename);
		goto end;
	}

	/* read at wanted offset */
	if (lseek((int)file_handle, offset, SEEK_SET) == -1)
	{
		CA_DEBUG(0, "[%s]: file %s could not be seeked\n",
						__FUNCTION__, _storage[num].filename);
		close(file_handle);
		goto end;
	}

	readLength = read(file_handle, p_buffer, num_bytes);
	if (readLength != (int)num_bytes)
	{
		CA_DEBUG(0, "[%s]: failed to read %d bytes at offset %d "
						"from file %s\n",
						__FUNCTION__, num_bytes, first_byte, _storage[num].filename);
		close(file_handle);
		goto end;
	}

	/* close file */
	if (0 != close(file_handle))
	{
		CA_DEBUG(0, "[%s]: failed to close file %s\n",
						__FUNCTION__, _storage[num].filename);
		goto end;
	}

	status = UC_ERROR_SUCCESS;

end:
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return status;
}

uc_result UniversalClientSPI_PS_GetProperty(uc_uint32 index, uc_ps_property *pProperty)
{
	uint32_t	num = get_num_from_index(index);

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	pProperty->reservedSize = _storage[num].max_size;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}


uc_result UniversalClientSPI_PS_Initialize(void)
{
	char source_file[MAX_FILENAME_LEN];

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	/*
	** Specified index 0.
	*/
	sprintf(_storage[0].filename,
		  PS_FILEPATH"/"PS_FILENAME0"."PS_EXTENSION);

	_storage[0].spec_idx = PS_SPECIFIED_INDEX0;
	_storage[0].max_size = PS_FILESIZE0_LIMIT;

	init_file_done_value |= 1 << 0;

	/*
	** Specified index 1.
	*/
	sprintf(_storage[1].filename,
		  PS_FILEPATH"/"PS_FILENAME1"."PS_EXTENSION);

	_storage[1].spec_idx = PS_SPECIFIED_INDEX1;
	_storage[1].max_size = PS_FILESIZE1_LIMIT;

	memset(source_file, '\0', MAX_FILENAME_LEN);
	sprintf(source_file, PS_SOURCE_FILEPATH"/"PS_FILENAME1"."PS_EXTENSION);
	/* Copy from source file */
	if (IRD_NO_ERROR != _copy_file_from(1, &source_file))
	{
		CA_DEBUG(0, "[%s]: failed to copy file %s\n", __func__, _storage[1].filename);
	}

	init_file_done_value |= 1 << 1;

	/*
	** Specified index 2.
	*/
	sprintf(_storage[2].filename,
		  PS_FILEPATH"/"PS_FILENAME2"."PS_EXTENSION);

	_storage[2].spec_idx = PS_SPECIFIED_INDEX2;
	_storage[2].max_size = PS_FILESIZE2_LIMIT;

	init_file_done_value |= 1 << 2;

	/*
	** Specified index 9.
	*/
	sprintf(_storage[3].filename,
		  PS_FILEPATH"/"PS_FILENAME9"."PS_EXTENSION);

	_storage[3].spec_idx = PS_SPECIFIED_INDEX9;
	_storage[3].max_size = PS_FILESIZE9_LIMIT;

	memset(source_file, 0, MAX_FILENAME_LEN);
	sprintf(source_file, PS_SOURCE_FILEPATH"/"PS_FILENAME9"."PS_EXTENSION);
	/* Copy from source file */
	if (IRD_NO_ERROR != _copy_file_from(3, &source_file))
	{
		CA_DEBUG(0, "[%s]: failed to copy file %s\n", __func__, _storage[3].filename);
	}

	init_file_done_value |= 1 << 3;

	/*
	** Specified index 31.
	*/
	sprintf(_storage[4].filename,
		  PS_FILEPATH"/"PS_FILENAME31"."PS_EXTENSION);

	_storage[4].spec_idx = PS_SPECIFIED_INDEX31;
	_storage[4].max_size = PS_FILESIZE31_LIMIT;

	init_file_done_value |= 1 << 4;

	/*
	** Specified index 32.
	*/
	sprintf(_storage[5].filename,
		  PS_FILEPATH"/"PS_FILENAME32"."PS_EXTENSION);

	_storage[5].spec_idx = PS_SPECIFIED_INDEX32;
	_storage[5].max_size = PS_FILESIZE32_LIMIT;

	init_file_done_value |= 1 << 5;

	/*
	** Specified index 41.
	*/
	sprintf(_storage[6].filename,
		  PS_FILEPATH"/"PS_FILENAME41"."PS_EXTENSION);

	_storage[6].spec_idx = PS_SPECIFIED_INDEX41;
	_storage[6].max_size = PS_FILESIZE41_LIMIT;

	init_file_done_value |= 1 << 6;

	/*
	** Specified index 51.
	*/
	sprintf(_storage[7].filename,
		  PS_FILEPATH"/"PS_FILENAME51"."PS_EXTENSION);

	_storage[7].spec_idx = PS_SPECIFIED_INDEX51;
	_storage[7].max_size = PS_FILESIZE51_LIMIT;

	init_file_done_value |= 1 << 7;

	/*
	** Specified index 61.
	*/
	sprintf(_storage[8].filename,
		  PS_FILEPATH"/"PS_FILENAME61"."PS_EXTENSION);

	_storage[8].spec_idx = PS_SPECIFIED_INDEX61;
	_storage[8].max_size = PS_FILESIZE61_LIMIT;

	init_file_done_value |= 1 << 8;

	/*
	** Specified index 62. For watermark feature.
	*/
	sprintf(_storage[9].filename,
		  PS_FILEPATH"/"PS_FILENAME62"."PS_EXTENSION);

	_storage[9].spec_idx = PS_SPECIFIED_INDEX62;
	_storage[9].max_size = PS_FILESIZE62_LIMIT;

	memset(source_file, 0, MAX_FILENAME_LEN);
	sprintf(source_file, PS_SOURCE_FILEPATH"/"PS_FILENAME62"."PS_EXTENSION);

	/* Copy from source file */
	if (IRD_NO_ERROR != _copy_file_from(9, &source_file))
	{
		CA_DEBUG(0, "[%s]: failed to copy file %s\n", __func__, _storage[9].filename);
	}

	init_file_done_value |= 1 << 9;

	/*
	** Specified index 72. For watermark feature.
	*/
	sprintf(_storage[10].filename,
		  PS_FILEPATH"/"PS_FILENAME72"."PS_EXTENSION);

	_storage[10].spec_idx = PS_SPECIFIED_INDEX72;
	_storage[10].max_size = PS_FILESIZE72_LIMIT;

	init_file_done_value |= 1 << 10;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_PS_Terminate(void)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	/*
	** do noting.
	*/

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

