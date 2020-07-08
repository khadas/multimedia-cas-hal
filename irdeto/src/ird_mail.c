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
#include <fcntl.h>

#include "am_cas.h"
#include "ird_cas.h"

#define MAIL_SAVE_FILEPATH       "/data/vendor/irdeto/mailbox"
#define MAIL_INDEX_FILENAME      "index"
#define MAIL_FILENAME_PREFIX      "mail_"

#define MAX_MAIL_NUM       (20)
#define MAX_MAIL_FILENAME_LEN (256)
#define MAX_MAIL_SEQUENCE_STR (128)

static pthread_mutex_t _mail_lock = PTHREAD_MUTEX_INITIALIZER;
static int b_mail_ready = 0;
static int index_sequence[MAX_MAIL_NUM] = {0};
static int valid_num = 0;

static void _split(char *src, const char *separator, char **dest, int *num)
{
    /*
        src 源字符串的首地址(buf的地址)
        separator 指定的分割字符
        dest 接收子字符串的数组
        num 分割后子字符串的个数
    */
     char *pNext;
     int count = 0;

     if (src == NULL || strlen(src) == 0) //如果传入的地址为空或长度为0，直接终止
        return;

     if (separator == NULL || strlen(separator) == 0) //如未指定分割的字符串，直接终止
        return;

     pNext = (char *)strtok(src,separator); //必须使用(char *)进行强制类型转换(虽然不写有的编译器中不会出现指针错误)
     while (pNext != NULL) {
          *dest++ = pNext;
          ++count;
         pNext = (char *)strtok(NULL,separator);  //必须使用(char *)进行强制类型转换
    }

    *num = count;
}

static int _check_index(int index)
{
	int idx = 0;
	int bFound = 0;
	for (idx = 0; idx < valid_num; idx++)
	{
		if (index == index_sequence[idx])
		{
			bFound = 1;
			break;
		}
	}

	return bFound;
}

static void _mail_init()
{
	char	mkcmd[MAX_MAIL_FILENAME_LEN + 10]; /* +10 because strlen("mkdir -p") = 9 */
	char	file_path[MAX_MAIL_FILENAME_LEN];
	int		file_handle;
	char	*p_buffer = AML_NULL, *start_addr = AML_NULL, *end_addr = AML_NULL;
	int		length = 0, readLength = 0;
	char	*revbuf[MAX_MAIL_NUM] = {0};
	int		index = 0;

	if (b_mail_ready == 0)
	{
		if (-1 == access(MAIL_SAVE_FILEPATH, F_OK))
		{
			sprintf(mkcmd, "mkdir -p %s", MAIL_SAVE_FILEPATH);
			if (0 != system(mkcmd))
			{
				CA_DEBUG(0, "[%s]: cannot create dir %s (can be already existing)\n",
			            __FUNCTION__, MAIL_SAVE_FILEPATH);

				goto end;
			}
			else
			{
				CA_DEBUG(0, "[%s]: dir %s created\n", __FUNCTION__, MAIL_SAVE_FILEPATH);
			}
		}

		memset(index_sequence, -1, MAX_MAIL_NUM);
		sprintf(file_path, MAIL_SAVE_FILEPATH"/"MAIL_INDEX_FILENAME);
		if (0 == access(file_path, F_OK))
		{
			if ((file_handle = open(file_path, O_RDONLY,
								  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
			{
				CA_DEBUG(0, "[%s]: file %s could not be opened\n", __FUNCTION__, file_path);
				goto end;
			}

			length = lseek(file_handle, 0L, SEEK_END);
			p_buffer = malloc(length);
			memset(p_buffer, 0x00, length);

			lseek(file_handle, 0L, SEEK_SET);
			readLength = read(file_handle, p_buffer, length);
			if (readLength != length)
			{
				CA_DEBUG(0, "[%s]: failed to read %d bytes from file %s\n",
								__FUNCTION__, length, file_path);
				close(file_handle);
				goto end;
			}

			CA_DEBUG(0, "[%s]: index file string: \'%s\'\n", __FUNCTION__, p_buffer);

			start_addr = strstr(p_buffer, "$");
			end_addr = strstr(p_buffer, "#");
			if ((start_addr == NULL) || (end_addr == NULL))
			{
				close(file_handle);
				goto end;
			}

			_split(start_addr, "|", revbuf, &valid_num);
			for (index = 0; index < valid_num; index++)
			{
				index_sequence[index] = atoi(revbuf[index]);
				CA_DEBUG(0, "[%s]: index_sequence: %d\n", __FUNCTION__, index_sequence[index]);
			}
		}

		pthread_mutex_init(&_mail_lock, NULL);

		CA_DEBUG(0, "[%s]: mail init success, has valid mail number: %d\n", __FUNCTION__, valid_num);
		b_mail_ready = 1;
	}

end:
	return;
}

static int _save_index_file(int *sequence, int count)
{
	char	sequence_str[MAX_MAIL_SEQUENCE_STR] = {0};
	char	file_path[MAX_MAIL_FILENAME_LEN];
	int		file_handle;
	int		target_size = 0, writtenLength = 0;
	int		index = 0;

	sprintf(file_path, MAIL_SAVE_FILEPATH"/"MAIL_INDEX_FILENAME);
	if ((file_handle = open(file_path,
						  O_WRONLY|O_CREAT|O_TRUNC,
						  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be opened\n",
						__FUNCTION__, file_path);
		return 1;
	}

	memset(sequence_str, 0x00, sizeof(sequence_str));
	sequence_str[0] = '$';
	for (index = 0; index < count; index++)
	{
		sprintf(sequence_str+1+3*index, "%02d|", sequence[index]);
	}

	// no mail
	if (strlen(sequence_str) == 1)
	{
		sequence_str[1] = '#';
	}
	else
	{
		sequence_str[strlen(sequence_str)-1] = '#';
	}

	CA_DEBUG(0, "[%s]: write string into file: %s\n", __FUNCTION__, sequence_str);

	target_size = strlen(sequence_str);
	writtenLength = write(file_handle, (void *)sequence_str, target_size);
	if (writtenLength != (int)target_size)
	{
		CA_DEBUG(0, "[%s]: failed to write %d bytes into file %s\n",
					  __FUNCTION__, target_size, file_path);
		close(file_handle);
		return 1;
	}

	close(file_handle);

	CA_DEBUG(0, "[%s]: save info into index file success\n", __FUNCTION__);
	return 0;
}

static void _debug_mail_sequence()
{
	char temp[1024] = {0};
	int index = 0;

	memset(temp, 0x00, sizeof(temp));
	CA_DEBUG(0, "[%s]: valid number: %d\n", __FUNCTION__, valid_num);

	for (index = 0; index < valid_num; index ++)
	{
		sprintf(temp+(index*4), "%02x, ", index_sequence[index]);
	}

	CA_DEBUG(0, "[%s]: sequence list: %s\n", __FUNCTION__, temp);
}

Ird_status_t ird_mail_save(mail_type_t type, mail_priority_t priority, char *p_content, int length)
{
	Ird_status_t ret = IRD_NO_ERROR;
	time_t timep;
    struct tm *p;
	mail_detail_st s_mail_detail;
	int		index = 0, valid_index = 0;
	char	file_path[MAX_MAIL_FILENAME_LEN];
	int		file_handle;
	int		target_size = 0, writtenLength = 0;
	char	sequence_str[MAX_MAIL_SEQUENCE_STR] = {0};

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	_mail_init();

	pthread_mutex_lock(&_mail_lock);

	memset(&s_mail_detail, 0x00, sizeof(mail_detail_st));

    time(&timep);
    p = gmtime(&timep);

	s_mail_detail.b_read = (priority == MAIL_PRIORITY_FORCED) ? 1: 0;
	s_mail_detail.priority = priority;
	s_mail_detail.type = type;
	s_mail_detail.year = 1900 + p->tm_year;
	s_mail_detail.month = 1 + p->tm_mon;
	s_mail_detail.day = p->tm_mday;
	s_mail_detail.hour = 8+p->tm_hour;
	s_mail_detail.minute = p->tm_min;
	s_mail_detail.ca_system_id = 0;

	for (index = 0; index < MAX_MAIL_NUM; index++)
	{
		for (valid_index = 0; valid_index < valid_num; valid_index++)
		{
			if (index == index_sequence[valid_index])
			{
				break;
			}
		}

		if (valid_index == valid_num)
		{
			break;
		}
	}

	if (index == MAX_MAIL_NUM)
	{
		CA_DEBUG(0, "[%s]: mailbox full, cannot save more mails, mail type %d\n", __FUNCTION__, type);
		ret = IRD_FAILURE;
		goto end;
	}

	CA_DEBUG(0, "[%s]: target index: %d\n", __FUNCTION__, index);

	s_mail_detail.index = index;
	memcpy(s_mail_detail.content, p_content, (length <= MAX_MAIL_CONTENT_LENGTH)?length:MAX_MAIL_CONTENT_LENGTH);

	sprintf(file_path, MAIL_SAVE_FILEPATH"/"MAIL_FILENAME_PREFIX"%d", index);
	if ((file_handle = open(file_path,
						  O_WRONLY|O_CREAT|O_TRUNC,
						  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be opened\n",
						__FUNCTION__, file_path);
		ret = IRD_FAILURE;
		goto end;
	}

	target_size = sizeof(mail_detail_st);
	writtenLength = write(file_handle, (void *)&s_mail_detail, target_size);
	if (writtenLength != (int)target_size)
	{
		CA_DEBUG(0, "[%s]: failed to write %d bytes into file %s\n",
					  __FUNCTION__, target_size, file_path);
		close(file_handle);
		ret = IRD_FAILURE;
		goto end;
	}

	close(file_handle);

	index_sequence[valid_num] = index;
	valid_num++;
	if (_save_index_file(index_sequence, valid_num))
	{
		CA_DEBUG(0, "[%s]: could not update index file \n", __FUNCTION__);
		ret = IRD_FAILURE;
		goto end;
	}

end:
	pthread_mutex_unlock(&_mail_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return ret;
}

Ird_status_t ird_mail_read_by_index(int index, mail_detail_st *p_mail, int b_with_mutex)
{
	Ird_status_t ret = IRD_NO_ERROR;
	char	file_path[MAX_MAIL_FILENAME_LEN];
	int		file_handle;
	char	*p_buffer = AML_NULL;
	int		length = 0, readLength = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	_mail_init();

	if (b_with_mutex)
	{
		pthread_mutex_lock(&_mail_lock);
	}

	CA_DEBUG(0, "[%s]: want to read mail index: %d\n", __FUNCTION__, index);
	if (!_check_index(index))
	{
		CA_DEBUG(0, "[%s]: not found index %d\n", index);
		ret = IRD_FAILURE;
		goto end;
	}

	sprintf(file_path, MAIL_SAVE_FILEPATH"/"MAIL_FILENAME_PREFIX"%d", index);
	if ((file_handle = open(file_path, O_RDONLY,
							  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be opened\n", __FUNCTION__, file_path);
		ret = IRD_FAILURE;
		goto end;
	}

	length = lseek(file_handle, 0L, SEEK_END);
	p_buffer = malloc(length);
	memset(p_buffer, 0x00, length);

	lseek(file_handle, 0L, SEEK_SET);
	readLength = read(file_handle, p_buffer, length);
	if (readLength != length)
	{
		CA_DEBUG(0, "[%s]: failed to read %d bytes from file %s\n",
					  __FUNCTION__, length, file_path);
		free(p_buffer);
		close(file_handle);
		ret = IRD_FAILURE;
		goto end;
	}

	memcpy(p_mail, p_buffer, length);

	free(p_buffer);
	close(file_handle);

end:
	if (b_with_mutex)
	{
		pthread_mutex_unlock(&_mail_lock);
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return ret;
}

Ird_status_t ird_mail_read_all(int *num, mail_detail_st **pp_mail_list)
{
	Ird_status_t ret = IRD_NO_ERROR;
	int		idx = 0;
	mail_detail_st temp_mail;
	int count = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	_mail_init();

	pthread_mutex_lock(&_mail_lock);

	*pp_mail_list = malloc(sizeof(mail_detail_st) * valid_num);
	if (*pp_mail_list == AML_NULL)
	{
		CA_DEBUG(0, "[%s]: could not malloc memory\n", __FUNCTION__);
		*num = 0;
		ret = IRD_FAILURE;
		goto end;
	}

	for (idx = 0; idx < valid_num; idx++)
	{
		memset(&temp_mail, 0x00, sizeof(mail_detail_st));
		if (IRD_NO_ERROR == ird_mail_read_by_index(index_sequence[idx], &temp_mail, 0))
		{
			memcpy(&((*pp_mail_list)[idx]), &temp_mail, sizeof(mail_detail_st));

#if 1
			CA_DEBUG(0, "[%s]: index: %d, b_read: %d, ca_system_id: %d\n", __FUNCTION__, temp_mail.index, temp_mail.b_read, temp_mail.ca_system_id);
			CA_DEBUG(0, "[%s]: %d/%d/%d %d:%d\n", __FUNCTION__, temp_mail.year, temp_mail.month, temp_mail.day, temp_mail.hour, temp_mail.minute);
			CA_DEBUG(0, "[%s]: type: %d, priority: %d\n", __FUNCTION__, temp_mail.type, temp_mail.priority);
			CA_DEBUG(0, "[%s]: content: %s\n", __FUNCTION__, temp_mail.content);
#endif
		}
		count++;
	}

	*num = count;

end:
	pthread_mutex_unlock(&_mail_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return ret;
}

void ird_mail_read_free(mail_detail_st **pp_mail_list)
{
	if (pp_mail_list != AML_NULL)
	{
		free(*pp_mail_list);
	}
	*pp_mail_list = AML_NULL;
}

Ird_status_t ird_mail_delete_by_index(int index)
{
	int		idx = 0;
	int		bMove = 0;
	char	file_path[MAX_MAIL_FILENAME_LEN];
	char    rmcmd[MAX_MAIL_FILENAME_LEN + 7]; /* +7 because strlen("rm -f") = 6 */

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	_mail_init();

	pthread_mutex_lock(&_mail_lock);

	CA_DEBUG(0, "[%s]: want to delete mail index: %d\n", __FUNCTION__, index);
	if (!_check_index(index))
	{
		CA_DEBUG(0, "[%s]: not found index %d\n", __FUNCTION__, index);
		goto end;
	}

	for (idx = 0; idx < valid_num; idx++)
	{
		if (index_sequence[idx] == index)
		{
			bMove = 1;
		}

		// delete the taget index, copy the next to cover it
		if (bMove == 1)
		{
			index_sequence[idx] = index_sequence[idx+1];
		}
	}

	valid_num -= 1;
	if (_save_index_file(index_sequence, valid_num))
	{
		CA_DEBUG(0, "[%s]: could not update index file \n", __FUNCTION__);
		goto end;
	}

	sprintf(file_path, MAIL_SAVE_FILEPATH"/"MAIL_FILENAME_PREFIX"%d", index);
	sprintf(rmcmd, "rm -f %s", file_path);
	if (0 != system(rmcmd))
	{
		CA_DEBUG(0, "[%s]: cannot delete mail file %s\n", __FUNCTION__, file_path);
	}
	else
	{
		CA_DEBUG(0, "[%s]: delete %s success\n", __FUNCTION__, file_path);
	}

	_debug_mail_sequence();

end:
	pthread_mutex_unlock(&_mail_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return IRD_NO_ERROR;
}


Ird_status_t ird_mail_delete_all()
{
	char    rmcmd[MAX_MAIL_FILENAME_LEN + 7]; /* +7 because strlen("rm -f") = 6 */

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	_mail_init();

	pthread_mutex_lock(&_mail_lock);

	memset(index_sequence, -1, MAX_MAIL_NUM);
	valid_num = 0;

	if (_save_index_file(index_sequence, valid_num))
	{
		CA_DEBUG(0, "[%s]: could not update index file \n", __FUNCTION__);
		goto end;
	}

	sprintf(rmcmd, "rm -f %s", MAIL_SAVE_FILEPATH"/"MAIL_FILENAME_PREFIX"*");
	if (0 != system(rmcmd))
	{
		CA_DEBUG(0, "[%s]: cannot delete all mail file %s\n", __FUNCTION__);
	}
	else
	{
		CA_DEBUG(0, "[%s]: delete all mail success\n", __FUNCTION__);
	}

end:
	pthread_mutex_unlock(&_mail_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return IRD_NO_ERROR;
}

Ird_status_t ird_mail_set_read_flag(int index)
{
	Ird_status_t ret = IRD_NO_ERROR;
	char	file_path[MAX_MAIL_FILENAME_LEN];
	int 	file_handle;
	char	*p_buffer = AML_NULL;
	int 	length = 0, readLength = 0, writtenLength = 0;
	mail_detail_st *p_mail = AML_NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	_mail_init();

	pthread_mutex_lock(&_mail_lock);

	CA_DEBUG(0, "[%s]: want to set read flag index: %d\n", __FUNCTION__, index);
	if (!_check_index(index))
	{
		CA_DEBUG(0, "[%s]: not found index %d\n", index);
		ret = IRD_FAILURE;
		goto end;
	}

	sprintf(file_path, MAIL_SAVE_FILEPATH"/"MAIL_FILENAME_PREFIX"%d", index);
	if ((file_handle = open(file_path, O_RDONLY,
							  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be opened\n", __FUNCTION__, file_path);
		ret = IRD_FAILURE;
		goto end;
	}

	length = lseek(file_handle, 0L, SEEK_END);
	p_buffer = malloc(length);
	memset(p_buffer, 0x00, length);

	lseek(file_handle, 0L, SEEK_SET);
	readLength = read(file_handle, p_buffer, length);
	if (readLength != length)
	{
		CA_DEBUG(0, "[%s]: failed to read %d bytes from file %s\n",
					  __FUNCTION__, length, file_path);
		free(p_buffer);
		close(file_handle);
		ret = IRD_FAILURE;
		goto end;
	}

	close(file_handle);

	p_mail = (mail_detail_st *)p_buffer;
	p_mail->b_read = 1;

	if ((file_handle = open(file_path,
						  O_WRONLY|O_CREAT|O_TRUNC,
						  S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
	{
		CA_DEBUG(0, "[%s]: file %s could not be opened\n",
						__FUNCTION__, file_path);
		ret = IRD_FAILURE;
		goto end;
	}

	writtenLength = write(file_handle, (void *)p_buffer, length);
	if (writtenLength != (int)length)
	{
		CA_DEBUG(0, "[%s]: failed to write %d bytes into file %s\n",
					  __FUNCTION__, length, file_path);
		close(file_handle);
		ret = IRD_FAILURE;
		goto end;
	}

	close(file_handle);
	free(p_buffer);

end:
	pthread_mutex_unlock(&_mail_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return ret;
}

