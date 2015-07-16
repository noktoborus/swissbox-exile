/* vim: ft=c ff=unix fenc=utf-8
 * file: src/as3/as3.c
 */
#include "as3.h"
#include "junk/xsyslog.h"
#include "junk/utils.h"

#include <sys/utsname.h>
#include <errno.h>
#include <curl/curl.h>
/* http://docs.harp.dev.morepower.ru/public/v10/EsbInterfaces/4.as-interfaces
 */

bool
as3_client(char *string, size_t string_size)
{
	struct utsname buf;
	memset(&buf, 0, sizeof(struct utsname));
	if (uname(&buf)) {
		xsyslog(LOG_ERR, "uname failed[%d]: %s", errno, strerror(errno));
		return false;
	}

	snprintf(string, string_size, "Server/OEM/%s/%s/Swissbox Server/1",
			buf.sysname, buf.release);

	return true;
}

size_t
curl_silent(void *ptr, size_t size, size_t nmemb, void *m){
	return size * nmemb;
}

bool
as3_auth(char *path, char *name, char *secret, uint64_t device_id)
{
	/* http://docs.harp.dev.morepower.ru/public/v10/EsbInterfaces/4.1.api.session-control
	 * headers:
	 * Content-Type: application/json
	 * X-Device-Id: <device.uniqueId:string> UUID(идентификатор устройства клиента)
	 * X-Client: <device.agent:T_AGENT>
	 *
	 * T_AGENT: Server/OEM/<sysname>/<sys version>/Swissbox Server/<version>
	 */
	CURL *curl;
	CURLcode res;
	struct curl_slist *x_header = NULL;
	guid_t x_device_id;
	char x_client[64];
	char xjson[1024];
	long rcode;

	as3_client(x_client, sizeof(x_client));

	/* формирование device_id */
	any2guid((char*)&device_id, sizeof(device_id), &x_device_id);

	/* формирование json */
	snprintf(xjson, sizeof(xjson),
			"{ \"username\": \"%s\", \"password\": \"%s\" }",
			name, secret);

	/* создание POST запроса */
	if (!(curl = curl_easy_init())) {
		xsyslog(LOG_WARNING, "curl initialization failed");
		return false;
	}

	x_header = curl_slist_append(x_header, "Content-Type: application/json");
	{
		char _x_device_id[GUID_MAX + 1];
		char _t[64];
		guid2string(&x_device_id, PSIZE(_x_device_id));
		snprintf(_t, sizeof(_t), "X-Device-Id: %s", _x_device_id);
		x_header = curl_slist_append(x_header, _t);
		snprintf(_t, sizeof(_t), "X-Client: %s", x_client);
		x_header = curl_slist_append(x_header, _t);
	}
	curl_easy_setopt(curl, CURLOPT_URL, path);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xjson);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, x_header);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_silent);

	if ((res = curl_easy_perform(curl)) != CURLE_OK) {
		xsyslog(LOG_WARNING, "curl perform failed: %s\n",
				curl_easy_strerror(res));
		curl_easy_cleanup(curl);
		return false;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rcode);

	curl_easy_cleanup(curl);

	if (rcode == 200)
		return true;
	if (rcode != 401) {
		xsyslog(LOG_WARNING, "AS3 (%s) response code: %ld", path, rcode);
	}
	return false;
}

