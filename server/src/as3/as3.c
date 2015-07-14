/* vim: ft=c ff=unix fenc=utf-8
 * file: src/as3/as3.c
 */
#include "as3.h"
#include "junk/xsyslog.h"

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
	if (uname(&utsname)) {
		xsyslog(LOG_ERR, "uname failed[%d]: %s", errno, strerror(errno));
		return false;
	}

	snprintf(string, string_size, "Server/OEM/%s/%s/Swissbox Server/1",
			utsname.sysname, utsname.release);

	return true;
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
	guid_t x_device_id;
	char x_client[64];
	char xaddr[64];
	char xjson[1024];
	long rcode;

	as3_client(x_client, sizeof(x_client));

	/* формирование json */
	snprintf(xjson, sizeof(xjson), "{ username: \"%s\", password: \"%s\" }",
			name, secret);
	snprintf(xaddr, sizeof(xaddr), "%s/session", path);

	/* создание POST запроса */
	if (!(curl = curl_easy_init())) {
		xsyslog(LOG_WARNING, "curl initialization failed");
		return false;
	}

	curl_easy_setopt(curl, CURLOPT_URL, xaddr);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xjson);

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
	return false;
}

