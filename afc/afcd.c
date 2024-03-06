/*
 * Automated Frequency Coordination Daemon
 * Copyright (c) 2024, Lorenzo Bianconi <lorenzo@kernel.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <curl/curl.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "utils/includes.h"
#include "utils/common.h"

#define CURL_TIMEOUT	60
#define AFCD_SOCK	"afcd.sock"

struct curl_ctx {
	char *buf;
	size_t buf_len;
};

static volatile bool exiting;

static char *path = "/var/run";
static char *bearer_token;
static char *url;
static int port = 443;


static size_t afcd_curl_cb_write(void *ptr, size_t size, size_t nmemb,
				 void *userdata)
{
	struct curl_ctx *ctx = userdata;
	char *buf;

	buf = os_realloc(ctx->buf, ctx->buf_len + size * nmemb + 1);
	if (!buf)
		return 0;

	ctx->buf = buf;
	os_memcpy(buf + ctx->buf_len, ptr, size * nmemb);
	buf[ctx->buf_len + size * nmemb] = '\0';
	ctx->buf_len += size * nmemb;

	return size * nmemb;
}


static int afcd_send_request(struct curl_ctx *ctx, unsigned char *request)
{
	struct curl_slist *headers = NULL;
	CURL *curl;
	int ret;
	char *data_ptr, *data = "{\"availableSpectrumInquiryResponses\": [{\"response\": {\"responseCode\": 0, \"shortDescription\": \"SUCCESS\"}, \"availableFrequencyInfo\": [{\"frequencyRange\": {\"highFrequency\": 5965, \"lowFrequency\": 5945}, \"maxPsd\": 12.1}, {\"frequencyRange\": {\"highFrequency\": 5985, \"lowFrequency\": 5965}, \"maxPsd\": 13.4}, {\"frequencyRange\": {\"highFrequency\": 6005, \"lowFrequency\": 5985}, \"maxPsd\": 16.4}, {\"frequencyRange\": {\"highFrequency\": 6025, \"lowFrequency\": 6005}, \"maxPsd\": 21.2}, {\"frequencyRange\": {\"highFrequency\": 6045, \"lowFrequency\": 6025}, \"maxPsd\": 17.9}, {\"frequencyRange\": {\"highFrequency\": 6065, \"lowFrequency\": 6045}, \"maxPsd\": 20.3}, {\"frequencyRange\": {\"highFrequency\": 6085, \"lowFrequency\": 6065}, \"maxPsd\": 21.3}, {\"frequencyRange\": {\"highFrequency\": 6105, \"lowFrequency\": 6085}, \"maxPsd\": 8.1}, {\"frequencyRange\": {\"highFrequency\": 6605, \"lowFrequency\": 6585}, \"maxPsd\": 20.3}, {\"frequencyRange\": {\"highFrequency\": 6625, \"lowFrequency\": 6605}, \"maxPsd\": 9.7}, {\"frequencyRange\": {\"highFrequency\": 6645, \"lowFrequency\": 6625}, \"maxPsd\": 13.5}, {\"frequencyRange\": {\"highFrequency\": 6665, \"lowFrequency\": 6645}, \"maxPsd\": 12.1}, {\"frequencyRange\": {\"highFrequency\": 6685, \"lowFrequency\": 6665}, \"maxPsd\": 15.4}, {\"frequencyRange\": {\"highFrequency\": 6705, \"lowFrequency\": 6685}, \"maxPsd\": 15.1}, {\"frequencyRange\": {\"highFrequency\": 6725, \"lowFrequency\": 6705}, \"maxPsd\": 17.8}, {\"frequencyRange\": {\"highFrequency\": 6745, \"lowFrequency\": 6725}, \"maxPsd\": 16.3}], \"requestId\": \"0\", \"availabilityExpireTime\": \"2023-03-07T09:49:45Z\", \"rulesetId\": \"US_47_CFR_PART_15_SUBPART_E\"}], \"version\": \"1.4\"}";

	wpa_printf(MSG_ERROR, "Sending AFC request to %s", url);

	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;

	headers  = curl_slist_append(headers, "Accept: application/json");
	headers  = curl_slist_append(headers,
				     "Content-Type: application/json");
	headers  = curl_slist_append(headers, "charset: utf-8");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_PORT, port);
	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			 afcd_curl_cb_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcrp/0.1");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
	if (bearer_token)
		curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer_token);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);

	ret = curl_easy_perform(curl);
	ret = CURLE_OK;
	if (ret != CURLE_OK)
		wpa_printf(MSG_ERROR, "curl_easy_perform failed: %s",
			   curl_easy_strerror(ret));

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	ctx->buf_len = strlen(data) + 1;
	data_ptr = os_zalloc(ctx->buf_len);
	if (!data_ptr)
		return -ENOMEM;

	os_strlcpy(data_ptr, data, ctx->buf_len);
	ctx->buf = data_ptr;

	return ret == CURLE_OK ? 0 : -EINVAL;
}


static void handle_term(int sig)
{
	wpa_printf(MSG_ERROR, "Received signal %d", sig);
	exiting = true;
}


static void usage(void)
{
	wpa_printf(MSG_ERROR,
		   "%s:\n"
		   "afcd -u<url> [-p<port>][-t<token>][-D<unix-sock dir>][-P<PID file>][-dB]",
		   __func__);
}


#define BUFSIZE		8192
static int afcd_server_run(void)
{
	size_t len = os_strlen(path) + 1 + os_strlen(AFCD_SOCK);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
#ifdef __FreeBSD__
		.sun_len = sizeof(addr),
#endif /* __FreeBSD__ */
	};
	int sockfd, ret = 0;
	char *fname = NULL;
	unsigned char *buf;
	fd_set read_set;

	if (len >= sizeof(addr.sun_path))
		return -EINVAL;

	if (mkdir(path, S_IRWXU | S_IRWXG) < 0 && errno != EEXIST)
		return -EINVAL;

	buf = os_malloc(BUFSIZE);
	if (!buf)
		return -ENOMEM;

	fname = os_malloc(len + 1);
	if (!fname) {
		ret = -ENOMEM;
		goto free_buf;
	}

	os_snprintf(fname, len + 1, "%s/%s", path, AFCD_SOCK);
	fname[len] = '\0';
	os_strlcpy(addr.sun_path, fname, sizeof(addr.sun_path));

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		wpa_printf(MSG_ERROR, "Failed creating socket");
		ret = -errno;
		goto unlink;
	}

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		wpa_printf(MSG_ERROR, "Failed to bind socket");
		ret = -errno;
		goto close;
	}

	if (listen(sockfd, 10) < 0) {
		wpa_printf(MSG_ERROR, "Failed to listen on socket");
		ret = -errno;
		goto close;
	}

	FD_ZERO(&read_set);
	while (!exiting) {
		socklen_t addr_len = sizeof(addr);
		struct sockaddr_in6 c_addr;
		struct timeval timeout = {
			.tv_sec = 1,
		};
		struct curl_ctx ctx = {};
		int fd;

		FD_SET(sockfd, &read_set);
		if (select(sockfd + 1, &read_set, NULL, NULL, &timeout) < 0) {
			if (errno != EINTR) {
				wpa_printf(MSG_ERROR,
					   "Select failed on socket");
				ret = -errno;
				break;
			}
			continue;
		}

		if (!FD_ISSET(sockfd, &read_set))
			continue;

		fd = accept(sockfd, (struct sockaddr *)&c_addr,
			    &addr_len);
		if (fd < 0) {
			if (errno != EINTR) {
				wpa_printf(MSG_ERROR,
					   "Failed accepting connections");
				ret = -errno;
				break;
			}
			continue;
		}

		os_memset(buf, 0, BUFSIZE);
		if (recv(fd, buf, BUFSIZE, 0) <= 0) {
			close(fd);
			continue;
		}

		wpa_printf(MSG_ERROR, "Received request: %s", buf);
		if (!afcd_send_request(&ctx, buf)) {
			wpa_printf(MSG_ERROR, "Received reply: %s", ctx.buf);
			send(fd, ctx.buf, ctx.buf_len, MSG_NOSIGNAL);
			free(ctx.buf);
		}
		close(fd);
	}
close:
	close(sockfd);
unlink:
	unlink(fname);
	os_free(fname);
free_buf:
	os_free(buf);

	return ret;
}


int main(int argc, char **argv)
{
	bool daemonize = false;
	char *pid_file = NULL;

	if (os_program_init())
		return -1;

	for (;;) {
		int c = getopt(argc, argv, "u:p:t:D:P:hdB");

		if (c < 0)
			break;

		switch (c) {
		case 'h':
			usage();
			return 0;
		case 'B':
			daemonize = true;
			break;
		case 'D':
			path = optarg;
			break;
		case 'P':
			os_free(pid_file);
			pid_file = os_rel2abs_path(optarg);
			break;
		case 'u':
			url = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'd':
			if (wpa_debug_level > 0)
				wpa_debug_level--;
			break;
		case 't':
			bearer_token = optarg;
			break;
		default:
			usage();
			return -EINVAL;
		}
	}

	if (!url) {
		usage();
		return -EINVAL;
	}

	if (daemonize && os_daemonize(pid_file)) {
		wpa_printf(MSG_ERROR, "daemon: %s", strerror(errno));
		return -EINVAL;
	}

	signal(SIGTERM, handle_term);
	signal(SIGINT, handle_term);

	return afcd_server_run();
}
