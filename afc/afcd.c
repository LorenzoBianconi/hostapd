/*
 * Automated Frequency Coordination Daemon
 * Copyright (c) 2024, Lorenzo Bianconi <lorenzo@kernel.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <curl/curl.h>

#include "utils/includes.h"
#include "utils/common.h"

#define CURL_TIMEOUT	60

struct afc_curl_ctx {
	char *buf;
	size_t buf_len;
};

static volatile bool exiting;
static char *bearer_token;
static char *url;


static size_t afcd_curl_cb_write(void *ptr, size_t size, size_t nmemb,
				 void *userdata)
{
	struct afc_curl_ctx *ctx = userdata;
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


static int afcd_send_request(struct afc_curl_ctx *ctx, unsigned char *request)
{
	struct curl_slist *headers = NULL;
	CURL *curl;
	int ret;

	wpa_printf(MSG_DEBUG, "Sending AFC request to %s", url);

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
	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			 afcd_curl_cb_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcrp/0.1");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
	curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer_token);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);

	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK)
		wpa_printf(MSG_ERROR, "curl_easy_perform failed: %s",
			   curl_easy_strerror(ret));

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return ret == CURLE_OK ? 0 : -EINVAL;
}


static void handle_term(int sig)
{
	exiting = true;
}


static void usage(void)
{
	wpa_printf(MSG_ERROR,
		   "%s:\n"
		   "afcd -u<url> -t<token> [-p<port>][-P<PID file>][-dB]",
		   __func__);
}


#define BUFSIZE		4096
static int afcd_server_run(int port)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_any,
		.sin6_port = htons(port),
	};
	int sockfd, on = 1, ret = 0;
	fd_set read_set;

	sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0) {
		wpa_printf(MSG_ERROR, "Failed creating socket");
		return -errno;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		wpa_printf(MSG_ERROR, "Failed to set SO_REUSEPORT");
		return -errno;
	}

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		wpa_printf(MSG_ERROR, "Failed to bind socket");
		close(sockfd);
		return -errno;
	}

	if (listen(sockfd, 10) < 0) {
		wpa_printf(MSG_ERROR, "Failed to listen on socket");
		close(sockfd);
		return -errno;
	}

	FD_ZERO(&read_set);
	while (!exiting) {
		socklen_t addr_len = sizeof(addr);
		unsigned char buf[BUFSIZE] = {};
		struct afc_curl_ctx ctx = {};
		struct sockaddr_in6 c_addr;
		struct timeval timeout = {
			.tv_sec = 1,
		};
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

		if (recv(fd, buf, sizeof(buf), 0) <= 0) {
			close(fd);
			continue;
		}

		wpa_printf(MSG_DEBUG, "Received request: %s", buf);
		if (!afcd_send_request(&ctx, buf)) {
			wpa_printf(MSG_DEBUG, "Received reply: %s", ctx.buf);
			ret = send(fd, ctx.buf, ctx.buf_len, 0);
			free(ctx.buf);
		}
		close(fd);
	}
	close(sockfd);

	return ret;
}


int main(int argc, char **argv)
{
	int port = 12345; /*default port */
	bool daemonize = false;
	char *pid_file = NULL;

	if (os_program_init())
		return -1;

	for (;;) {
		int c = getopt(argc, argv, "u:t:p:P:hdB");

		if (c < 0)
			break;

		switch (c) {
		case 'h':
			usage();
			return 0;
		case 'B':
			daemonize = true;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'P':
			os_free(pid_file);
			pid_file = os_rel2abs_path(optarg);
			break;
		case 'u':
			url = optarg;
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

	if (!url || !bearer_token) {
		usage();
		return -EINVAL;
	}

	if (daemonize && os_daemonize(pid_file)) {
		wpa_printf(MSG_ERROR, "daemon: %s", strerror(errno));
		return -EINVAL;
	}

	signal(SIGTERM, handle_term);
	signal(SIGINT, handle_term);

	return afcd_server_run(port);
}
