/*
 * Automated Frequency Coordination
 * Copyright (c) 2024, Lorenzo Bianconi <lorenzo@kernel.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <json-c/json.h>
#include <sys/un.h>
#include <time.h>

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "hostapd.h"
#include "acs.h"

#define HOSTAPD_AFC_RETRY_TIMEOUT	180
#define HOSTAPD_AFC_TIMEOUT		86400 /* 24h */
#define HOSTAPD_AFC_BUFSIZE		4096

struct afc_curl_ctx {
	int timeout;
	char *buf;
	size_t buf_len;
};

static void hostapd_afc_timeout_handler(void *eloop_ctx, void *timeout_ctx);


static struct json_object *
hostapd_afc_build_location_request(struct hostapd_iface *iface)
{
	struct json_object *location_obj, *center_obj, *ellipse_obj;
	struct json_object *elevation_obj, *str_obj;
	struct hostapd_config *iconf = iface->conf;
	bool is_ap_indoor = he_reg_is_indoor(iconf->he_6ghz_reg_pwr_type);

	location_obj = json_object_new_object();
	if (!location_obj)
		return NULL;

	if (iconf->afc.location.type != LINEAR_POLYGON) {
		struct afc_linear_polygon *lp =
			&iconf->afc.location.linear_polygon_data[0];

		ellipse_obj = json_object_new_object();
		if (!ellipse_obj)
			goto error;

		center_obj = json_object_new_object();
		if (!center_obj)
			goto error;

		json_object_object_add(ellipse_obj, "center", center_obj);

		str_obj = json_object_new_double(lp->longitude);
		if (!str_obj)
			goto error;

		json_object_object_add(center_obj, "longitude", str_obj);
		str_obj = json_object_new_double(lp->latitude);
		if (!str_obj)
			goto error;

		json_object_object_add(center_obj, "latitude", str_obj);

	}

	switch (iconf->afc.location.type) {
	case LINEAR_POLYGON: {
		struct json_object *outer_boundary_obj;
		int i;

		outer_boundary_obj = json_object_new_object();
		if (!outer_boundary_obj)
			goto error;

		json_object_object_add(location_obj, "linearPolygon",
				       outer_boundary_obj);
		ellipse_obj = json_object_new_array();
		if (!ellipse_obj)
			goto error;

		json_object_object_add(outer_boundary_obj, "outerBoundary",
				       ellipse_obj);
		for (i = 0;
		     i < iconf->afc.location.n_linear_polygon_data; i++) {
			struct afc_linear_polygon *lp =
				&iconf->afc.location.linear_polygon_data[i];

			center_obj = json_object_new_object();
			if (!center_obj)
				goto error;

			json_object_array_add(ellipse_obj, center_obj);
			str_obj = json_object_new_double(lp->longitude);
			if (!str_obj)
				goto error;

			json_object_object_add(center_obj, "longitude",
					       str_obj);
			str_obj = json_object_new_double(lp->latitude);
			if (!str_obj)
				goto error;

			json_object_object_add(center_obj, "latitude",
					       str_obj);
		}
		break;
	}
	case RADIAL_POLYGON: {
		struct json_object *outer_boundary_obj;
		int i;

		json_object_object_add(location_obj, "radialPolygon",
				       ellipse_obj);

		outer_boundary_obj = json_object_new_array();
		if (!outer_boundary_obj)
			goto error;

		json_object_object_add(ellipse_obj, "outerBoundary",
				       outer_boundary_obj);
		for (i = 0;
		     i < iconf->afc.location.n_radial_polygon_data; i++) {
			struct afc_radial_polygon *rp =
				&iconf->afc.location.radial_polygon_data[i];
			struct json_object *angle_obj;

			angle_obj = json_object_new_object();
			if (!angle_obj)
				goto error;

			json_object_array_add(outer_boundary_obj, angle_obj);

			str_obj = json_object_new_double(rp->angle);
			if (!str_obj)
				goto error;

			json_object_object_add(angle_obj, "angle", str_obj);
			str_obj = json_object_new_double(rp->length);
			if (!str_obj)
				goto error;

			json_object_object_add(angle_obj, "length", str_obj);
		}
		break;
	}
	case ELLIPSE:
	default:
		json_object_object_add(location_obj, "ellipse", ellipse_obj);

		str_obj = json_object_new_int(iconf->afc.location.major_axis);
		if (!str_obj)
			goto error;

		json_object_object_add(ellipse_obj, "majorAxis", str_obj);
		str_obj = json_object_new_int(iconf->afc.location.minor_axis);
		if (!str_obj)
			goto error;

		json_object_object_add(ellipse_obj, "minorAxis", str_obj);
		str_obj = json_object_new_int(iconf->afc.location.orientation);
		if (!str_obj)
			goto error;

		json_object_object_add(ellipse_obj, "orientation", str_obj);
		break;
	}

	elevation_obj = json_object_new_object();
	if (!elevation_obj)
		goto error;

	json_object_object_add(location_obj, "elevation",
			       elevation_obj);
	str_obj = json_object_new_double(iconf->afc.location.height);
	if (!str_obj)
		goto error;

	json_object_object_add(elevation_obj, "height", str_obj);
	str_obj = json_object_new_string(iconf->afc.location.height_type);
	if (!str_obj)
		goto error;

	json_object_object_add(elevation_obj, "heightType", str_obj);
	str_obj = json_object_new_int(iconf->afc.location.vertical_tolerance);
	if (!str_obj)
		goto error;

	json_object_object_add(elevation_obj, "verticalUncertainty",
			       str_obj);
	str_obj = json_object_new_int(is_ap_indoor);
	if (!str_obj)
		goto error;

	json_object_object_add(location_obj, "indoorDeployment", str_obj);

	return location_obj;

error:
	json_object_put(location_obj);
	return NULL;
}


static void
hostapd_afc_get_opclass_chan_list(struct hostapd_iface *iface, u8 op_class,
				  u8 *chan_list, u16 *n_chan_list)
{
	struct hostapd_hw_modes *mode = iface->current_mode;
	int i, count = 0;

	memset(chan_list, 0, mode->num_channels * sizeof(*chan_list));
	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *chan = &mode->channels[i];

		if (!is_6ghz_freq(chan->freq))
			continue;

		if (ieee80211_chan_to_freq(iface->conf->country, op_class,
					   chan->chan) < 0)
			continue;

		chan_list[count++] = chan->chan;
	}
	*n_chan_list = count;
}


static struct json_object *
hostapd_afc_build_request(struct hostapd_iface *iface)
{
	struct json_object *l1_obj, *l2_obj, *la1_obj, *la2_obj;
	struct json_object *s2_obj, *str_obj, *location_obj;
	struct hostapd_hw_modes *mode = iface->current_mode;
	struct hostapd_config *iconf = iface->conf;
	u8 *chan_list = NULL;
	int i;

	l1_obj = json_object_new_object();
	if (!l1_obj)
		return NULL;

	if (iconf->afc.request.version) {
		str_obj = json_object_new_string(iconf->afc.request.version);
		if (!str_obj)
			goto error;

		json_object_object_add(l1_obj, "version", str_obj);
	}

	la1_obj = json_object_new_array();
	if (!la1_obj)
		goto error;

	json_object_object_add(l1_obj, "availableSpectrumInquiryRequests",
			       la1_obj);
	l2_obj = json_object_new_object();
	if (!l2_obj)
		goto error;

	json_object_array_add(la1_obj, l2_obj);
	if (iconf->afc.request.id) {
		str_obj = json_object_new_string(iconf->afc.request.id);
		if (!str_obj)
			goto error;

		json_object_object_add(l2_obj, "requestId", str_obj);
	}

	s2_obj = json_object_new_object();
	if (!s2_obj)
		goto error;

	json_object_object_add(l2_obj, "deviceDescriptor", s2_obj);
	if (iconf->afc.request.sn) {
		str_obj = json_object_new_string(iconf->afc.request.sn);
		if (!str_obj)
			goto error;

		json_object_object_add(s2_obj, "serialNumber", str_obj);
	}

	la2_obj = json_object_new_array();
	if (!la2_obj)
		goto error;

	json_object_object_add(s2_obj, "certificationId", la2_obj);
	for (i = 0; i < iconf->afc.n_cert_ids; i++) {
		struct json_object *obj;

		obj = json_object_new_object();
		if (!obj)
			goto error;

		json_object_array_add(la2_obj, obj);
		str_obj =
			json_object_new_string(iconf->afc.cert_ids[i].rulset);
		if (!str_obj)
			goto error;

		json_object_object_add(obj, "rulesetId", str_obj);
		str_obj = json_object_new_string(iconf->afc.cert_ids[i].id);
		if (!str_obj)
			goto error;

		json_object_object_add(obj, "id", str_obj);
	}

	location_obj = hostapd_afc_build_location_request(iface);
	if (!location_obj)
		goto error;

	json_object_object_add(l2_obj, "location", location_obj);
	str_obj = json_object_new_int(iconf->afc.min_power);
	if (!str_obj)
		goto error;

	json_object_object_add(l2_obj, "minDesiredPower", str_obj);

	if (iconf->afc.n_freq_range) {
		struct json_object *freq_obj;

		freq_obj = json_object_new_array();
		if (!freq_obj)
			goto error;

		json_object_object_add(l2_obj, "inquiredFrequencyRange",
				       freq_obj);
		for (i = 0; i < iconf->afc.n_freq_range; i++) {
			struct afc_freq_range *fr = &iconf->afc.freq_range[i];
			struct json_object *obj;

			obj = json_object_new_object();
			if (!obj)
				goto error;

			json_object_array_add(freq_obj, obj);
			str_obj = json_object_new_int(fr->low_freq);
			if (!str_obj)
				goto error;

			json_object_object_add(obj, "lowFrequency", str_obj);
			str_obj = json_object_new_int(fr->high_freq);
			if (!str_obj)
				goto error;

			json_object_object_add(obj, "highFrequency", str_obj);
		}
	}

	if (iconf->afc.n_op_class) {
		struct json_object *op_class_list_obj;

		chan_list = os_malloc(mode->num_channels * sizeof(*chan_list));
		if (!chan_list)
			goto error;

		op_class_list_obj = json_object_new_array();
		if (!op_class_list_obj)
			goto error;

		json_object_object_add(l2_obj, "inquiredChannels",
				       op_class_list_obj);
		for (i = 0; i < iconf->afc.n_op_class; i++) {
			struct json_object *op_class_obj, *chan_list_obj;
			u16 n_chan_list = 0;
			int j;

			hostapd_afc_get_opclass_chan_list(
					iface, iconf->afc.op_class[i],
					chan_list, &n_chan_list);
			if (!n_chan_list)
				continue;

			op_class_obj = json_object_new_object();
			if (!op_class_obj)
				goto error;

			json_object_array_add(op_class_list_obj, op_class_obj);
			str_obj = json_object_new_int(iconf->afc.op_class[i]);
			if (!str_obj)
				goto error;

			json_object_object_add(op_class_obj,
					       "globalOperatingClass",
					       str_obj);
			chan_list_obj = json_object_new_array();
			if (!chan_list_obj)
				goto error;

			json_object_object_add(op_class_obj, "channelCfi",
					       chan_list_obj);
			for (j = 0; j < n_chan_list; j++) {
				str_obj = json_object_new_int(chan_list[j]);
				if (!str_obj)
					goto error;

				json_object_array_add(chan_list_obj, str_obj);
			}
		}
		free(chan_list);
	}

	wpa_printf(MSG_DEBUG, "Pending AFC request: %s",
		   json_object_get_string(l1_obj));

	return l1_obj;

error:
	free(chan_list);
	json_object_put(l1_obj);

	return NULL;
}


static int
hostad_afc_parse_available_freq_info(struct hostapd_iface *iface,
				     struct json_object *reply_elem_obj)
{
	struct hostapd_hw_modes *mode = iface->current_mode;
	struct afc_freq_range_elem *f = NULL;
	struct json_object *obj;
	int i, count = 0;

	if (!json_object_object_get_ex(reply_elem_obj,
				       "availableFrequencyInfo", &obj))
		return 0;

	for (i = 0; i < json_object_array_length(obj); i++) {
		struct json_object *range_elem_obj, *freq_range_obj;
		struct json_object *high_freq_obj, *low_freq_obj;
		struct json_object *max_psd_obj;

		range_elem_obj = json_object_array_get_idx(obj, i);
		if (!json_object_object_get_ex(range_elem_obj,
					       "frequencyRange",
					       &freq_range_obj))
			continue;

		if (!json_object_object_get_ex(freq_range_obj,
					       "lowFrequency",
					       &low_freq_obj))
			continue;

		if (!json_object_object_get_ex(freq_range_obj,
					       "highFrequency",
					       &high_freq_obj))
			continue;

		if (!json_object_object_get_ex(range_elem_obj, "maxPsd",
					       &max_psd_obj) &&
		    !json_object_object_get_ex(range_elem_obj, "maxPSD",
					       &max_psd_obj))
			continue;

		f = os_realloc_array(f, count + 1, sizeof(*f));
		if (!f)
			return -ENOMEM;

		f[count].low_freq = json_object_get_int(low_freq_obj);
		f[count].high_freq = json_object_get_int(high_freq_obj);
		f[count++].max_psd = json_object_get_int(max_psd_obj);
	}
	os_free(iface->afc.freq_range);
	iface->afc.freq_range = f;
	iface->afc.num_freq_range = count;

	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *chan = &mode->channels[i];
		int j;

		if (!is_6ghz_freq(chan->freq))
			continue;

		for (j = 0; j < count; j++) {
			if (chan->freq >= f[j].low_freq &&
			    chan->freq <= f[j].high_freq)
				break;
		}

		if (j == count)
			chan->flag |= HOSTAPD_CHAN_DISABLED;
	}

	return 0;
}


static int
hostad_afc_parse_available_chan_info(struct hostapd_iface *iface,
				     struct json_object *reply_elem_obj)
{
	struct json_object *obj;
	int i;

	if (!json_object_object_get_ex(reply_elem_obj,
				       "availableChannelInfo", &obj))
		return 0;

	for (i = 0; i < json_object_array_length(obj); i++) {
		struct hostapd_hw_modes *mode = iface->current_mode;
		struct json_object *range_elem_obj, *op_class_obj;
		struct json_object *chan_cfi_obj, *max_eirp_obj;
		struct afc_chan_info_elem *c = NULL;
		int j, ch, op_class, count = 0;

		range_elem_obj = json_object_array_get_idx(obj, i);
		if (!json_object_object_get_ex(range_elem_obj,
					       "globalOperatingClass",
					       &op_class_obj))
			continue;

		op_class = json_object_get_int(op_class_obj);
		if (op_class != iface->conf->op_class)
			continue;

		if (!json_object_object_get_ex(range_elem_obj, "maxEirp",
					       &max_eirp_obj))
			continue;

		if (!json_object_object_get_ex(range_elem_obj, "channelCfi",
					       &chan_cfi_obj))
			continue;

		for (ch = 0;
		     ch < json_object_array_length(chan_cfi_obj); ch++) {
			struct json_object *pwr_obj;
			struct json_object *ch_obj;
			int channel, power;

			ch_obj = json_object_array_get_idx(chan_cfi_obj, ch);
			if (!ch_obj)
				continue;

			pwr_obj = json_object_array_get_idx(max_eirp_obj, ch);
			if (!pwr_obj)
				continue;

			channel = json_object_get_int(ch_obj);
			power = json_object_get_int(pwr_obj);

			c = os_realloc_array(c, count + 1, sizeof(*c));
			if (!c)
				return -ENOMEM;

			c[count].chan = channel;
			c[count++].power = power;
		}
		os_free(iface->afc.chan_info_list);
		iface->afc.chan_info_list = c;
		iface->afc.num_chan_info = count;

		for (j = 0; j < mode->num_channels; j++) {
			struct hostapd_channel_data *chan = &mode->channels[j];
			int n;

			if (!is_6ghz_freq(chan->freq))
				continue;

			for (n = 0; n < count; n++) {
				if (chan->chan == c[n].chan)
					break;
			}

			if (n == count)
				chan->flag |= HOSTAPD_CHAN_DISABLED;
		}
	}

	return 0;
}


static int hostad_afc_get_timeout(struct json_object *obj)
{
	time_t t, now;
	struct tm tm;

	if (sscanf(json_object_get_string(obj), "%d-%d-%dT%d:%d:%dZ",
		   &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
		   &tm.tm_min, &tm.tm_sec) <= 0)
		return HOSTAPD_AFC_TIMEOUT;

	tm.tm_year -= 1900;
	tm.tm_mon -= 1;
	tm.tm_isdst = -1;
	t = mktime(&tm);
	time(&now);

	return now > t ? HOSTAPD_AFC_RETRY_TIMEOUT : (t - now) * 80 / 100;
}


static int hostapd_afc_parse_reply(struct hostapd_iface *iface, char *reply)
{
	int i, request_timeout = HOSTAPD_AFC_RETRY_TIMEOUT, ret = -EINVAL;
	struct json_object *payload_obj, *reply_obj, *version_obj;
	struct hostapd_config *iconf = iface->conf;

	wpa_printf(MSG_DEBUG, "Received AFC reply: %s", reply);
	payload_obj = json_tokener_parse(reply);
	if (!payload_obj)
		return -EINVAL;

	if (!json_object_object_get_ex(payload_obj, "version", &version_obj))
		return -EINVAL;

	if (iconf->afc.request.version &&
	    os_strcmp(iconf->afc.request.version,
		      json_object_get_string(version_obj)))
		return -EINVAL;

	if (!json_object_object_get_ex(payload_obj,
				       "availableSpectrumInquiryResponses",
				       &reply_obj))
		return -EINVAL;

	for (i = 0; i < json_object_array_length(reply_obj); i++) {
		struct json_object *reply_elem_obj, *obj, *status_obj;
		int j, status = -EINVAL;

		reply_elem_obj = json_object_array_get_idx(reply_obj, i);
		if (!reply_elem_obj)
			continue;

		if (!json_object_object_get_ex(reply_elem_obj, "requestId",
					       &obj))
			continue;

		if (iconf->afc.request.id &&
		    os_strcmp(iconf->afc.request.id,
			      json_object_get_string(obj)))
			continue;

		if (!json_object_object_get_ex(reply_elem_obj, "rulesetId",
					       &obj))
			continue;

		for (j = 0; j < iconf->afc.n_cert_ids; j++) {
			if (!os_strcmp(iconf->afc.cert_ids[j].rulset,
				       json_object_get_string(obj)))
				break;
		}

		if (j == iconf->afc.n_cert_ids)
			continue;

		if (!json_object_object_get_ex(reply_elem_obj, "response",
					       &obj))
			continue;

		if (json_object_object_get_ex(obj, "shortDescription",
					      &status_obj))
			wpa_printf(MSG_DEBUG, "AFC reply element %d: %s",
				   i, json_object_get_string(status_obj));

		if (json_object_object_get_ex(obj, "responseCode",
					      &status_obj))
			status = json_object_get_int(status_obj);

		if (status < 0)
			continue;

		if (hostad_afc_parse_available_freq_info(iface,
							 reply_elem_obj) ||
		    hostad_afc_parse_available_chan_info(iface,
							 reply_elem_obj))
			continue;

		if (json_object_object_get_ex(reply_elem_obj,
					      "availabilityExpireTime",
					      &obj)) {
			int timeout = hostad_afc_get_timeout(obj);

			if (timeout < request_timeout)
				request_timeout = timeout;
		}

		ret = status;
	}

	return ret < 0 ? ret : request_timeout;
}


static int hostapd_afc_send_receive(struct hostapd_iface *iface,
				    int *request_timeout)
{
	struct hostapd_config *iconf = iface->conf;
	json_object *request_obj = NULL;
	struct timeval sock_timeout = {
		.tv_sec = 2,
	};
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
#ifdef __FreeBSD__
		.sun_len = sizeof(addr),
#endif /* __FreeBSD__ */
	};
	char buf[HOSTAPD_AFC_BUFSIZE] = {};
	const char *request;
	int sockfd, ret;
	fd_set read_set;

	*request_timeout = HOSTAPD_AFC_RETRY_TIMEOUT;
	if (iface->afc.data_valid)
		return 0;

	if (os_strlen(iconf->afc.socket) >= sizeof(addr.sun_path)) {
		wpa_printf(MSG_ERROR, "Malformed AFC socket string %s",
			   iconf->afc.socket);
		return -EINVAL;
	}

	os_strlcpy(addr.sun_path, iconf->afc.socket, sizeof(addr.sun_path));
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		wpa_printf(MSG_ERROR, "Failed creating AFC socket");
		return sockfd;
	}

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		wpa_printf(MSG_ERROR, "Failed connecting AFC socket");
		ret = -EIO;
		goto close_sock;
	}

	request_obj = hostapd_afc_build_request(iface);
	if (!request_obj) {
		ret = -ENOMEM;
		goto close_sock;
	}

	request = json_object_to_json_string(request_obj);
	if (send(sockfd, request, strlen(request), 0) < 0) {
		wpa_printf(MSG_ERROR, "Failed sending AFC request");
		ret = -EIO;
		goto close_sock;
	}

	FD_ZERO(&read_set);
	FD_SET(sockfd, &read_set);
	if (select(sockfd + 1, &read_set, NULL, NULL, &sock_timeout) < 0) {
		wpa_printf(MSG_ERROR, "Select failed on AFC socket");
		ret = -errno;
		goto close_sock;
	}

	if (!FD_ISSET(sockfd, &read_set)) {
		ret = -EIO;
		goto close_sock;
	}

	ret = recv(sockfd, buf, sizeof(buf), 0);
	if (ret <= 0)
		goto close_sock;

	ret = hostapd_afc_parse_reply(iface, buf);
	if (ret > 0) {
		iface->afc.data_valid = true;
		*request_timeout = ret;
		ret = 0;
	}

close_sock:
	json_object_put(request_obj);
	close(sockfd);

	return ret;
}


int hostapd_afc_handle_request(struct hostapd_iface *iface)
{
	struct hostapd_config *iconf = iface->conf;
	int ret, request_timeout;

	if (iface->afc.completed)
		return 1;

	/* AFC is required just for standard power AP */
	if (!he_reg_is_sp(iconf->he_6ghz_reg_pwr_type))
		return 1;

	if (!is_6ghz_op_class(iconf->op_class) || !is_6ghz_freq(iface->freq))
		return 1;

	ret = hostapd_afc_send_receive(iface, &request_timeout);
	if (ret < 0) {
		/*
		 * If the connection to the AFCD failed, resched for a
		 * future attempt.
		 */
		if (ret == -EIO)
			ret = 0;
		goto resched;
	}

	/* Trigger a ACS freq scan */
	iface->freq = 0;
	iconf->channel = 0;
	iface->afc.completed = true;

	if (acs_init(iface) != HOSTAPD_CHAN_ACS) {
		wpa_printf(MSG_ERROR, "Could not start ACS");
		ret = -EINVAL;
	}

resched:
	eloop_register_timeout(request_timeout, 0, hostapd_afc_timeout_handler,
			       iface, NULL);

	return ret;
}


static void hostapd_afc_timeout_handler(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_iface *iface = eloop_ctx;
	int request_timeout;

	iface->afc.data_valid = false;
	if (!hostapd_afc_send_receive(iface, &request_timeout)) {
		struct hostapd_hw_modes *mode = iface->current_mode;
		int i;

		for (i = 0; i < mode->num_channels; i++) {
			struct hostapd_channel_data *chan = &mode->channels[i];

			if (chan->freq != iface->freq ||
			    (chan->flag & HOSTAPD_CHAN_DISABLED))
				continue;

			eloop_register_timeout(request_timeout, 0,
					       hostapd_afc_timeout_handler,
					       iface, NULL);
			return;
		}
	}

	/* Toggle interface to trigger new AFC connection */
	iface->afc.completed = false;
	hostapd_disable_iface(iface);
	hostapd_enable_iface(iface);
}
