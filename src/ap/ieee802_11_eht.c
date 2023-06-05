/*
 * hostapd / IEEE 802.11be EHT
 * Copyright (c) 2021-2022, Qualcomm Innovation Center, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "sta_info.h"
#include "ieee802_11.h"
#include "crypto/dh_groups.h"


static u16 ieee80211_eht_ppet_size(u16 ppe_thres_hdr, const u8 *phy_cap_info)
{
	u8 ru;
	u16 sz = 0;

	if ((phy_cap_info[EHT_PHYCAP_PPE_THRESHOLD_PRESENT_IDX] &
	     EHT_PHYCAP_PPE_THRESHOLD_PRESENT) == 0)
		return 0;

	ru = (ppe_thres_hdr &
	      EHT_PPE_THRES_RU_INDEX_MASK) >> EHT_PPE_THRES_RU_INDEX_SHIFT;
	while (ru) {
		if (ru & 0x1)
			sz++;
		ru >>= 1;
	}

	sz = sz * (1 + ((ppe_thres_hdr & EHT_PPE_THRES_NSS_MASK) >>
			EHT_PPE_THRES_NSS_SHIFT));
	sz = (sz * 6) + 9;
	if (sz % 8)
		sz += 8;
	sz /= 8;

	return sz;
}


static u8 ieee80211_eht_mcs_set_size(enum hostapd_hw_mode mode, u8 opclass,
				     u8 he_oper_chwidth, const u8 *he_phy_cap,
				     const u8 *eht_phy_cap)
{
	u8 sz = EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;
	bool band24, band5, band6;
	u8 he_phy_cap_chwidth = ~HE_PHYCAP_CHANNEL_WIDTH_MASK;

	switch (he_oper_chwidth) {
	case CONF_OPER_CHWIDTH_80P80MHZ:
		he_phy_cap_chwidth |=
			HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G;
		/* fall through */
	case CONF_OPER_CHWIDTH_160MHZ:
		he_phy_cap_chwidth |= HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G;
		/* fall through */
	case CONF_OPER_CHWIDTH_80MHZ:
	case CONF_OPER_CHWIDTH_USE_HT:
		he_phy_cap_chwidth |= HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G |
			HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
		break;
	}

	he_phy_cap_chwidth &= he_phy_cap[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX];

	band24 = mode == HOSTAPD_MODE_IEEE80211B ||
		mode == HOSTAPD_MODE_IEEE80211G ||
		mode == NUM_HOSTAPD_MODES;
	band5 = mode == HOSTAPD_MODE_IEEE80211A ||
		mode == NUM_HOSTAPD_MODES;
	band6 = is_6ghz_op_class(opclass);

	if (band24 &&
	    (he_phy_cap_chwidth & HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G) == 0)
		return EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY;

	if (band5 &&
	    (he_phy_cap_chwidth &
	     (HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G |
	      HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	      HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G)) == 0)
		return EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY;

	if (band5 &&
	    (he_phy_cap_chwidth &
	     (HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	      HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G)))
	    sz += EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;

	if (band6 &&
	    (eht_phy_cap[EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &
	     EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK))
		sz += EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;

	return sz;
}


size_t hostapd_eid_eht_capab_len(struct hostapd_data *hapd,
				 enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct eht_capabilities *eht_cap;
	size_t len = 3 + 2 + EHT_PHY_CAPAB_LEN;

	mode = hapd->iface->current_mode;
	if (!mode)
		return 0;

	eht_cap = &mode->eht_capab[opmode];
	if (!eht_cap->eht_supported)
		return 0;

	len += ieee80211_eht_mcs_set_size(mode->mode, hapd->iconf->op_class,
					  hapd->iconf->he_oper_chwidth,
					  mode->he_capab[opmode].phy_cap,
					  eht_cap->phy_cap);
	len += ieee80211_eht_ppet_size(WPA_GET_LE16(&eht_cap->ppet[0]),
				       eht_cap->phy_cap);

	return len;
}


u8 * hostapd_eid_eht_capab(struct hostapd_data *hapd, u8 *eid,
			   enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct eht_capabilities *eht_cap;
	struct ieee80211_eht_capabilities *cap;
	size_t mcs_nss_len, ppe_thresh_len;
	u8 *pos = eid, *length_pos;

	mode = hapd->iface->current_mode;
	if (!mode)
		return eid;

	eht_cap = &mode->eht_capab[opmode];
	if (!eht_cap->eht_supported)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_EHT_CAPABILITIES;

	cap = (struct ieee80211_eht_capabilities *) pos;
	os_memset(cap, 0, sizeof(*cap));
	cap->mac_cap = host_to_le16(eht_cap->mac_cap);
	os_memcpy(cap->phy_cap, eht_cap->phy_cap, EHT_PHY_CAPAB_LEN);

	if (!is_6ghz_op_class(hapd->iconf->op_class))
		cap->phy_cap[EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &=
			~EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK;
	if (!hapd->iface->conf->eht_phy_capab.su_beamformer)
		cap->phy_cap[EHT_PHYCAP_SU_BEAMFORMER_IDX] &=
			~EHT_PHYCAP_SU_BEAMFORMER;

	if (!hapd->iface->conf->eht_phy_capab.su_beamformee)
		cap->phy_cap[EHT_PHYCAP_SU_BEAMFORMEE_IDX] &=
			~EHT_PHYCAP_SU_BEAMFORMEE;

	if (!hapd->iface->conf->eht_phy_capab.mu_beamformer)
		cap->phy_cap[EHT_PHYCAP_MU_BEAMFORMER_IDX] &=
			~EHT_PHYCAP_MU_BEAMFORMER_MASK;

	pos = cap->optional;

	mcs_nss_len = ieee80211_eht_mcs_set_size(mode->mode,
						 hapd->iconf->op_class,
						 hapd->iconf->he_oper_chwidth,
						 mode->he_capab[opmode].phy_cap,
						 eht_cap->phy_cap);
	if (mcs_nss_len) {
		os_memcpy(pos, eht_cap->mcs, mcs_nss_len);
		pos += mcs_nss_len;
	}

	ppe_thresh_len = ieee80211_eht_ppet_size(
				WPA_GET_LE16(&eht_cap->ppet[0]),
				eht_cap->phy_cap);
	if (ppe_thresh_len) {
		os_memcpy(pos, eht_cap->ppet, ppe_thresh_len);
		pos += ppe_thresh_len;
	}

	*length_pos = pos - (eid + 2);
	return pos;
}


u8 * hostapd_eid_eht_operation(struct hostapd_data *hapd, u8 *eid)
{
	struct hostapd_config *conf = hapd->iconf;
	struct ieee80211_eht_operation *oper;
	u8 *pos = eid, seg0 = 0, seg1 = 0;
	enum oper_chan_width chwidth;
	size_t elen = 1 + 4 + 3;

	if (!hapd->iface->current_mode)
		return eid;

	if (hapd->iconf->punct_bitmap)
		elen += EHT_OPER_DISABLED_SUBCHAN_BITMAP_SIZE;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + elen;
	*pos++ = WLAN_EID_EXT_EHT_OPERATION;

	oper = (struct ieee80211_eht_operation *) pos;
	oper->oper_params = EHT_OPER_INFO_PRESENT;

	/* TODO: Fill in appropriate EHT-MCS max Nss information */
	oper->basic_eht_mcs_nss_set[0] = 0x11;
	oper->basic_eht_mcs_nss_set[1] = 0x00;
	oper->basic_eht_mcs_nss_set[2] = 0x00;
	oper->basic_eht_mcs_nss_set[3] = 0x00;

	if (is_6ghz_op_class(conf->op_class))
		chwidth = op_class_to_ch_width(conf->op_class);
	else
		chwidth = conf->eht_oper_chwidth;

	seg0 = hostapd_get_oper_centr_freq_seg0_idx(conf);

	switch (chwidth) {
	case CONF_OPER_CHWIDTH_320MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_320MHZ;
		seg1 = seg0;
		if (hapd->iconf->channel < seg0)
			seg0 -= 16;
		else
			seg0 += 16;
		break;
	case CONF_OPER_CHWIDTH_160MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_160MHZ;
		seg1 = seg0;
		if (hapd->iconf->channel < seg0)
			seg0 -= 8;
		else
			seg0 += 8;
		break;
	case CONF_OPER_CHWIDTH_80MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_80MHZ;
		break;
	case CONF_OPER_CHWIDTH_USE_HT:
		if (seg0)
			oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_40MHZ;
		break;
	default:
		return eid;
	}

	oper->oper_info.ccfs0 = seg0 ? seg0 : hapd->iconf->channel;
	oper->oper_info.ccfs1 = seg1;

	if (hapd->iconf->punct_bitmap) {
		oper->oper_params |= EHT_OPER_DISABLED_SUBCHAN_BITMAP_PRESENT;
		oper->oper_info.disabled_chan_bitmap =
			host_to_le16(hapd->iconf->punct_bitmap);
	}

	return pos + elen;
}


static bool check_valid_eht_mcs_nss(struct hostapd_data *hapd, const u8 *ap_mcs,
				    const u8 *sta_mcs, u8 mcs_count, u8 map_len)
{
	unsigned int i, j;

	for (i = 0; i < mcs_count; i++) {
		ap_mcs += i * 3;
		sta_mcs += i * 3;

		for (j = 0; j < map_len; j++) {
			if (((ap_mcs[j] >> 4) & 0xFF) == 0)
				continue;

			if ((sta_mcs[j] & 0xFF) == 0)
				continue;

			return true;
		}
	}

	wpa_printf(MSG_DEBUG,
		   "No matching EHT MCS found between AP TX and STA RX");
	return false;
}


static bool check_valid_eht_mcs(struct hostapd_data *hapd,
				const u8 *sta_eht_capab,
				enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	const struct ieee80211_eht_capabilities *capab;
	const u8 *ap_mcs, *sta_mcs;
	u8 mcs_count = 1;

	mode = hapd->iface->current_mode;
	if (!mode)
		return true;

	ap_mcs = mode->eht_capab[opmode].mcs;
	capab = (const struct ieee80211_eht_capabilities *) sta_eht_capab;
	sta_mcs = capab->optional;

	if (ieee80211_eht_mcs_set_size(mode->mode, hapd->iconf->op_class,
				       hapd->iconf->he_oper_chwidth,
				       mode->he_capab[opmode].phy_cap,
				       mode->eht_capab[opmode].phy_cap) ==
	    EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY)
		return check_valid_eht_mcs_nss(
			hapd, ap_mcs, sta_mcs, 1,
			EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY);

	switch (hapd->iface->conf->eht_oper_chwidth) {
	case CONF_OPER_CHWIDTH_320MHZ:
		mcs_count++;
		/* fall through */
	case CONF_OPER_CHWIDTH_80P80MHZ:
	case CONF_OPER_CHWIDTH_160MHZ:
		mcs_count++;
		break;
	default:
		break;
	}

	return check_valid_eht_mcs_nss(hapd, ap_mcs, sta_mcs, mcs_count,
				       EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS);
}


static bool ieee80211_invalid_eht_cap_size(enum hostapd_hw_mode mode,
					   u8 opclass, u8 he_oper_chwidth,
					   const u8 *he_cap, const u8 *eht_cap,
					   size_t len)
{
	const struct ieee80211_he_capabilities *he_capab;
	struct ieee80211_eht_capabilities *cap;
	const u8 *he_phy_cap;
	size_t cap_len;
	u16 ppe_thres_hdr;

	he_capab = (const struct ieee80211_he_capabilities *) he_cap;
	he_phy_cap = he_capab->he_phy_capab_info;
	cap = (struct ieee80211_eht_capabilities *) eht_cap;
	cap_len = sizeof(*cap) - sizeof(cap->optional);
	if (len < cap_len)
		return true;

	cap_len += ieee80211_eht_mcs_set_size(mode, opclass, he_oper_chwidth,
					      he_phy_cap, cap->phy_cap);
	if (len < cap_len)
		return true;

	ppe_thres_hdr = len > cap_len + 1 ?
		WPA_GET_LE16(&eht_cap[cap_len]) : 0x01ff;
	cap_len += ieee80211_eht_ppet_size(ppe_thres_hdr, cap->phy_cap);

	return len < cap_len;
}


u16 copy_sta_eht_capab(struct hostapd_data *hapd, struct sta_info *sta,
		       enum ieee80211_op_mode opmode,
		       const u8 *he_capab, size_t he_capab_len,
		       const u8 *eht_capab, size_t eht_capab_len)
{
	struct hostapd_hw_modes *c_mode = hapd->iface->current_mode;
	enum hostapd_hw_mode mode = c_mode ? c_mode->mode : NUM_HOSTAPD_MODES;

	if (!hapd->iconf->ieee80211be || hapd->conf->disable_11be ||
	    !he_capab || he_capab_len < IEEE80211_HE_CAPAB_MIN_LEN ||
	    !eht_capab ||
	    ieee80211_invalid_eht_cap_size(mode, hapd->iconf->op_class,
					   hapd->iconf->he_oper_chwidth,
					   he_capab, eht_capab,
					   eht_capab_len) ||
	    !check_valid_eht_mcs(hapd, eht_capab, opmode)) {
		sta->flags &= ~WLAN_STA_EHT;
		os_free(sta->eht_capab);
		sta->eht_capab = NULL;
		return WLAN_STATUS_SUCCESS;
	}

	os_free(sta->eht_capab);
	sta->eht_capab = os_memdup(eht_capab, eht_capab_len);
	if (!sta->eht_capab) {
		sta->eht_capab_len = 0;
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->flags |= WLAN_STA_EHT;
	sta->eht_capab_len = eht_capab_len;

	return WLAN_STATUS_SUCCESS;
}


void hostapd_get_eht_capab(struct hostapd_data *hapd,
			   const struct ieee80211_eht_capabilities *src,
			   struct ieee80211_eht_capabilities *dest,
			   size_t len)
{
	if (!src || !dest)
		return;

	if (len > sizeof(*dest))
		len = sizeof(*dest);
	/* TODO: mask out unsupported features */

	os_memset(dest, 0, sizeof(*dest));
	os_memcpy(dest, src, len);
}

u8 *hostapd_eid_eht_basic_ml(struct hostapd_data *hapd, u8 *eid,
			     struct sta_info *info, bool include_mld_id)
{
	struct wpabuf *buf;
	u16 control;
	u8 *pos = eid;
	const u8 *ptr;
	size_t len, slice_len;
	u8 link_id;
	u8 common_info_len;

	/*
	 * As the ML element can exceed the size of 244 bytes need to first
	 * build it and then handle defragmentation
	 */
	buf = wpabuf_alloc(1024);
	if (!buf)
		return pos;

	/* set the multi-link control field */
	control = MULTI_LINK_CONTROL_TYPE_BASIC |
		  BASIC_MULTI_LINK_CTRL_PRES_LINK_ID |
		  BASIC_MULTI_LINK_CTRL_PRES_BSS_PARAM_CH_COUNT |
		  BASIC_MULTI_LINK_CTRL_PRES_EML_CAPA |
		  BASIC_MULTI_LINK_CTRL_PRES_MLD_CAPA;

	/*
	 * set the basic multi-link common information. Hard code the common
	 * info length to 13 based on the length of the present fields:
	 * Length (1) + MLD address (6) + Link ID (1) +
	 * BSS change parameter (1) + MLD EML capabilities (2) +
	 * MLD MLD capabilities (2)
	 */
	common_info_len = 13;

	if (include_mld_id) {
		control |= BASIC_MULTI_LINK_CTRL_PRES_AP_MLD_ID;
		common_info_len++;
	}

	wpabuf_put_le16(buf, control);

	wpabuf_put_u8(buf, common_info_len);

	/* own MLD address */
	wpabuf_put_data(buf, hapd->mld_addr, ETH_ALEN);

	/* own link ID */
	wpabuf_put_u8(buf, hapd->mld_link_id);

	/* currently hard code the BSS change parameters to 0x1 */
	wpabuf_put_u8(buf, 0x1);

	wpa_printf(MSG_DEBUG, "MLD: EML capabilities=0x%x",
		   hapd->iface->mld_eml_capa);

	wpabuf_put_le16(buf, hapd->iface->mld_eml_capa);

	wpa_printf(MSG_DEBUG, "MLD: MLD capabilities=0x%x",
		   hapd->iface->mld_mld_capa);

	wpabuf_put_le16(buf, hapd->iface->mld_mld_capa);

	if (include_mld_id) {
		wpa_printf(MSG_DEBUG, "MLD: MLD ID=0x%x", hapd->conf->mld_id);
		wpabuf_put_u8(buf, hapd->conf->mld_id);
	}

	if (!info)
		goto out;

	/* Add link info for the other links */
	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
		struct mld_link_info *link = &info->mld_info.links[link_id];
		struct hostapd_data *link_bss;

		/*
		 * control (2) + station info length (1) + MAC address (6) +
		 * beacon interval (2) + TSF offset (8) + DTIM info (2) + BSS
		 * parameters change counter (1) + station profile length.
		 */
		const size_t fixed_len = 22;
		size_t total_len = fixed_len + link->resp_sta_profile_len;

		/* skip the local one */
		if (link_id == hapd->mld_link_id || !link->valid)
			continue;

		link_bss = hostapd_mld_get_link_bss(hapd, link_id);
		if (!link_bss) {
			wpa_printf(MSG_ERROR, "MLD: Couldn't find link BSS - skip it");
			continue;
		}

		wpabuf_put_u8(buf, EHT_ML_SUB_ELEM_PER_STA_PROFILE);

		if (total_len <= 255)
			wpabuf_put_u8(buf, total_len);
		else
			wpabuf_put_u8(buf, 255);

		control = (link_id & 0xf) |
			EHT_PER_STA_CTRL_MAC_ADDR_PRESENT_MSK |
			EHT_PER_STA_CTRL_COMPLETE_PROFILE_MSK |
			EHT_PER_STA_CTRL_TSF_OFFSET_PRESENT_MSK |
			EHT_PER_STA_CTRL_BEACON_INTERVAL_PRESENT_MSK |
			EHT_PER_STA_CTRL_DTIM_INFO_PRESENT_MSK |
			EHT_PER_STA_CTRL_BSS_PARAM_CNT_PRESENT_MSK;

		wpabuf_put_le16(buf, control);

		/* STA info length */
		wpabuf_put_u8(buf, fixed_len - 2);
		wpabuf_put_data(buf, link->local_addr, ETH_ALEN);
		wpabuf_put_le16(buf, link_bss->iconf->beacon_int);

		/*
		 * TODO: currently setting TSF offset to zero. However this
		 * information needs to come from the driver
		 */
		wpabuf_put_le32(buf, 0);
		wpabuf_put_le32(buf, 0);

		wpabuf_put_le16(buf, link_bss->conf->dtim_period);

		/* TODO: currently hard code the BSS change parameters to 0x1 */
		wpabuf_put_u8(buf, 0x1);

		/* Fragment the sub element if needed */
		if (total_len <= 255) {
			wpabuf_put_data(buf, link->resp_sta_profile,
					link->resp_sta_profile_len);
		} else {
			ptr = link->resp_sta_profile;
			len = link->resp_sta_profile_len;

			slice_len = 255 - fixed_len;

			wpabuf_put_data(buf, ptr, slice_len);
			len -= slice_len;
			ptr += slice_len;

			while (len) {
				if (len <= 255)
					slice_len = len;
				else
					slice_len = 255;

				wpabuf_put_u8(buf, EHT_ML_SUB_ELEM_FRAGMENT);
				wpabuf_put_u8(buf, slice_len);
				wpabuf_put_data(buf, ptr, slice_len);

				len -= slice_len;
				ptr += slice_len;
			}
		}
	}

out:
	/* start the fragmentation */
	len = wpabuf_len(buf);
	ptr = wpabuf_head(buf);

	if (len <= 254)
		slice_len = len;
	else
		slice_len = 254;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = slice_len + 1;
	*pos++ = WLAN_EID_EXT_MULTI_LINK;
	os_memcpy(pos, ptr, slice_len);

	ptr += slice_len;
	pos += slice_len;
	len -= slice_len;

	while (len) {
		if (len <= 255)
			slice_len = len;
		else
			slice_len = 255;

		*pos++ = WLAN_EID_FRAGMENT;
		*pos++ = slice_len;
		os_memcpy(pos, ptr, slice_len);

		ptr += slice_len;
		pos += slice_len;
		len -= slice_len;
	}

	wpabuf_free(buf);
	return pos;
}

struct wpabuf *hostapd_ml_auth_resp(struct hostapd_data *hapd)
{
	struct wpabuf *buf = wpabuf_alloc(12);

	if (!buf)
		return NULL;

	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	wpabuf_put_u8(buf, 10);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MULTI_LINK);
	wpabuf_put_le16(buf, MULTI_LINK_CONTROL_TYPE_BASIC);
	wpabuf_put_u8(buf, ETH_ALEN + 1);
	wpabuf_put_data(buf, hapd->mld_addr, ETH_ALEN);

	return buf;
}


static const u8 *auth_skip_fixed_fields(struct hostapd_data *hapd,
					const struct ieee80211_mgmt *mgmt,
					size_t len)
{
	u16 auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
	u16 auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
	u16 status_code = le_to_host16(mgmt->u.auth.status_code);
	const u8 *pos = mgmt->u.auth.variable;

	/* Skip fixed fields as defined in table 9-41 */
	switch (auth_alg) {
	case WLAN_AUTH_OPEN:
		return pos;
	case WLAN_AUTH_SAE:
		if (auth_transaction == 1) {
			u16 group;
			size_t prime_len;
			struct crypto_ec *ec;

			if (status_code == WLAN_STATUS_SUCCESS) {
				wpa_printf(MSG_DEBUG,
					   "EHT: SAE: H2E is mandatory for MLD");
				goto out;
			}

			if (status_code != WLAN_STATUS_SAE_HASH_TO_ELEMENT)
				return pos;

			/* H2E commit message (group, scalar, FFE) */
			if (len < 2) {
				wpa_printf(MSG_DEBUG,
					   "EHT: SAE: Group is not present");
				return NULL;
			}

			group = WPA_GET_LE16(pos);
			pos += 2;

			/* TODO: how to parse when the group is unknown? */
			ec = crypto_ec_init(group);
			if (!ec) {
				const struct dh_group *dh =
					dh_groups_get(group);

				if (!dh) {
					wpa_printf(MSG_DEBUG,
						   "EHT: SAE: Unknown group=%u",
						   group);
					return NULL;
				}

				prime_len = dh->prime_len;
			} else {
				prime_len = crypto_ec_prime_len(ec);
			}

			wpa_printf(MSG_DEBUG, "EHT: SAE: scalar length is %zu",
				   prime_len);

			/* scalar */
			pos += prime_len;

			if (ec) {
				pos += prime_len * 2;
				crypto_ec_deinit(ec);
			} else {
				pos += prime_len;
			}

			if (pos - mgmt->u.auth.variable > (int)len) {
				wpa_printf(MSG_DEBUG,
					   "EHT: SAE: frame too short");
				return NULL;
			}

			wpa_hexdump(MSG_DEBUG, "EHT: SAE: remaining auth:",
				    pos,
				    (int)len - (pos - mgmt->u.auth.variable));
		} else if (auth_transaction == 2) {
			struct sta_info *sta;

			if (status_code ==
			    WLAN_STATUS_REJECTED_WITH_SUGGESTED_BSS_TRANSITION)
				return pos;

			/* send confirm integer */
			pos += 2;

			/*
			 * At this stage we should already have an MLD station
			 * and actually sa, will be replaced to MLD address by
			 * the kernel.
			 */
			sta = ap_get_sta(hapd, mgmt->sa);
			if (!sta) {
				wpa_printf(MSG_DEBUG,
					   "SAE: No MLD sta for SAE confirm");
				return NULL;
			}

			if (!sta->sae || sta->sae->state < SAE_COMMITTED ||
			    !sta->sae->tmp) {
				if (sta->sae)
					wpa_printf(MSG_DEBUG,
						   "SAE: Invalid state=%u",
						   sta->sae ?
						   sta->sae->state :
						   SAE_NOTHING);
				else
					wpa_printf(MSG_DEBUG,
						   "SAE: state is NULL");
				return NULL;
			}

			wpa_printf(MSG_DEBUG, "SAE: confirm: kck_len=%zu",
				   sta->sae->tmp->kck_len);

			pos += sta->sae->tmp->kck_len;

			if (pos - mgmt->u.auth.variable > (int)len) {
				wpa_printf(MSG_DEBUG,
					   "EHT: Too short SAE AUTH frame");
				return NULL;
			}
		}

		return pos;

	/* TODO: support additional algorithms */
	case WLAN_AUTH_FT:
	case WLAN_AUTH_FILS_SK:
	case WLAN_AUTH_FILS_SK_PFS:
	case WLAN_AUTH_FILS_PK:
	case WLAN_AUTH_PASN:
	case WLAN_AUTH_LEAP:
	case WLAN_AUTH_SHARED_KEY:
	default:
		break;
	}

out:
	wpa_printf(MSG_DEBUG,
		   "TODO: Auth method not supported with MLD (%d)",
		   auth_alg);
	return NULL;
}


const u8 *hostapd_process_ml_auth(struct hostapd_data *hapd,
				  const struct ieee80211_mgmt *mgmt,
				  size_t len)
{
	struct ieee802_11_elems elems;
	const u8 *pos;

	if (!hapd->conf->mld_ap)
		return NULL;

	len -= offsetof(struct ieee80211_mgmt, u.auth.variable);

	pos = auth_skip_fixed_fields(hapd, mgmt, len);
	if (!pos)
		return NULL;

	if (ieee802_11_parse_elems(pos,
				   (int)len - (pos - mgmt->u.auth.variable),
				   &elems, 0) == ParseFailed) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Failed parsing Authentication frame");
	}

	if (!elems.basic_mle || !elems.basic_mle_len)
		return NULL;

	return get_basic_mle_mld_addr(elems.basic_mle, elems.basic_mle_len);
}
