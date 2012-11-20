/*
 * hostapd / EAP Full Authenticator state machine (RFC 4137)
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef EAP_H
#define EAP_H

#include "common/defs.h"
#include "eap_common/eap_defs.h"
#include "eap_server/eap_methods.h"
#include "wpabuf.h"

struct eap_sm;

#define EAP_MAX_METHODS 8

#define EAP_TTLS_AUTH_PAP 1
#define EAP_TTLS_AUTH_CHAP 2
#define EAP_TTLS_AUTH_MSCHAP 4
#define EAP_TTLS_AUTH_MSCHAPV2 8

struct eap_user {
	struct {
		int vendor;
		u32 method;
	} methods[EAP_MAX_METHODS];
	u8 *password;
	size_t password_len;
	int password_hash; /* whether password is hashed with
			    * nt_password_hash() */
	int phase2;
	int force_version;
	int ttls_auth; /* bitfield of
			* EAP_TTLS_AUTH_{PAP,CHAP,MSCHAP,MSCHAPV2} */
};

struct eap_eapol_interface {
	/* Lower layer to full authenticator variables */
	Boolean eapResp; /* shared with EAPOL Backend Authentication */
	struct wpabuf *eapRespData;
	/* portEnabled - Set by the EAPOL entity if EAPOL PDUs
	can be transmitted and received by the PAE. */
	Boolean portEnabled;
	int retransWhile;
	/* eapRestart - This variable is set to TRUE by the Authenticator state machine
	to signal it is restarting its state machine due to an EAPOL packet,
	a timeout, or an initialization event. */
	Boolean eapRestart; /* shared with EAPOL Authenticator PAE */
	int eapSRTT;
	int eapRTTVAR;

	/* Full authenticator to lower layer variables */
	/* eapReq - This variable is set TRUE by the higher layer
	when it has an EAP frame to be sent to the Supplicant.
	It is set to FALSE by the Backend Authentication state machine
	when the EAP-frame has been transmitted. */
	Boolean eapReq; /* shared with EAPOL Backend Authentication */
	/* eapNoReq - This variable is set TRUE by the higher layer when
	it has no EAP frame to be sent to the Supplicant in response to
	the last EAP frame sent by the Supplicant. */
	Boolean eapNoReq; /* shared with EAPOL Backend Authentication */
	/* eapSuccess - The eapSuccess signal is set by the higher layer to indicate that
	the EAP authentication exchange has completed with a successful outcome.
	This will cause the PAE state machine to initiate other processing that may
	result in entering the authenticated state.
	The higher layer should set this signal in conjunction with the eapNoResp signal.
	This signal is reset by the higher layer during its initialization of state. */
	Boolean eapSuccess;
	/* eapFail - This signal is set by the higher layer to indicate that
	the EAP authentication exchange has completed with an unsuccessful outcome.
	This will cause the PAE state machine to initiate other processing that
	will result in entering the held state.
	The higher layer should set this signal in conjunction with the eapNoResp signal.
	This signal is reset by the higher layer during its initialization of state. */
	Boolean eapFail;
	/* eapTimeout - The higher layer should set this signal to indicate that
	it has waited too long to receive a new EAP Request from the Authentication Server.
	The PAE Authenticator state machine will begin the process of aborting the
	current authentication exchange and will restart a new authentication.
	The higher layer should reset this signal whenever it is initialized. */
	Boolean eapTimeout;
	struct wpabuf *eapReqData;
	u8 *eapKeyData;
	size_t eapKeyDataLen;
	/* keyAvailable - The higher layer should set this signal when
	the Authentication Server has made available any keying material necessary
	to generate an EAPOL-Key message.
	Once this signal is set the PAE key transmit machine will gather the key material
	and begin the process of making the link secure.
	The PAE key transmit machine will reset this signal once the link has been made secure. */
	Boolean eapKeyAvailable; /* called keyAvailable in IEEE 802.1X-2004 */

	/* AAA interface to full authenticator variables */
	Boolean aaaEapReq;
	Boolean aaaEapNoReq;
	/* 认证成功 */
	Boolean aaaSuccess;
	/* 认证拒绝 */
	Boolean aaaFail;
	/* 认证服务器RADIUS报文中的EAP-MESSAGE数据 */
	struct wpabuf *aaaEapReqData;
	u8 *aaaEapKeyData;
	size_t aaaEapKeyDataLen;
	Boolean aaaEapKeyAvailable;
	int aaaMethodTimeout;

	/* Full authenticator to AAA interface variables */
	Boolean aaaEapResp;
	struct wpabuf *aaaEapRespData;
	/* aaaIdentity -> eap_get_identity() */
	Boolean aaaTimeout;
};

struct eapol_callbacks {
	int (*get_eap_user)(void *ctx, const u8 *identity, size_t identity_len,
			    int phase2, struct eap_user *user);
	const char * (*get_eap_req_id_text)(void *ctx, size_t *len);
};

struct eap_config {
	void *ssl_ctx;
	void *msg_ctx;
	void *eap_sim_db_priv;
	Boolean backend_auth;
	int eap_server;
	u16 pwd_group;
	u8 *pac_opaque_encr_key;
	u8 *eap_fast_a_id;
	size_t eap_fast_a_id_len;
	char *eap_fast_a_id_info;
	int eap_fast_prov;
	int pac_key_lifetime;
	int pac_key_refresh_time;
	int eap_sim_aka_result_ind;
	int tnc;
	struct wps_context *wps;
	const struct wpabuf *assoc_wps_ie;
	const struct wpabuf *assoc_p2p_ie;
	const u8 *peer_addr;
	int fragment_size;

	int pbc_in_m1;
};


struct eap_sm * eap_server_sm_init(void *eapol_ctx,
				   struct eapol_callbacks *eapol_cb,
				   struct eap_config *eap_conf);
void eap_server_sm_deinit(struct eap_sm *sm);
int eap_server_sm_step(struct eap_sm *sm);
void eap_sm_notify_cached(struct eap_sm *sm);
void eap_sm_pending_cb(struct eap_sm *sm);
int eap_sm_method_pending(struct eap_sm *sm);
const u8 * eap_get_identity(struct eap_sm *sm, size_t *len);
struct eap_eapol_interface * eap_get_interface(struct eap_sm *sm);
void eap_server_clear_identity(struct eap_sm *sm);

#endif /* EAP_H */
