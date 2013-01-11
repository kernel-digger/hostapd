/*
 * hostapd - IEEE 802.11i-2004 / WPA Authenticator: Internal definitions
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

#ifndef WPA_AUTH_I_H
#define WPA_AUTH_I_H

/* max(dot11RSNAConfigGroupUpdateCount,dot11RSNAConfigPairwiseUpdateCount) */
#define RSNA_MAX_EAPOL_RETRIES 4

struct wpa_group;

struct wpa_stsl_negotiation {
	struct wpa_stsl_negotiation *next;
	u8 initiator[ETH_ALEN];
	u8 peer[ETH_ALEN];
};


/*
每个STA的WPA认证状态机
由wpa_auth_sta_init()初始化
*/
struct wpa_state_machine {
	/* 所关联的bss的认证者结构 */
	struct wpa_authenticator *wpa_auth;
	struct wpa_group *group;

	/* STA MAC */
	u8 addr[ETH_ALEN];

	/* 该字段的状态赋值由宏SM_ENTRY_MA控制
	   比如SM_ENTRY_MA(WPA_PTK, INITIALIZE, wpa_ptk);
	   即sm->wpa_ptk_state = WPA_PTK_INITIALIZE;
	*/
	enum {
		WPA_PTK_INITIALIZE, WPA_PTK_DISCONNECT, WPA_PTK_DISCONNECTED,
		WPA_PTK_AUTHENTICATION, WPA_PTK_AUTHENTICATION2,
		WPA_PTK_INITPMK, WPA_PTK_INITPSK, WPA_PTK_PTKSTART,
		WPA_PTK_PTKCALCNEGOTIATING, WPA_PTK_PTKCALCNEGOTIATING2,
		WPA_PTK_PTKINITNEGOTIATING, WPA_PTK_PTKINITDONE
	} wpa_ptk_state;

	enum {
		WPA_PTK_GROUP_IDLE = 0,
		WPA_PTK_GROUP_REKEYNEGOTIATING,
		WPA_PTK_GROUP_REKEYESTABLISHED,
		WPA_PTK_GROUP_KEYERROR
	} wpa_ptk_group_state;

	/* Init - This variable is used to initialize per-STA state machine. */
	Boolean Init;
	/* DeauthenticationRequest - This variable is set to TRUE
	if a Disassociation or Deauthentication message is received. */
	Boolean DeauthenticationRequest;
	/* AuthenticationRequest - This variable is set to TRUE
	by the STA's IEEE 802.11 management entity in order to authenticate an association.
	This can be set to TRUE when the STA associates or at other times. */
	Boolean AuthenticationRequest;
	/* ReAuthenticationRequest - This variable is set to TRUE
	if the IEEE 802.1X Authenticator received an eapStart or 802.1X::reAuthenticate is 1. */
	Boolean ReAuthenticationRequest;
	/* Disconnect - This variable is set to TRUE
	when the STA should initiate a deauthentication. */
	Boolean Disconnect;
	/* TimeoutCtr - This variable maintains the count of EAPOL-Key receive timeouts.
	It is incremented each time a timeout occurs on EAPOL-Key receive event
	and is initialized to 0. */
	int TimeoutCtr;
	/* GTimeoutCtr - This variable maintains the count of EAPOL-Key receive timeouts
	for the Group Key Handshake. It is incremented each time a timeout
	occurs on EAPOL-Key receive event and is initialized to 0. */
	int GTimeoutCtr;
	/* TimeoutEvt - This variable is set to TRUE
	if the EAPOL-Key frame sent out fails to obtain a response from the Supplicant.
	The variable may be set to 1 by management action
	or set to 1 by the operation of a timeout while in the PTKSTART and REKEYNEGOTIATING states. */
	Boolean TimeoutEvt;
	/* EAPOLKeyReceived - This variable is set to TRUE
	when an EAPOL-Key frame is received. */
	Boolean EAPOLKeyReceived;
	/* TRUE = 收到的EAPOL-KEY是4路握手报文，wpa_receive()中记录 */
	Boolean EAPOLKeyPairwise;
	Boolean EAPOLKeyRequest;
	/* MICVerified - This variable is set to TRUE
	if the MIC on the received EAPOL-Key frame is verified and is correct.
	Any EAPOL-Key frames with an invalid MIC are dropped and ignored. */
	Boolean MICVerified;
	/* GUpdateStationKeys - This variable is set to TRUE
	when a new GTK is available to be sent to Supplicants. */
	Boolean GUpdateStationKeys;
	/* ANonce - This variable holds the current nonce to be used if the STA is an Authenticator. */
	u8 ANonce[WPA_NONCE_LEN];
	/* STA发来的随机数，在wpa_receive()中保存 */
	u8 SNonce[WPA_NONCE_LEN];
	/* pairwise master key
	   在SM_STATE(WPA_PTK, INITPMK)或SM_STATE(WPA_PTK, INITPSK)中设置
	*/
	u8 PMK[PMK_LEN];
	/* PTK - This variable is the current PTK. */
	struct wpa_ptk PTK;
	/* 4路握手，收到STA的第2个报文，成功导出PTK后，标记为TRUE */
	Boolean PTK_valid;
	/* 4路握手完成后，置为TRUE，标记后续的EAPOL-KEY报文进行加密 */
	Boolean pairwise_set;
	int keycount;
	Boolean Pair;
	struct {
		u8 counter[WPA_REPLAY_COUNTER_LEN];
		Boolean valid;
	} key_replay[RSNA_MAX_EAPOL_RETRIES];
	Boolean PInitAKeys; /* WPA only, not in IEEE 802.11i */
	Boolean PTKRequest; /* not in IEEE 802.11i state machine */
	Boolean has_GTK;
	Boolean PtkGroupInit; /* init request for PTK Group state machine */

	u8 *last_rx_eapol_key; /* starting from IEEE 802.1X header */
	size_t last_rx_eapol_key_len;

	/* 标记状态机的状态发生了改变
	   使用宏SM_ENTRY SM_ENTRY_M SM_ENTRY_MA切换状态时
	   如果状态变了会将sm->changed = TRUE;
	*/
	unsigned int changed:1;
	unsigned int in_step_loop:1;
	unsigned int pending_deinit:1;
	unsigned int started:1;
	unsigned int mgmt_frame_prot:1;
	unsigned int rx_eapol_key_secure:1;
#ifdef CONFIG_IEEE80211R
	unsigned int ft_completed:1;
	unsigned int pmk_r1_name_valid:1;
#endif /* CONFIG_IEEE80211R */

	u8 req_replay_counter[WPA_REPLAY_COUNTER_LEN];
	int req_replay_counter_used;

	/* 下面几个字段在wpa_validate_wpa_ie中保存 */

	/* 记录STA的IE信息 */
	u8 *wpa_ie;
	size_t wpa_ie_len;

	enum {
		WPA_VERSION_NO_WPA = 0 /* WPA not used */,
		WPA_VERSION_WPA = 1 /* WPA / IEEE 802.11i/D3.0 */,
		WPA_VERSION_WPA2 = 2 /* WPA2 / IEEE 802.11i */
	} wpa;
	int pairwise; /* Pairwise cipher suite, WPA_CIPHER_* */
	/* WPA_KEY_MGMT_IEEE8021X WPA_KEY_MGMT_PSK */
	int wpa_key_mgmt; /* the selected WPA_KEY_MGMT_* */
	struct rsn_pmksa_cache_entry *pmksa;

	u32 dot11RSNAStatsTKIPLocalMICFailures;
	u32 dot11RSNAStatsTKIPRemoteMICFailures;

#ifdef CONFIG_IEEE80211R
	u8 xxkey[PMK_LEN]; /* PSK or the second 256 bits of MSK */
	size_t xxkey_len;
	u8 pmk_r1_name[WPA_PMK_NAME_LEN]; /* PMKR1Name derived from FT Auth
					   * Request */
	u8 r0kh_id[FT_R0KH_ID_MAX_LEN]; /* R0KH-ID from FT Auth Request */
	size_t r0kh_id_len;
	u8 sup_pmk_r1_name[WPA_PMK_NAME_LEN]; /* PMKR1Name from EAPOL-Key
					       * message 2/4 */
	u8 *assoc_resp_ftie;
#endif /* CONFIG_IEEE80211R */

	int pending_1_of_4_timeout;
};


/* per group key state machine data */
struct wpa_group {
	struct wpa_group *next;
	int vlan_id;

	/* GInit - This variable is used to initialize the group key state machine.
	This is a group variable. */
	Boolean GInit;
	/* GKeyDoneStations - Count of number of STAs left to have their GTK updated.
	This is a global variable. */
	int GKeyDoneStations;
	/* GTKReKey - This variable is set to TRUE when a Group Key Handshake is required.
	This is a global variable. */
	/* wpa_rekey_gtk中置为TRUE
	   表示更新gtk，然后向所有STA下发新密钥
	*/
	Boolean GTKReKey;
	/* 函数wpa_group_set_key_len()设置 */
	int GTK_len;
	/* GN, GM - These are the current key indices for GTKs.
	Swap(GM, GN) means that the global key index in GN is swapped with
	the global key index in GM, so now GM and GN are reversed. */
	/* 初始值 GN = 1, GM = 2 */
	int GN, GM;
	/* GTKAuthenticator - This variable is set to TRUE
	if the Authenticator is on an AP
	or it is the designated Authenticator for an IBSS. */
	Boolean GTKAuthenticator;
	/* Counter - This variable is the global STA key counter.
	在wpa_group_init_gmk_and_counter中初始化 */
	u8 Counter[WPA_NONCE_LEN];

	enum {
		WPA_GROUP_GTK_INIT = 0,
		WPA_GROUP_SETKEYS, WPA_GROUP_SETKEYSDONE
	} wpa_group_state;

	/* GMK - This variable is the buffer holding the current GMK.
	一个定时更新的可用来导出GTK的值
	在wpa_group_init_gmk_and_counter中初始化 */
	u8 GMK[WPA_GMK_LEN];
	/* GTK - This variable is the current GTKs for each GTK index. */
	u8 GTK[2][WPA_GTK_MAX_LEN];
	u8 GNonce[WPA_NONCE_LEN];
	Boolean changed;
	Boolean first_sta_seen;
	Boolean reject_4way_hs_for_entropy;
#ifdef CONFIG_IEEE80211W
	u8 IGTK[2][WPA_IGTK_LEN];
	/* 初始值 GN_igtk = 4, GM_igtk = 5 */
	int GN_igtk, GM_igtk;
#endif /* CONFIG_IEEE80211W */
};


struct wpa_ft_pmk_cache;

/* per authenticator data */
struct wpa_authenticator {
	struct wpa_group *group;

	unsigned int dot11RSNAStatsTKIPRemoteMICFailures;
	u32 dot11RSNAAuthenticationSuiteSelected;
	u32 dot11RSNAPairwiseCipherSelected;
	u32 dot11RSNAGroupCipherSelected;
	u8 dot11RSNAPMKIDUsed[PMKID_LEN];
	u32 dot11RSNAAuthenticationSuiteRequested; /* FIX: update */
	u32 dot11RSNAPairwiseCipherRequested; /* FIX: update */
	u32 dot11RSNAGroupCipherRequested; /* FIX: update */
	unsigned int dot11RSNATKIPCounterMeasuresInvoked;
	unsigned int dot11RSNA4WayHandshakeFailures;

	struct wpa_stsl_negotiation *stsl_negotiations;

	struct wpa_auth_config conf;
	struct wpa_auth_callbacks cb;

	/* wpa_init => wpa_auth_gen_wpa_ie */
	u8 *wpa_ie;
	size_t wpa_ie_len;

	/* 认证点的MAC，比如VAP的MAC(bssid) */
	u8 addr[ETH_ALEN];

	/* hostapd_setup_wpa => wpa_init => pmksa_cache_auth_init */
	struct rsn_pmksa_cache *pmksa;
	struct wpa_ft_pmk_cache *ft_pmk_cache;
};


int wpa_write_rsn_ie(struct wpa_auth_config *conf, u8 *buf, size_t len,
		     const u8 *pmkid);
void wpa_auth_logger(struct wpa_authenticator *wpa_auth, const u8 *addr,
		     logger_level level, const char *txt);
void wpa_auth_vlogger(struct wpa_authenticator *wpa_auth, const u8 *addr,
		      logger_level level, const char *fmt, ...);
void __wpa_send_eapol(struct wpa_authenticator *wpa_auth,
		      struct wpa_state_machine *sm, int key_info,
		      const u8 *key_rsc, const u8 *nonce,
		      const u8 *kde, size_t kde_len,
		      int keyidx, int encr, int force_version);
int wpa_auth_for_each_sta(struct wpa_authenticator *wpa_auth,
			  int (*cb)(struct wpa_state_machine *sm, void *ctx),
			  void *cb_ctx);
int wpa_auth_for_each_auth(struct wpa_authenticator *wpa_auth,
			   int (*cb)(struct wpa_authenticator *a, void *ctx),
			   void *cb_ctx);

#ifdef CONFIG_PEERKEY
int wpa_stsl_remove(struct wpa_authenticator *wpa_auth,
		    struct wpa_stsl_negotiation *neg);
void wpa_smk_error(struct wpa_authenticator *wpa_auth,
		   struct wpa_state_machine *sm, struct wpa_eapol_key *key);
void wpa_smk_m1(struct wpa_authenticator *wpa_auth,
		struct wpa_state_machine *sm, struct wpa_eapol_key *key);
void wpa_smk_m3(struct wpa_authenticator *wpa_auth,
		struct wpa_state_machine *sm, struct wpa_eapol_key *key);
#endif /* CONFIG_PEERKEY */

#ifdef CONFIG_IEEE80211R
int wpa_write_mdie(struct wpa_auth_config *conf, u8 *buf, size_t len);
int wpa_write_ftie(struct wpa_auth_config *conf, const u8 *r0kh_id,
		   size_t r0kh_id_len,
		   const u8 *anonce, const u8 *snonce,
		   u8 *buf, size_t len, const u8 *subelem,
		   size_t subelem_len);
int wpa_auth_derive_ptk_ft(struct wpa_state_machine *sm, const u8 *pmk,
			   struct wpa_ptk *ptk, size_t ptk_len);
struct wpa_ft_pmk_cache * wpa_ft_pmk_cache_init(void);
void wpa_ft_pmk_cache_deinit(struct wpa_ft_pmk_cache *cache);
void wpa_ft_install_ptk(struct wpa_state_machine *sm);
#endif /* CONFIG_IEEE80211R */

#endif /* WPA_AUTH_I_H */
