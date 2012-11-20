/*
 * IEEE 802.1X-2004 Authenticator - EAPOL state machine (internal definitions)
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
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

#ifndef EAPOL_AUTH_SM_I_H
#define EAPOL_AUTH_SM_I_H

#include "common/defs.h"
#include "radius/radius.h"

/* IEEE Std 802.1X-2004, Ch. 8.2 */

typedef enum { ForceUnauthorized = 1, ForceAuthorized = 3, Auto = 2 }
	PortTypes;
typedef enum { Unauthorized = 2, Authorized = 1 } PortState;
typedef enum { Both = 0, In = 1 } ControlledDirection;
typedef unsigned int Counter;


/**
 * struct eapol_authenticator - Global EAPOL authenticator data
 */
struct eapol_authenticator {
	struct eapol_auth_config conf;
	/* ieee802_1x_init => eapol_auth_init中设置回调函数 */
	struct eapol_auth_cb cb;

	u8 *default_wep_key;
	u8 default_wep_key_idx;
};


/**
 * struct eapol_state_machine - Per-Supplicant Authenticator state machines
 */
struct eapol_state_machine {
	/* 变量说明来自IEEE Std 802.1X-2004,8.2.2 */
	/* timers */
	/* aWhile - A timer used by the Backend Authentication state machine
	in order to determine timeout conditions in the exchanges between the Authenticator and EAP.
	The initial value of this timer is serverTimeout. */
	int aWhile;
	/* quietWhile - A timer used by the Authenticator state machine
	to define periods of time during which it will not attempt to acquire a Supplicant.
	The initial value of this timer is quietPeriod. */
	int quietWhile;
	/* reAuthWhen - A timer used by the Reauthentication Timer state machine
	to determine when reauthentication of the Supplicant takes place.
	The initial value of this timer is reAuthPeriod. */
	int reAuthWhen;

	/* global variables */
	/* authAbort - This variable is set TRUE by the Authenticator PAE state machine
	in order to signal to the Backend Authentication state machine
	to abort its authentication procedure.
	Its value is set FALSE by the Backend Authentication state machine
	once the authentication procedure has been aborted. */
	Boolean authAbort;
	/* authFail - This variable is set TRUE
	if the authentication process (represented by the Backend Authentication state machine) fails.
	It is set FALSE by the operation of the Authenticator PAE state machine,
	prior to initiating authentication. */
	Boolean authFail;
	/* authPortStatus - The current authorization state of the Authenticator PAE state machine.
	This variable is set to Unauthorized or Authorized by the operation of the state machine.
	If the Authenticator PAE state machine is not implemented,
	then this variable has the value Authorized. */
	PortState authPortStatus;
	/* authStart - This variable is set TRUE by the Authenticator PAE state machine
	in order to signal to the Backend Authentication state machine
	to start its authentication procedure.
	Its value is set FALSE by the Backend Authentication state machine
	once the authentication procedure has been started. */
	Boolean authStart;
	/* authTimeout - This variable is set TRUE if the authentication process
	(represented by the Backend Authentication state machine)
	fails to obtain a response from the Supplicant.
	The variable may be set by management action, or by the operation of a timeout
	while in the AUTHENTICATED state.
	This variable is set FALSE by the operation of the Authenticator PAE state machine. */
	Boolean authTimeout;
	/* authSuccess - This variable is set TRUE if the authentication process
	(represented by the Backend Authentication state machine) succeeds.
	It is set FALSE by the operation of the Authenticator PAE state machine,
	prior to initiating authentication. */
	Boolean authSuccess;
	/* eapolEap - This variable is set TRUE by an external entity
	if an EAPOL PDU carrying a Packet Type of EAP-Packet is received. */
	Boolean eapolEap;
	/* initialize - This variable is externally controlled.
	When asserted, it forces all EAPOL state machines to their initial state.
	The PACP state machines are held in their initial state
	until initialize is deasserted. */
	Boolean initialize;
	/* keyDone - This variable is set TRUE by the key machine
	when it is in a state that portValid can be tested. */
	Boolean keyDone;
	/* keyRun - This variable is set TRUE by the PACP machine
	when the transmit key machine should run.
	It is set FALSE by a PAE to indicate the PAE state machine has been reset
	and the key machine should abort. */
	Boolean keyRun;
	/* keyTxEnabled - Reflects the current value of the KeyTransmissionEnabled parameter. */
	Boolean keyTxEnabled;
	/* portControl -
	1. ForceUnauthorized. The controlled Port is required to be held in the Unauthorized state.
	2. ForceAuthorized. The controlled Port is required to be held in the Authorized state.
	3. Auto. The controlled Port is set to the Authorized or Unauthorized state in accordance with the
		outcome of an authentication exchange between the Supplicant and the Authentication Server.
	*/
	PortTypes portControl;
	Boolean portValid;
	/* reAuthenticate - */
	Boolean reAuthenticate;

	/* Port Timers state machine */
	/* 'Boolean tick' implicitly handled as registered timeout */

	/* Authenticator PAE state machine */
	enum { AUTH_PAE_INITIALIZE, AUTH_PAE_DISCONNECTED, AUTH_PAE_CONNECTING,
	       AUTH_PAE_AUTHENTICATING, AUTH_PAE_AUTHENTICATED,
	       AUTH_PAE_ABORTING, AUTH_PAE_HELD, AUTH_PAE_FORCE_AUTH,
	       AUTH_PAE_FORCE_UNAUTH, AUTH_PAE_RESTART } auth_pae_state;
	/* variables */
	/* eapolLogoff - This variable is set TRUE if an EAPOL PDU carrying
	a Packet Type of EAPOL-Logoff is received.
	It is set FALSE by the operation of the Authenticator PAE state machine. */
	Boolean eapolLogoff;
	/* eapolStart - This variable is set TRUE if an EAPOL PDU carrying
	a Packet Type of EAPOL-Start is received.
	It is set FALSE by the operation of the Authenticator PAE state machine. */
	Boolean eapolStart;
	/* portMode - Used in conjunction with authPortControl to switch between
	the Auto and non-Auto modes of operation of the Authenticator PAE state machine.
	This variable can take the following values:
	1. ForceUnauthorized.
	2. ForceAuthorized.
	3. Auto.
	*/
	PortTypes portMode;
	/* reAuthCount - This variable counts the number of times the CONNECTING state is re-entered.
	If the count exceeds reAuthMax, it forces the Port to become Unauthorized
	before further attempts to authenticate can be made. */
	unsigned int reAuthCount;
	/* constants */
	unsigned int quietPeriod; /* default 60; 0..65535 */
#define AUTH_PAE_DEFAULT_quietPeriod 60
	unsigned int reAuthMax; /* default 2 */
#define AUTH_PAE_DEFAULT_reAuthMax 2
	/* counters */
	Counter authEntersConnecting;
	Counter authEapLogoffsWhileConnecting;
	Counter authEntersAuthenticating;
	Counter authAuthSuccessesWhileAuthenticating;
	Counter authAuthTimeoutsWhileAuthenticating;
	Counter authAuthFailWhileAuthenticating;
	Counter authAuthEapStartsWhileAuthenticating;
	Counter authAuthEapLogoffWhileAuthenticating;
	Counter authAuthReauthsWhileAuthenticated;
	Counter authAuthEapStartsWhileAuthenticated;
	Counter authAuthEapLogoffWhileAuthenticated;

	/* Backend Authentication state machine */
	enum { BE_AUTH_REQUEST, BE_AUTH_RESPONSE, BE_AUTH_SUCCESS,
	       BE_AUTH_FAIL, BE_AUTH_TIMEOUT, BE_AUTH_IDLE, BE_AUTH_INITIALIZE,
	       BE_AUTH_IGNORE
	} be_auth_state;
	/* constants */
	unsigned int serverTimeout; /* default 30; 1..X */
#define BE_AUTH_DEFAULT_serverTimeout 30
	/* counters */
	Counter backendResponses;
	Counter backendAccessChallenges;
	Counter backendOtherRequestsToSupplicant;
	Counter backendAuthSuccesses;
	Counter backendAuthFails;

	/* Reauthentication Timer state machine */
	enum { REAUTH_TIMER_INITIALIZE, REAUTH_TIMER_REAUTHENTICATE
	} reauth_timer_state;
	/* constants */
	unsigned int reAuthPeriod; /* default 3600 s */
	Boolean reAuthEnabled;

	/* Authenticator Key Transmit state machine */
	enum { AUTH_KEY_TX_NO_KEY_TRANSMIT, AUTH_KEY_TX_KEY_TRANSMIT
	} auth_key_tx_state;

	/* Key Receive state machine */
	enum { KEY_RX_NO_KEY_RECEIVE, KEY_RX_KEY_RECEIVE } key_rx_state;
	/* variables */
	Boolean rxKey;

	/* Controlled Directions state machine */
	enum { CTRL_DIR_FORCE_BOTH, CTRL_DIR_IN_OR_BOTH } ctrl_dir_state;
	/* variables */
	ControlledDirection adminControlledDirections;
	ControlledDirection operControlledDirections;
	Boolean operEdge;

	/* Authenticator Statistics Table */
	Counter dot1xAuthEapolFramesRx;
	Counter dot1xAuthEapolFramesTx;
	Counter dot1xAuthEapolStartFramesRx;
	Counter dot1xAuthEapolLogoffFramesRx;
	Counter dot1xAuthEapolRespIdFramesRx;
	Counter dot1xAuthEapolRespFramesRx;
	Counter dot1xAuthEapolReqIdFramesTx;
	Counter dot1xAuthEapolReqFramesTx;
	Counter dot1xAuthInvalidEapolFramesRx;
	Counter dot1xAuthEapLengthErrorFramesRx;
	Counter dot1xAuthLastEapolFrameVersion;

	/* Other variables - not defined in IEEE 802.1X */
	u8 addr[ETH_ALEN]; /* Supplicant address */
	int flags; /* EAPOL_SM_* */

	/* EAPOL/AAA <-> EAP full authenticator interface */
	struct eap_eapol_interface *eap_if;

	int radius_identifier;
	/* TODO: check when the last messages can be released */
	struct radius_msg *last_recv_radius;
	u8 last_eap_id; /* last used EAP Identifier */
	u8 *identity;
	size_t identity_len;
	u8 eap_type_authsrv; /* EAP type of the last EAP packet from
			      * Authentication server */
	u8 eap_type_supp; /* EAP type of the last EAP packet from Supplicant */
	struct radius_class_data radius_class;

	/* Keys for encrypting and signing EAPOL-Key frames */
	u8 *eapol_key_sign;
	size_t eapol_key_sign_len;
	u8 *eapol_key_crypt;
	size_t eapol_key_crypt_len;

	/* eapol_auth_alloc => eap_server_sm_init */
	struct eap_sm *eap;

	Boolean initializing; /* in process of initializing state machines */
	Boolean changed;

	/* 指向hostapd_data中的eapol_auth */
	struct eapol_authenticator *eapol;

	/* struct sta_info */
	void *sta; /* station context pointer to use in callbacks */
};

#endif /* EAPOL_AUTH_SM_I_H */
