/*
 * tel-plugin-packetservice
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ps.h"

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <storage.h>
#include <co_ps.h>
#include <co_context.h>
#include <co_modem.h>
#include <co_sim.h>
#include <co_network.h>

static TcoreHookReturn __on_hook_call_status(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	gpointer service = user_data;
	TcorePsCallStatusInfo *cstatus = NULL;
	gboolean netif_updown = FALSE;
	gchar *ifname = NULL;
	GSList *contexts;
	CoreObject *co_context;
	CoreObject *co;

	dbg("Call Status event");
	tcore_check_return_value(service != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);
	co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_PS);

	cstatus = (TcorePsCallStatusInfo *)data;
	tcore_check_return_value(cstatus != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	dbg("Context ID: [%d] Call State: [%s]", cstatus->context_id,
		((cstatus->state == TCORE_PS_CALL_STATE_CTX_DEFINED) ? "DEFINED"
		: (cstatus->state == TCORE_PS_CALL_STATE_CONNECTED) ? "CONNECTED"
		: "NOT CONNECTED"));

	if (cstatus->state == TCORE_PS_CALL_STATE_CTX_DEFINED)
		goto out;
	else if (cstatus->state == TCORE_PS_CALL_STATE_CONNECTED)
		netif_updown = TRUE;
	else if (cstatus->state == TCORE_PS_CALL_STATE_NOT_CONNECTED)
		netif_updown = FALSE;

	/* Refer to context */
	tcore_ps_ref_context_by_id(co, cstatus->context_id, &contexts);
	for (; contexts != NULL; contexts = g_slist_next(contexts)) {
		co_context = contexts->data;
		if (co_context == NULL) {
			dbg("Context is NULL");
			continue;
		}

		/* Get Interface name */
		tcore_context_get_ipv4_devname(co_context, &ifname);
		if (ifname == NULL) {
			dbg("Interface name is NULL");
			continue;
		}

		/* Setup network interface */
		if (tcore_util_netif(ifname, netif_updown)
				!= TEL_RETURN_SUCCESS) {
			g_slist_free(contexts);
			err("Failed to setup interface - Interface name: [%s] Interface Status: [%s]",
				ifname, (netif_updown ? "UP" : "DOWN"));
		}
		dbg("Successfully setup interface - Interface name: [%s] Interface Status: [%s]",
			ifname, (netif_updown ? "UP" : "DOWN"));
	}
out:
	//send activation event / deactivation event
	if (cstatus->state == TCORE_PS_CALL_STATE_CTX_DEFINED) {
		/* OK: PDP define is complete. */
		dbg("Service - [READY TO ACTIVATE]");
		_ps_service_set_ps_defined(service, TRUE, cstatus->context_id);
		//_ps_service_connect_default_context(service);
	} else if (cstatus->state == TCORE_PS_CALL_STATE_CONNECTED) {
		/* CONNECTED */
		dbg("Service - [ACTIVATED]");
		_ps_service_set_connected(service, cstatus->context_id, TRUE);
	} else if (cstatus->state == TCORE_PS_CALL_STATE_NOT_CONNECTED) {
		/* NO CARRIER */
		_ps_service_set_ps_defined(service, FALSE, cstatus->context_id);
		_ps_service_set_connected(service, cstatus->context_id, FALSE);
	}
	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_ipconfiguration(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	gpointer service = user_data;
	TcorePsPdpIpConf *devinfo = NULL;

	tcore_check_return_value(service != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	devinfo = (TcorePsPdpIpConf *) data;

	dbg("IP Configuration event");
	_ps_service_set_context_info(service, devinfo);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_powered(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	gpointer modem = user_data;
	TelModemPowerStatus *modem_power = NULL;

	gboolean power = FALSE;

	dbg("Powered event");

	tcore_check_return_value(modem != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	modem_power = (TelModemPowerStatus *)data;
	dbg("Modem Power state: [%s]",
		((*modem_power == TEL_MODEM_POWER_ON) ? "ONLINE"
		: (*modem_power == TEL_MODEM_POWER_OFF) ? "OFFLINE" : "ERROR"));

	if ( *modem_power == TEL_MODEM_POWER_ON )
		power = TRUE;
	else
		power = FALSE;

	/* Process modem Power state */
	_ps_modem_processing_power_enable(modem, power);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_flight(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	gpointer modem = user_data;
	gboolean *flight_mode = NULL;

	dbg("Flight mode event");

	tcore_check_return_value(modem != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	flight_mode = (gboolean *)data;
	dbg("Flight mode: [%s]", (*flight_mode ? "ON" : "OFF"));

	/* Process Flight mode event */
	_ps_modem_processing_flight_mode(modem, *flight_mode);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_net_register(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	gpointer service = user_data;
	gboolean ps_attached = FALSE;
	TelNetworkRegStatusInfo *registration_status;
	gboolean roaming_status = FALSE;

	dbg("network register event called");
	tcore_check_return_value(service != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	registration_status = (TelNetworkRegStatusInfo *)data;
	switch (registration_status->ps_status) {
	case TEL_NETWORK_REG_STATUS_ROAMING:
		roaming_status = TRUE;
	case TEL_NETWORK_REG_STATUS_REGISTERED: /* FALLTHROUGH */
		ps_attached = TRUE;
	break;
	case TEL_NETWORK_REG_STATUS_DENIED: /* FALLTHROUGH */
	case TEL_NETWORK_REG_STATUS_SEARCHING: /* FALLTHROUGH */
	case TEL_NETWORK_REG_STATUS_UNKNOWN: /* FALLTHROUGH */
	case TEL_NETWORK_REG_STATUS_UNREGISTERED: /* FALLTHROUGH */
	default:
		dbg("Network PS Status: [%d]", registration_status->ps_status);
	break;
	}

  	/*
  	 * Roaming status infered from CS Status is also applicable
  	 * if PS Status doesn't communicate the same.
  	 */
	if (!roaming_status
			&& (registration_status->cs_status
			== TEL_NETWORK_REG_STATUS_ROAMING))
		roaming_status = TRUE;

	/* Set Roaming Status */
	_ps_modem_set_roaming(_ps_service_ref_modem(service), roaming_status);

	/* Process Network Registration event */
	_ps_service_processing_network_event(service, ps_attached, roaming_status);

	/* Set AcT */
	dbg("act(%d)", registration_status->act);
	_ps_service_set_access_technology(service, registration_status->act);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_sim_init(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	TelSimCardStatusInfo *sim_data;
	CoreObject *co_sim;


	dbg("sim init event called");
	tcore_check_return_value(user_data != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	co_sim = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);

	sim_data = (TelSimCardStatusInfo *)data;
	dbg("SIM status: [0x%02x]", sim_data->status);

	if( sim_data->status == TEL_SIM_STATUS_SIM_INIT_COMPLETED){
		TelSimImsiInfo *imsi = NULL;
		char plmn[(TEL_SIM_MCC_MNC_LEN_MAX * 2) + 1] = {0,}; //mcc+mnc

		tcore_sim_get_imsi(co_sim, &imsi);
		strncpy(plmn, imsi->mcc,strlen( imsi->mcc));
		strcat(plmn, imsi->mnc);

		_ps_modem_processing_sim_complete((gpointer)user_data, TRUE, plmn);
		g_free(imsi);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

gboolean _ps_hook_co_modem_event(gpointer modem)
{
	CoreObject *co_modem;
	tcore_check_return_value(modem != NULL, FALSE);

	dbg("Hooking modem and sim events");
	co_modem = _ps_modem_ref_co_modem(modem);

	tcore_plugin_add_notification_hook(tcore_object_ref_plugin(co_modem),
		TCORE_NOTIFICATION_MODEM_POWER, __on_hook_powered, modem);
	tcore_plugin_add_notification_hook(tcore_object_ref_plugin(co_modem),
		TCORE_NOTIFICATION_MODEM_FLIGHT_MODE, __on_hook_flight, modem);
	tcore_plugin_add_notification_hook(tcore_object_ref_plugin(co_modem),
		TCORE_NOTIFICATION_SIM_STATUS, __on_hook_sim_init, modem);

	return TRUE;
}

gboolean _ps_get_co_modem_values(gpointer modem)
{
	TcorePlugin *plg;
	CoreObject *co_modem = NULL;
	CoreObject *co_sim = NULL;

	gboolean sim_init = FALSE, modem_powered = FALSE, flight_mode = FALSE;
	TelSimCardStatus sim_status;
	TelSimImsiInfo *sim_imsi = NULL;
	gchar plmn[(TEL_SIM_MCC_MNC_LEN_MAX * 2) + 1] = {0,}; //mcc+mnc

	tcore_check_return_value(modem != NULL, FALSE);

	co_modem = _ps_modem_ref_co_modem(modem);
	if (!co_modem){
		err("invalid PsModem ");
		return FALSE;
	}

	plg = tcore_object_ref_plugin(co_modem);
	if (!plg){
		err("invalid plugin");
		return FALSE;
	}

	co_sim = tcore_plugin_ref_core_object(plg, CORE_OBJECT_TYPE_SIM);
	if (!co_sim) {
		err("invalid co sim");
		return FALSE;
	}

	/* SIM State */
	tcore_sim_get_status(co_sim, &sim_status);
	if(sim_status == TEL_SIM_STATUS_SIM_INIT_COMPLETED){
		sim_init = TRUE;

		/*
		 * If sim is intialized then only fetch modem state
		 */
		tcore_modem_get_powered(co_modem, &modem_powered);
	}

	/* IMSI */
	tcore_sim_get_imsi(co_sim, &sim_imsi);
	strncpy(plmn, sim_imsi->mcc, strlen( sim_imsi->mcc));
	strcat(plmn, sim_imsi->mnc);

	/* Flight mode */
	tcore_modem_get_flight_mode_state(co_modem, &flight_mode);

	dbg("SIM init: [%s], Modem powered: [%s], Flight mode: [%s]",
		sim_init ? "YES" : "NO",
		modem_powered ? "YES" : "ON",
		flight_mode ? "ON" : "OFF");

	/* Set Flight mode */
	_ps_modem_processing_flight_mode(modem, flight_mode);

	/* Set Power power */
	_ps_modem_processing_power_enable(modem, modem_powered);

	/* Process SIM state */
	_ps_modem_processing_sim_complete(modem, sim_init, plmn);

	g_free(sim_imsi);
	return TRUE;
}

gboolean _ps_hook_co_network_event(gpointer service)
{
	CoreObject *co_network;
	tcore_check_return_value(service != NULL, FALSE);


	dbg("Hook for network event");
	co_network = _ps_service_ref_co_network(service);

	tcore_plugin_add_notification_hook(tcore_object_ref_plugin(co_network),
		TCORE_NOTIFICATION_NETWORK_REGISTRATION_STATUS,
		__on_hook_net_register, service);

	return TRUE;
}

gboolean _ps_get_co_network_values(gpointer service)
{
	CoreObject *co_network = NULL;
	gboolean ps_attached = FALSE;
	gboolean roam ;

	TelNetworkRegStatus ps_status;
	TelNetworkAct act;

	tcore_check_return_value(service != NULL, FALSE);

	co_network = _ps_service_ref_co_network(service);

	tcore_network_get_ps_reg_status(co_network, &ps_status);
	tcore_network_get_access_technology(co_network, &act);
	tcore_network_get_roam_state(co_network, &roam);

	if (ps_status == TEL_NETWORK_REG_STATUS_REGISTERED)
		ps_attached = TRUE;

	_ps_service_set_roaming(service, roam );
	_ps_service_set_ps_attached(service, ps_attached);
	_ps_service_set_access_technology(service, act);

	return TRUE;
}

gboolean _ps_hook_co_ps_event(gpointer service)
{
	CoreObject *co_ps;
	tcore_check_return_value(service != NULL, FALSE);

	co_ps = _ps_service_ref_co_ps(service);

	tcore_plugin_add_notification_hook(tcore_object_ref_plugin(co_ps),
		TCORE_NOTIFICATION_PS_CALL_STATUS,
		__on_hook_call_status, service);

	tcore_plugin_add_notification_hook(tcore_object_ref_plugin(co_ps),
		TCORE_NOTIFICATION_PS_IPCONFIG,
		__on_hook_ipconfiguration, service);

	return TRUE;
}

gboolean _ps_free_co_ps_event(gpointer service)
{
	CoreObject *co_ps;
	tcore_check_return_value(service != NULL, FALSE);

	co_ps = _ps_service_ref_co_ps(service);

	tcore_plugin_remove_notification_hook(tcore_object_ref_plugin(co_ps),
		TCORE_NOTIFICATION_PS_CALL_STATUS,
		__on_hook_call_status);

	tcore_plugin_remove_notification_hook(tcore_object_ref_plugin(co_ps),
		TCORE_NOTIFICATION_PS_IPCONFIG,
		__on_hook_ipconfiguration);

	return TRUE;
}

gboolean _ps_free_co_network_event(gpointer service)
{
	CoreObject *co_network;
	tcore_check_return_value(service != NULL, FALSE);

	co_network = _ps_service_ref_co_network(service);

	tcore_plugin_remove_notification_hook(tcore_object_ref_plugin(co_network),
		TCORE_NOTIFICATION_NETWORK_REGISTRATION_STATUS,
		__on_hook_net_register);

	return TRUE;
}

gboolean _ps_update_cellular_state_key(gpointer service)
{
	Server *s = NULL;
	TcoreStorage *strg;
	TcorePsState cur_cell_state;
	gint stored_cell_state = 0;

	s = tcore_plugin_ref_server((TcorePlugin *)_ps_service_ref_plugin(service));
	strg = tcore_server_find_storage(s, "vconf");

	cur_cell_state = _ps_service_check_cellular_state(service);
	stored_cell_state = tcore_storage_get_int(strg, STORAGE_KEY_CELLULAR_STATE);

	dbg("cellular state, current (%d), cur_cell_state (%d)", stored_cell_state, cur_cell_state);

	if (stored_cell_state != (gint)cur_cell_state)
		tcore_storage_set_int(strg, STORAGE_KEY_CELLULAR_STATE, cur_cell_state);

	return TRUE;
}
