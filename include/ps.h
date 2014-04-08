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
#ifndef __PS_H__
#define __PS_H__

#define PS_DBUS_SERVICE	"com.tcore.ps"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <gio/gio.h>

#include <tcore.h>
#include <plugin.h>
#include <storage.h>
#include <server.h>
#include <core_object.h>
#include <type/ps.h>
#include <hal.h>

#include "generated-code.h"

#define FAIL_RESPONSE(ivc,msg) g_dbus_method_invocation_return_error (ivc, \
		G_DBUS_ERROR, G_DBUS_ERROR_FAILED, msg);


#define PS_NO_PENDING_REQUEST 0x00

#define PS_NETWORK_SEARCH_PENDING 0x01
#define PS_RESET_NETWORK_SEARCH_FLAG 0x0E

#define PS_NETWORK_SELECTION_PENDING 0x02
#define PS_NETWORK_RESET_SELECTION_FLAG 0x0D

#define PS_NETWORK_SELECT_MODE 0x04
#define PS_NETWORK_RESET_SELECT_MODE_FLAG 0x0B

#define PS_NETWORK_GET_MODE 0x08
#define PS_NETWORK_RESET_GET_MODE_FLAG 0x07

/*Storage Key value*/
#define KEY_3G_ENABLE				STORAGE_KEY_3G_ENABLE
#define KEY_DATA_ROAMING_SETTING	STORAGE_KEY_SETAPPL_STATE_DATA_ROAMING_BOOL
#define KEY_DATA_ROAMING_APP_SETTING	STORAGE_KEY_SETAPPL_STATE_DATA_ROAMING_APP_STATUS
#define KEY_POWER_SAVING_MODE		STORAGE_KEY_POWER_SAVING_MODE
#define KEY_PM_STATE 				STORAGE_KEY_PM_STATE
#define KEY_NETWORK_RESTRICT_MODE   STORAGE_KEY_SETAPPL_NETWORK_RESTRICT_MODE

#define PS_ERR_INTERNAL "Internal Error"
#define PS_ERR_NO_SERVICE "NO service"
#define PS_ERR_TRASPORT "No Transport"
#define PS_ERR_NO_PROFILE "No Profile"
#define PS_ERR_WRONG_PROFILE "Wrong Profile"
#define PS_ERR_MAX "Unknown Error"

/* Tizen Power saving mode */
#define POWER_SAVING_MODE_NORMAL   0
#define POWER_SAVING_MODE_ECO	   1
#define POWER_SAVING_MODE_ECO_PLUS 2
#define POWER_SAVING_MODE_SURVIVAL 3

typedef struct {
	gchar *path;
	TcorePlugin *plg;
	GDBusConnection *conn;
	PacketServiceMaster *if_obj;
	GHashTable *modems;
} PsMaster;

typedef struct {
	gchar* path;
	gpointer p_master;
	TcorePlugin *plg;
	CoreObject *co_modem;
	GDBusConnection *conn;
	PacketServiceModem *if_obj;

	/*Value from modem*/
	gchar* operator;
	gboolean powered;
	gboolean sim_init;
	gboolean flight_mode;

	gboolean roaming_allowed;
	gboolean roaming;

	gboolean data_allowed;
	GHashTable *services;
}PsModem;

typedef struct {
	gchar *path;
	TcorePlugin *plg;
	GDBusConnection *conn;
	PacketServiceService *if_obj;

	gpointer p_modem;
	CoreObject *co_network;
	CoreObject *co_ps;

	gboolean ps_attached;
	gboolean roaming;
	gboolean restricted;
	TelNetworkAct act;

	GHashTable *contexts;
} PsService;

typedef struct {
	gchar* path;
	gchar* mccmnc;
	GDBusConnection *conn;
	PacketServiceContext *if_obj;
	TcorePlugin *plg;

	gboolean alwayson;
	gboolean default_internet;
	gboolean hidden;
	gboolean editable;
	gboolean ps_defined;
	gboolean b_active;
	gpointer p_service;
	gint profile_id;
	CoreObject *co_context;

	gpointer async_context;
	gpointer user_data;
} PsContext;

typedef struct {
	GDBusConnection *conn;
	guint bus_id;
	TcorePlugin *p;
	GSList *master;
} PsCustom;


void _packet_service_cleanup();
TcoreHookReturn __on_hook_modem_added(Server *server,
        TcoreServerNotification command, guint data_len, void *data,
        void *user_data);

/*MASTER*/
void 		__remove_master(gpointer master, gpointer user_data);
gpointer    _ps_master_create_master(GDBusConnection *conn, TcorePlugin *p);
gboolean    _ps_master_create_modems(gpointer master);
gboolean    _ps_master_get_storage_value_bool(gpointer master, TcoreStorageKey key);
gboolean    _ps_master_get_storage_value_int(gpointer master, TcoreStorageKey key);
gboolean    _ps_master_set_storage_value_bool(gpointer master, TcoreStorageKey key, gboolean value);
gboolean    _ps_master_set_storage_value_int(gpointer master, TcoreStorageKey key, gint value);

/*MODEM*/
void 		__remove_modem_handler(gpointer modem);
gpointer    _ps_modem_create_modem(GDBusConnection *conn, TcorePlugin *p, gpointer master,
				gchar* modem_name, gpointer co_modem);
gboolean    _ps_modem_processing_flight_mode(gpointer object, gboolean enable);
gboolean    _ps_modem_processing_power_enable(gpointer modem, gboolean enable);
gboolean    _ps_modem_processing_sim_complete(gpointer modem, gboolean complete, gchar *operator);
gboolean    _ps_modem_set_sim_enabled(gpointer object, gboolean value);
gboolean    _ps_modem_set_data_allowed(gpointer modem, gboolean value);
gboolean    _ps_modem_get_data_allowed(gpointer modem);
gboolean    _ps_modem_set_data_roaming_allowed(gpointer modem, gboolean value);
gboolean    _ps_modem_get_data_roaming_allowed(gpointer modem);
gboolean    _ps_modem_get_roaming(gpointer object);
void        _ps_modem_set_roaming(gpointer object, gboolean value);
gboolean    _ps_modem_set_psmode(gpointer modem, gint value);
gboolean    _ps_modem_get_psmode(gpointer modem);
gboolean    _ps_modem_get_flght_mode(gpointer object);
gboolean    _ps_modem_get_sim_init(gpointer object);
gboolean    _ps_modem_get_power(gpointer object);
gchar*      _ps_modem_ref_operator(gpointer object);
gboolean	_ps_modem_get_properties_handler(gpointer object, GVariantBuilder * properties);
GVariant*	_ps_modem_get_properties(gpointer object, GVariantBuilder *properties);
GHashTable* _ps_modem_ref_services(gpointer modem);
gchar*      _ps_modem_ref_path(gpointer modem);
gpointer    _ps_modem_ref_plugin(gpointer modem);
gpointer    _ps_modem_ref_dbusconn(gpointer modem);
gpointer    _ps_modem_ref_co_modem(gpointer modem);
gpointer	_ps_modem_ref_work_queue(gpointer modem);

/*SERVICE*/
void 		__remove_service_handler(gpointer service);
gpointer    _ps_service_create_service(GDBusConnection *conn, TcorePlugin *p,
				gpointer modem, CoreObject *co_network, CoreObject *co_ps, gchar* path);
gboolean    _ps_service_ref_context(gpointer object, gpointer context);
gboolean    _ps_service_ref_contexts(gpointer service, GHashTable *contexts, gchar *operator);
gboolean    _ps_service_unref_context(gpointer service, gpointer context);
gboolean	_ps_service_get_properties_handler(gpointer object, GVariantBuilder *properties);
GVariant*	_ps_service_get_properties(gpointer object, GVariantBuilder *properties);
gchar*      _ps_service_ref_path(gpointer service);
gpointer    _ps_service_ref_plugin(gpointer service);
gpointer    _ps_service_ref_co_network(gpointer service);
gpointer    _ps_service_ref_co_ps(gpointer service);
gpointer    _ps_service_ref_modem(gpointer object);
gboolean    _ps_service_set_context_info(gpointer service,  TcorePsPdpIpConf *devinfo);
gint 		_ps_service_define_context(gpointer object, gpointer context);
gint         _ps_service_activate_context(gpointer service, gpointer context);
gint	    _ps_service_deactivate_context(gpointer service, gpointer context);
void        _ps_service_set_retry_timeout_value(int value);
void        _ps_service_connection_timer(gpointer service, gpointer context);
void        _ps_service_reset_connection_timer(gpointer context);
int         _ps_service_connect_default_context(gpointer service);
void        _ps_service_remove_contexts(gpointer object);
void        _ps_service_disconnect_contexts(gpointer service);
gboolean    _ps_service_processing_network_event(gpointer service, gboolean ps_attached, gboolean roaming);
gpointer    _ps_service_return_default_context(gpointer object);
gboolean    _ps_service_set_connected(gpointer service, gint context_id, gboolean enabled);
void		_ps_service_set_ps_defined(gpointer *object, gboolean value, gint cid);
gboolean    _ps_service_set_ps_attached(gpointer service, gboolean value);
//gboolean    _ps_service_set_number_of_pdn_cnt(gpointer object, gchar *operator);
gboolean    _ps_service_set_roaming(gpointer service, gboolean value);
gboolean    _ps_service_get_roaming(gpointer object);
gboolean    _ps_service_set_restricted(gpointer object, gboolean value);
gboolean    _ps_service_get_restricted(gpointer object);
gboolean    _ps_service_set_access_technology(gpointer service,
				TelNetworkAct value);
TcorePsState _ps_service_check_cellular_state(gpointer object);

/*CONTEXT*/
void 		__remove_context_handler(gpointer context);
gboolean    _ps_context_initialize(gpointer plugin);
gboolean    _ps_context_reset_profile_table(void);
gboolean    _ps_context_fill_profile_table_from_ini_file(void);
gboolean    _ps_context_reset_hashtable(void);
GHashTable* _ps_context_create_hashtable(GDBusConnection *conn, TcorePlugin *p, gchar *mccmnc);
GHashTable* _ps_context_ref_hashtable(void);
gboolean    _ps_context_add_context(gpointer modem, gchar *operator, GHashTable *property);
gboolean	_ps_context_get_properties_handler(gpointer context, GVariantBuilder *properties);
GVariant*	_ps_context_get_properties(gpointer context, GVariantBuilder *properties);
gboolean    _ps_context_set_service(gpointer context, gpointer service);
gpointer    _ps_context_ref_service(gpointer object);
gboolean    _ps_context_get_alwayson_enable(gpointer object);
gchar*      _ps_context_ref_path(gpointer context);
gpointer    _ps_context_ref_co_context(gpointer context);
gboolean    _ps_context_set_connected(gpointer context, gboolean enabled);
gboolean 	_ps_context_set_ps_defined(gpointer *object, gboolean value, gint cid);
gboolean 	_ps_context_get_ps_defined(gpointer *object);
gboolean    _ps_context_set_alwayson_enable(gpointer object, gboolean enabled);
gboolean    _ps_context_get_default_internet(gpointer object);
gboolean    _ps_context_remove_context(gpointer context);
gboolean    _ps_context_reset_user_data(gpointer object);
gpointer    _ps_context_get_user_data(gpointer object);
TelReturn     _ps_connection_hdlr(gpointer object);
void        _ps_default_connection_hdlr(gpointer object);
gint        _ps_context_get_number_of_pdn(gchar *operator);
gboolean 	_ps_context_handle_ifaceup(gpointer user_data);
gboolean 	_ps_context_handle_ifacedown(gpointer user_data);


/*PLUGIN INTERFACE*/
gboolean    _ps_hook_co_modem_event(gpointer modem);
gboolean    _ps_get_co_modem_values(gpointer modem);
gboolean    _ps_hook_co_network_event(gpointer service);
gboolean    _ps_free_co_network_event(gpointer service);
gboolean    _ps_get_co_network_values(gpointer service);
gboolean    _ps_hook_co_ps_event(gpointer service);
gboolean    _ps_free_co_ps_event(gpointer service);
gboolean    _ps_update_cellular_state_key(gpointer service);

#endif /* __PS_H__ */
