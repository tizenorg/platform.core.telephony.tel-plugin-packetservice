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
#include "generated-code.h"

#include <server.h>
#include <plugin.h>
#include <core_object.h>

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL
#define BOOL2STRING(a)		((a==TRUE) ? ("TRUE"):("FALSE"))

static void __ps_modem_emit_property_changed_signal(PsModem *modem);
static void __ps_modem_emit_service_added_signal(PsModem *modem, gpointer service);
/* static void __ps_modem_emit_service_removed_signal(PsModem *modem, gpointer service); */
static void _ps_modem_setup_interface(PacketServiceModem *modem, PsModem *modem_data);

static void __ps_modem_create_service(GDBusConnection *conn,
	TcorePlugin *p, gpointer modem, CoreObject *co_modem);
static void __ps_modem_remove_service(PsModem *modem, gpointer service);
static void __ps_modem_get_ps_setting_from_storage(PsModem *object);
static void __ps_modem_processing_modem_event(gpointer object);

static gboolean __ps_modem_set_powered(PsModem *modem, gboolean value);
static gboolean __ps_modem_set_sim_complete(PsModem *modem,
	gboolean value, gchar *operator);

void __remove_modem_handler(gpointer data)
{
	PsModem *modem = data;

	dbg("Entered");
	if (!modem) {
		dbg("Modem is NULL");
		return;
	}

	/* Need to remove the compelete hash table */
	g_hash_table_remove_all(modem->services);

	/* Need to UNexport and Unref the master Object */
	g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(modem->if_obj));

	g_object_unref(modem->if_obj);

	/* Need to free memory allocated for the internal structure */
	g_free(modem->path);
	g_free(modem->operator);
	g_free(modem);

	dbg("Exiting");
}

static void __ps_modem_emit_property_changed_signal(PsModem *modem)
{
	GVariant *gv = NULL;
	GVariantBuilder properties;

	dbg("get modem properties");

	gv = _ps_modem_get_properties(modem, &properties);
	packet_service_modem_emit_property_changed(modem->if_obj, gv);
}

static void __ps_modem_emit_service_added_signal(PsModem *modem, gpointer service)
{
	GVariant *gv = NULL;
	GVariantBuilder property;

	dbg("get service properties");

	gv = _ps_service_get_properties(service, &property);
	packet_service_modem_emit_service_added(modem->if_obj, gv);
}

/*  blocked may be used later
static void __ps_modem_emit_service_removed_signal(PsModem *modem, gpointer service)
{
	PsService *psservice = service;
	packet_service_modem_emit_service_removed(modem->if_obj,psservice->path);
	return;
}
*/

static void __ps_modem_create_service(GDBusConnection *conn,
	TcorePlugin *p, gpointer modem, CoreObject *co_modem)
{
	gchar *t_path = NULL;
	GObject *object = NULL;

	CoreObject *co_ps = NULL;
	CoreObject *co_network = NULL;
	TcorePlugin *target_plg = NULL;

	target_plg = tcore_object_ref_plugin(co_modem);

	co_ps = tcore_plugin_ref_core_object(target_plg, CORE_OBJECT_TYPE_PS);

	co_network = tcore_plugin_ref_core_object(target_plg, CORE_OBJECT_TYPE_NETWORK);

	if (!co_ps || !co_network) {
		err("Either ps or network core object not Present");
		return;
	}

	t_path = g_strdup_printf("%s_ps", _ps_modem_ref_path(modem));
	dbg("service path (%s)", t_path);

	/*  Create service object */
	object = _ps_service_create_service(conn,p, modem, co_network, co_ps, t_path);

	g_hash_table_insert( ((PsModem *) modem)->services, g_strdup(t_path), object);
	dbg("service (%p) insert to hash", object);

	/*  Emit signal for service added  */
	__ps_modem_emit_service_added_signal((PsModem *) modem, object);

	g_free(t_path);
}

static void __ps_modem_remove_service(PsModem *modem, gpointer service)
{
	PsService *psservice = service;

	dbg("Entered");

	/* Unexporting the interface for the modem */
	if (psservice->if_obj) {
		g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(psservice->if_obj));
		g_object_unref(psservice->if_obj);
		psservice->if_obj = NULL;
	}

	g_hash_table_remove(modem->services, _ps_service_ref_path(service));

	dbg("Successfully removed the service from the modem");
}

static gboolean __ps_modem_set_powered(PsModem *modem, gboolean value)
{
	tcore_check_return_value(modem != NULL, FALSE);

	modem->powered = value;

	dbg("modem(%p) powered(%d)", modem, modem->powered);
	__ps_modem_emit_property_changed_signal(modem);

	return TRUE;
}

static gboolean __ps_modem_set_sim_complete(PsModem *modem, gboolean value, gchar *operator)
{
	tcore_check_return_value(modem != NULL, FALSE);

	modem->sim_init = value;
	if (value && operator != NULL && !modem->operator)
		modem->operator = g_strdup(operator);

	dbg("modem(%p) sim init(%d) operator(%s)", modem, modem->sim_init, modem->operator);
	__ps_modem_emit_property_changed_signal(modem);

	return TRUE;
}

static gboolean __ps_modem_set_flght_mode(PsModem *modem, gboolean value)
{
	tcore_check_return_value(modem != NULL, FALSE);

	modem->flight_mode = value;

	dbg("modem(%p) flight_mode(%d)", modem, modem->flight_mode);
	__ps_modem_emit_property_changed_signal(modem);
	__ps_modem_processing_modem_event(modem);

	return TRUE;
}

static void __ps_modem_get_ps_setting_from_storage(PsModem *object)
{
	gboolean key_3g_enable = FALSE, key_roaming_allowed = FALSE;
	PsModem *modem = NULL;

	modem = (PsModem *) object;
	key_3g_enable = _ps_master_get_storage_value_bool(modem->p_master, STORAGE_KEY_DATA_ENABLE);
	key_roaming_allowed = _ps_master_get_storage_value_bool(modem->p_master, STORAGE_KEY_SVC_ROAM);

	_ps_modem_set_data_allowed(modem, key_3g_enable);

	_ps_modem_set_data_roaming_allowed(modem, key_roaming_allowed);

	dbg("data allowed(%d) roaming allowed(%d) ", key_3g_enable, key_roaming_allowed);
}

static void __ps_modem_processing_modem_event(gpointer object)
{
	PsModem * modem = object;
	GHashTableIter iter;
	gpointer key, value;

	g_return_if_fail(modem != NULL);

	if (!modem->services) {
		err("Null Service");
		return;
	}

	g_hash_table_iter_init(&iter, modem->services);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gboolean s_roaming = FALSE;

		s_roaming = _ps_service_get_roaming(value);
		_ps_update_cellular_state_key(value);

		if (!modem->powered) {
			_ps_service_remove_contexts(value);
			_ps_free_co_ps_event(value);
			_ps_free_co_network_event(value);
			__ps_modem_remove_service(modem, value);
			continue;
		}

		if (modem->flight_mode || !modem->data_allowed || (s_roaming && !modem->roaming_allowed)) {
			_ps_service_disconnect_contexts(value);
			continue;
		}

		//only available case
		_ps_service_connect_default_context(value);
	}
}

gpointer _ps_modem_create_modem(GDBusConnection *conn,
	TcorePlugin *p, gpointer master, gchar* modem_name, gpointer co_modem)
{
	PacketServiceModem *modem;
	PsModem *new_modem;
	GError *error = NULL;

	dbg("modem object create");
	tcore_check_return_value(conn != NULL, NULL);
	tcore_check_return_value(master != NULL, NULL);

	/* creating the master object for the interface com.tcore.ps.modem */
	modem = packet_service_modem_skeleton_new();

	/* Initializing the modem list for internal referencing */
	new_modem = g_try_malloc0(sizeof(PsModem));
	if (NULL == new_modem) {
		err("Unable to allocate memory for modem");
		return NULL;
	}

	new_modem->conn = conn;
	new_modem->p_master = master;
	new_modem->plg = p;
	new_modem->co_modem = co_modem;
	new_modem->path = g_strdup(modem_name);
	new_modem->if_obj = modem;
	new_modem->services =
		g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, __remove_service_handler);

	dbg("core object of modem %p", co_modem);

	dbg("core object of modem %p", new_modem->co_modem);
	__ps_modem_get_ps_setting_from_storage(new_modem);
	_ps_hook_co_modem_event(new_modem);
	_ps_get_co_modem_values(new_modem);

	/* Setting the interface call backs functions */
	_ps_modem_setup_interface(modem, new_modem);

	/* exporting the interface object to the path mention for modem */
	g_dbus_interface_skeleton_export((G_DBUS_INTERFACE_SKELETON(modem)),
			conn, modem_name, &error);
	g_assert_no_error (error);

	dbg("Successfully created the modem");
	return new_modem;
}

gboolean _ps_modem_processing_flight_mode(gpointer object, gboolean enable)
{
	PsModem * modem = object;

	tcore_check_return_value(modem != NULL, FALSE);

	if (modem->flight_mode == enable)
		return TRUE;

	__ps_modem_set_flght_mode(modem, enable);

	return TRUE;
}

gboolean _ps_modem_processing_power_enable(gpointer object, gboolean enable)
{
	PsModem * modem = object;

	tcore_check_return_value(modem != NULL, FALSE);

	if (modem->powered == enable)
		return TRUE;

	__ps_modem_set_powered(modem, enable);
	if (enable) {
		__ps_modem_create_service(modem->conn,
			modem->plg, modem, modem->co_modem);

		if (modem->sim_init == TRUE && modem->operator != NULL) {
			GHashTable *contexts = NULL;
			contexts = _ps_context_ref_hashtable();

			if (contexts != NULL) {
				GHashTableIter iter;
				gpointer key, value;
				g_hash_table_iter_init(&iter, modem->services);

				while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
					_ps_service_ref_contexts(value, contexts, modem->operator);
				}
			}
		}
	}
	else {
		__ps_modem_processing_modem_event(modem);
		_ps_modem_set_sim_enabled(modem, FALSE);
	}

	return TRUE;
}

gboolean _ps_modem_processing_sim_complete(gpointer object,
	gboolean complete, gchar *operator)
{
	PsModem * modem = object;
	GHashTable *contexts = NULL;

	tcore_check_return_value(modem != NULL, FALSE);
	dbg("Entered");
	if (modem->sim_init == complete)
		return TRUE;

	__ps_modem_set_sim_complete(modem, complete, operator);
	if (modem->sim_init == TRUE && modem->operator != NULL) {
		contexts = _ps_context_create_hashtable(modem->conn,
			modem->plg, modem->operator);
		dbg("Hash table created");
	}

	if (contexts != NULL) {
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, modem->services);
		dbg("context not null as created the hash");
		while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
			//_ps_service_set_number_of_pdn_cnt(value, modem->operator);
			_ps_service_ref_contexts(value, contexts, modem->operator);
		}
	}

	dbg("Exiting");
	return TRUE;
}

gboolean _ps_modem_set_sim_enabled(gpointer object, gboolean value)
{
	PsModem * modem = object;

	tcore_check_return_value(modem != NULL, FALSE);

	modem->sim_init = value;
	dbg("modem(%p) sim_enabled(%d)", modem, modem->sim_init);
	return TRUE;
}

gboolean _ps_modem_set_data_allowed(gpointer object, gboolean value)
{
	PsModem * modem = object;

	tcore_check_return_value(modem != NULL, FALSE);

	modem->data_allowed = value;
	dbg("modem(%p) data allowed(%d)", modem, modem->data_allowed);
	__ps_modem_emit_property_changed_signal(modem);
	__ps_modem_processing_modem_event(modem);

	return TRUE;
}

gboolean _ps_modem_get_data_allowed(gpointer object)
{
	PsModem * modem = object;
	tcore_check_return_value(modem != NULL, FALSE);

	return modem->data_allowed;
}

gboolean _ps_modem_set_data_roaming_allowed(gpointer object,
	gboolean roaming_allowed)
{
	PsModem * modem = object;

	tcore_check_return_value(modem != NULL, FALSE);

	modem->roaming_allowed = roaming_allowed;
	dbg("modem(%p) roaming allowed(%d)", modem, modem->roaming_allowed);
	__ps_modem_emit_property_changed_signal(modem);

	if (!modem->services)
		return TRUE;

	if (modem->roaming)
		__ps_modem_processing_modem_event(modem);

	return TRUE;
}

gboolean _ps_modem_get_roaming(gpointer object)
{
	PsModem * modem = object;
	tcore_check_return_value(modem != NULL, FALSE);

	return modem->roaming;
}

void _ps_modem_set_roaming(gpointer object, gboolean value)
{
	PsModem * modem = object;
	g_return_if_fail(modem != NULL);

	modem->roaming = value;
	dbg("modem(%p) roaming(%d)", modem, modem->roaming);

	return;
}

gboolean _ps_modem_get_data_roaming_allowed(gpointer object)
{
	PsModem * modem = object;
	tcore_check_return_value(modem != NULL, FALSE);

	return modem->roaming_allowed;
}

gboolean _ps_modem_get_flght_mode(gpointer object)
{
	PsModem * modem = object;
	tcore_check_return_value(modem != NULL, FALSE);

	return modem->flight_mode;
}

gboolean _ps_modem_get_sim_init(gpointer object)
{
	PsModem * modem = object;
	tcore_check_return_value(modem != NULL, FALSE);

	return modem->sim_init;
}

gboolean _ps_modem_get_power(gpointer object)
{
	PsModem * modem = object;
	tcore_check_return_value(modem != NULL, FALSE);

	return modem->powered;
}

gchar* _ps_modem_ref_operator(gpointer object)
{
	PsModem * modem = object;
	tcore_check_return_value(modem != NULL, FALSE);

	return modem->operator;
}

gboolean _ps_modem_get_properties_handler(gpointer object,
	GVariantBuilder *properties)
{
	PsModem *modem = object;

	dbg("get modem properties");
	tcore_check_return_value(modem != NULL, FALSE);
	tcore_check_return_value(properties != NULL, FALSE);

	g_variant_builder_open(properties,G_VARIANT_TYPE("a{ss}"));
	g_variant_builder_add(properties, "{ss}", "path", g_strdup(modem->path));

	if (modem->operator) {
		g_variant_builder_add(properties, "{ss}", "operator", g_strdup(modem->operator));
	}
	g_variant_builder_add(properties, "{ss}", "powered", g_strdup(BOOL2STRING(modem->powered)));
	g_variant_builder_add(properties, "{ss}", "sim_init", g_strdup(BOOL2STRING(modem->sim_init)));
	g_variant_builder_add(properties, "{ss}", "flight_mode", g_strdup(BOOL2STRING(modem->flight_mode)));
	g_variant_builder_add(properties, "{ss}", "roaming_allowed", g_strdup(BOOL2STRING(modem->roaming_allowed)));
	g_variant_builder_add(properties, "{ss}", "data_allowed", g_strdup(BOOL2STRING(modem->data_allowed)));
	g_variant_builder_close(properties);

	dbg("Exiting");
	return TRUE;
}

GVariant *_ps_modem_get_properties(gpointer object, GVariantBuilder *properties)
{
	PsModem *modem = object;

	dbg("get modem properties");
	tcore_check_return_value(modem != NULL, FALSE);
	tcore_check_return_value(properties != NULL, FALSE);

	g_variant_builder_init(properties, G_VARIANT_TYPE("a{ss}"));

	g_variant_builder_add(properties, "{ss}", "path", g_strdup(modem->path));

	if (modem->operator) {
		g_variant_builder_add(properties, "{ss}", "operator", g_strdup(modem->operator));
	}
	g_variant_builder_add(properties, "{ss}", "powered", g_strdup(BOOL2STRING(modem->powered)));
	g_variant_builder_add(properties, "{ss}", "sim_init", g_strdup(BOOL2STRING(modem->sim_init)));
	g_variant_builder_add(properties, "{ss}", "flight_mode", g_strdup(BOOL2STRING(modem->flight_mode)));
	g_variant_builder_add(properties, "{ss}", "roaming_allowed", g_strdup(BOOL2STRING(modem->roaming_allowed)));
	g_variant_builder_add(properties, "{ss}", "data_allowed", g_strdup(BOOL2STRING(modem->data_allowed)));

	dbg("Path: [%s]", modem->path);
	dbg("Operator: [%s]", modem->operator);
	dbg("Powered: [%s]", modem->powered ? "YES" : "NO");
	dbg("SIM Init: [%s]", modem->sim_init ? "YES" : "NO");
	dbg("Flight mode: [%s]", modem->flight_mode ? "ON" : "OFF");
	dbg("Roaming allowed: [%s]", modem->roaming_allowed ? "YES" : "NO");
	dbg("Data allowed: [%s]", modem->data_allowed ? "YES" : "NO");

	return g_variant_builder_end(properties);
}

GHashTable* _ps_modem_ref_services(gpointer object)
{
	PsModem *modem = object;
	tcore_check_return_value(modem != NULL, NULL);

	return modem->services;
}

gchar* _ps_modem_ref_path(gpointer object)
{
	PsModem *modem = object;
	tcore_check_return_value(modem != NULL, NULL);

	return modem->path;
}

gpointer _ps_modem_ref_plugin(gpointer object)
{
	PsModem *modem = object;
	tcore_check_return_value(modem != NULL, NULL);

	return modem->plg;
}

gpointer _ps_modem_ref_dbusconn(gpointer object)
{
	PsModem *modem = object;
	tcore_check_return_value(modem != NULL, NULL);

	return modem->conn;
}

gpointer _ps_modem_ref_co_modem(gpointer object)
{
	PsModem *modem = object;
	tcore_check_return_value(modem != NULL, NULL);

	return modem->co_modem;
}

static gboolean on_modem_get_properties (PacketServiceModem *obj_modem,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	GVariant *gv = NULL;
	GVariantBuilder properties;

	dbg("get modem properties");

	gv = _ps_modem_get_properties(user_data, &properties);
	packet_service_modem_complete_get_properties(obj_modem, invocation, gv);
	return TRUE;
}

static gboolean on_modem_get_services (PacketServiceModem *obj_modem,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	GVariantBuilder b_service;
	GVariant *services;

	GHashTableIter iter;
	gpointer key, value;
	PsModem *modem = user_data;

	dbg("modem get service interface");

	if (modem->services == NULL) {
		FAIL_RESPONSE(invocation,PS_ERR_INTERNAL);
		return TRUE;
	}

	g_variant_builder_init(&b_service, G_VARIANT_TYPE("a{sa{ss}}"));
	g_hash_table_iter_init(&iter,modem->services);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *path = NULL;

		g_variant_builder_open(&b_service,G_VARIANT_TYPE("{sa{ss}}"));
		path = _ps_service_ref_path(value);
		dbg("path added [%s]", path);
		g_variant_builder_add(&b_service, "s", g_strdup(path));
		if (FALSE == _ps_service_get_properties_handler(value, &b_service)) {
			g_variant_builder_close(&b_service);
			FAIL_RESPONSE(invocation,PS_ERR_INTERNAL);
			return TRUE;
		}
		g_variant_builder_close(&b_service);
	}

	services = g_variant_builder_end(&b_service);
	packet_service_modem_complete_get_services(obj_modem, invocation, services);
	return TRUE;
}

static void _ps_modem_setup_interface(PacketServiceModem *modem,
	PsModem *modem_data)
{
	dbg("Entered");

	g_signal_connect (modem,
		"handle-get-properties",
		G_CALLBACK (on_modem_get_properties),
		modem_data);

	g_signal_connect (modem,
		"handle-get-services",
		G_CALLBACK (on_modem_get_services),
		modem_data);
}
