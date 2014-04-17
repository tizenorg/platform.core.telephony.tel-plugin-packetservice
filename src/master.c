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

#include <unistd.h>

#include "ps.h"
#include "generated-code.h"

#include <server.h>
#include <plugin.h>
#include <storage.h>
#include <hal.h>

#define PS_MASTER_PATH		"/"
#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL
#define BOOL2STRING(a)		((a==TRUE) ? ("TRUE"):("FALSE"))


static void __ps_master_emit_modem_added_signal(PsMaster *master, gpointer modem);
/* static void __ps_master_emit_modem_removed_signal(PsMaster *master, gpointer modem); */
static void _ps_master_setup_interface(PacketServiceMaster *master, PsMaster *master_data);

static void __ps_master_register_key_callback(gpointer master, TcoreStorageKey key);
static void __ps_master_storage_key_callback(TcoreStorageKey key, void *value, void *user_data);

#if 0
static void __ps_master_handle_contexts(gchar *request)
{
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *contexts = NULL;

	dbg("send dbus %s requeset", request);

	contexts = _ps_context_ref_hashtable();
	if (contexts == NULL) {
		err("no profiles");
		return;
	}

	g_hash_table_iter_init(&iter, contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *s_path = NULL;

		s_path = _ps_context_ref_path(value);
		dbg("key(%s), value(%p), path(%s)", (gchar *)key, value, s_path);
		if (!g_strcmp0(request, "InterfaceDown")) {
			_ps_context_handle_ifacedown(value);
		} else if (!g_strcmp0(request, "InterfaceUp")) {
			_ps_context_handle_ifaceup(value);
		}
	}
	return;
}
#endif

void __remove_master(gpointer data, gpointer user_data)
{
	PsMaster *master = data;

	dbg("Entered");

	/* Need to remove the compelete hash table */
	g_hash_table_remove_all(master->modems);

	/* Need to UNexport and Unref the master Object */
	g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(master->if_obj));

	g_object_unref(master->if_obj);

	/* Need to free the memory allocated for the members of the master */
	g_free(master->path);
	g_free(master);

	dbg("Exiting");
	return;
}

static void __ps_master_emit_modem_added_signal(PsMaster *master, gpointer modem)
{
	GVariant *gv = NULL;
	GVariantBuilder properties;

	dbg("get modem properties");

	gv = _ps_modem_get_properties(modem, &properties);
	packet_service_master_emit_modem_added(master->if_obj,gv);

	dbg("Exiting");
	return;
}

/*
static void __ps_master_emit_modem_removed_signal(PsMaster *master, gpointer modem)
{
	g_signal_emit(master, signals[SIG_MASTER_MODEM_REMOVED], 0, _ps_modem_ref_path(modem));
	dbg("master (%p) emit the modem(%p) removed signal", master, modem);
	return;
}
*/

static void __ps_master_register_key_callback(gpointer object, TcoreStorageKey key)
{
	PsMaster *master = (PsMaster *) object;
	Server *s = tcore_plugin_ref_server(master->plg);
	TcoreStorage *strg = NULL;

	strg = tcore_server_find_storage(s, "vconf");
	tcore_storage_set_key_callback(strg, key, __ps_master_storage_key_callback, object);

	return;
}

static void __ps_master_storage_key_callback(TcoreStorageKey key, void *value, void *user_data)
{
	GVariant *tmp = NULL;
	GHashTableIter iter;
	gpointer h_key, h_value;
	gboolean type_check = FALSE;
	PsMaster *master = (PsMaster *)user_data;

	dbg("storage key(%d) callback", key);
	g_return_if_fail(master != NULL);

	tmp = (GVariant *)value;
	if (!tmp) {
		err("value is null");
		return;
	}

	type_check = g_variant_is_of_type(tmp, G_VARIANT_TYPE_BOOLEAN);
	if (!type_check) {
		err("wrong variant data type");
		g_variant_unref(tmp);
		return;
	}

	g_hash_table_iter_init(&iter, master->modems);
	while (g_hash_table_iter_next(&iter, &h_key, &h_value) == TRUE) {
		if(key == STORAGE_KEY_DATA_ENABLE) {
			gboolean data_allowed = g_variant_get_boolean(tmp);
			_ps_modem_set_data_allowed(h_value, data_allowed);
		} else if(key == STORAGE_KEY_SETAPPL_STATE_DATA_ROAMING) {
			gboolean roaming_allowed = g_variant_get_boolean(tmp);
			_ps_modem_set_data_roaming_allowed(h_value, roaming_allowed);
		}
	}

	g_variant_unref(tmp);
	return;
}

gpointer _ps_master_create_master(GDBusConnection *conn, TcorePlugin *p)
{
	PacketServiceMaster *master = NULL;
	PsMaster *new_master = NULL;
	GError *error = NULL;

	dbg("master object create");
	tcore_check_return_value(conn != NULL, NULL);

	/* creating the master object for the interface com.tcore.ps.master */
	master = packet_service_master_skeleton_new();
	tcore_check_return_value(master != NULL, NULL);


	/* Initializing the master list for internal referencing */
	new_master = g_try_malloc0(sizeof(PsMaster));
	if (NULL == new_master) {
		err("Unable to allocate memory for master");
		goto FAILURE;
	}

	new_master->conn = conn;
	new_master->path = g_strdup(PS_MASTER_PATH);
	new_master->plg = p;
	new_master->if_obj = master;
	new_master->modems =
		g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, __remove_modem_handler);

	/* Setting Up the call backs for the interface */
	_ps_master_setup_interface(master, new_master);

	/* exporting the interface object to the path mention for master */
	g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(master),
			conn, PS_MASTER_PATH, &error);
	g_assert_no_error (error);

	/* Registering the key callbacks for values in storage settings */
	__ps_master_register_key_callback(new_master,
		STORAGE_KEY_DATA_ENABLE);
	__ps_master_register_key_callback(new_master,
		STORAGE_KEY_SETAPPL_STATE_DATA_ROAMING);

	/* Adding Hook for modem addition laters */
	tcore_server_add_notification_hook(tcore_plugin_ref_server(p),
		TCORE_SERVER_NOTIFICATION_ADDED_MODEM_PLUGIN,
		__on_hook_modem_added, new_master);

	dbg("Successfully created the master");
	return new_master;

FAILURE:
	err("Unable to create master");
	g_object_unref(master);
	return NULL;
}

gboolean _ps_master_create_modems(gpointer object)
{
	Server *s = NULL;
	GSList *plist = NULL;
	PsMaster *master = NULL;

	TcorePlugin *plugin;
	gchar *modem_name;
	CoreObject *co_modem;
	gpointer modem, modem_node;

	dbg("create modem objects");
	tcore_check_return_value(object != NULL, FALSE);

	master = (PsMaster *)object;
	s = tcore_plugin_ref_server(master->plg);
	plist = tcore_server_get_modem_plugin_list(s);
	for (; plist; plist = plist->next) {
		plugin = plist->data;
		co_modem = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
		if (co_modem == NULL)
			continue;

		dbg("create modem objects %p", co_modem);
		modem_name = g_strdup_printf("/%s",
		tcore_server_get_cp_name_by_plugin(plugin));

		modem_node = g_hash_table_lookup(master->modems, modem_name);
		if (modem_node != NULL) {
			dbg("modem '%s' already exists", modem_name);
			g_free(modem_name);

			continue;
		}

		/*  Create Modem */
		modem = _ps_modem_create_modem(master->conn,
		master->plg, master, modem_name, co_modem);
		if (modem == NULL) {
			err("Failed to Create modem '%s'", modem_name);
			g_free(modem_name);

			return FALSE;
		}

		g_hash_table_insert(master->modems, g_strdup(modem_name), modem);
		dbg("Created modem '%s'", modem_name);

		/*  Emit signal: Modem added */
		__ps_master_emit_modem_added_signal(master, modem);

		g_free(modem_name);
	}

	return TRUE;
}

gboolean _ps_master_get_storage_value_bool(gpointer object, TcoreStorageKey key)
{
	Server *s = NULL;
	TcoreStorage *strg = NULL;
	PsMaster *master = object;

	tcore_check_return_value(master != NULL, FALSE);
	s = tcore_plugin_ref_server(master->plg);
	strg = tcore_server_find_storage(s, "vconf");

	return tcore_storage_get_bool(strg, key);
}

gboolean _ps_master_set_storage_value_bool(gpointer object,TcoreStorageKey key, gboolean value)
{
	Server *s = NULL;
	TcoreStorage *strg = NULL;
	PsMaster *master = object;

	tcore_check_return_value(master != NULL, FALSE);
	s = tcore_plugin_ref_server(master->plg);
	strg = tcore_server_find_storage(s, "vconf");

	return tcore_storage_set_bool(strg, key, value);
}

static gboolean on_master_get_modems (PacketServiceMaster *obj_master,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	GVariantBuilder b_modem;
	GVariant *modems;

	GHashTableIter iter;
	gpointer key, value;
	PsMaster *master = user_data;

	dbg("Entered");
	if (master->modems == NULL) {
		err("No modem Present");
		FAIL_RESPONSE(invocation, PS_ERR_INTERNAL);
		return TRUE;
	}

	g_variant_builder_init(&b_modem,G_VARIANT_TYPE("a{sa{ss}}"));

	g_hash_table_iter_init(&iter, master->modems);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *path = NULL;

		path = _ps_modem_ref_path(value);
		dbg("modem path [%s]",path);

		g_variant_builder_open(&b_modem, G_VARIANT_TYPE("{sa{ss}}"));
		g_variant_builder_add(&b_modem, "s", g_strdup(path));
		if (FALSE == _ps_modem_get_properties_handler(value, &b_modem)) {
			err("Unable to get the modem properties");
			g_variant_builder_close(&b_modem);
			FAIL_RESPONSE(invocation, PS_ERR_INTERNAL);
			return TRUE;
		}
		g_variant_builder_close(&b_modem);
	}
	modems = g_variant_builder_end(&b_modem);

	packet_service_master_complete_get_modems(obj_master, invocation, modems);
	return TRUE;
}

static gboolean on_master_get_profile_list (PacketServiceMaster *obj_master,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	int index = 0;
	GHashTableIter iter;
	gpointer key, value;

	guint len =0;
	gchar **strv = NULL;
	GHashTable *contexts = NULL;
	GSList *profiles = NULL;

	dbg("master get the profile list");

	contexts = _ps_context_ref_hashtable();
	if (contexts == NULL) {
		err("no profiles");
		FAIL_RESPONSE(invocation, PS_ERR_NO_PROFILE);
		return TRUE;
	}

	g_hash_table_iter_init(&iter, contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *s_path = NULL;

		s_path = _ps_context_ref_path(value);
		dbg("key(%s), value(%p), path(%s)", (gchar *)key, value, s_path);
		if (s_path)
			profiles = g_slist_append(profiles, g_strdup((const gchar*)s_path));
	}

	if (profiles == NULL) {
		err("no profiles");
		FAIL_RESPONSE(invocation, PS_ERR_NO_PROFILE);
		return TRUE;
	}

	len = g_slist_length(profiles);
	strv = g_new(gchar *, len+1);

	while (profiles) {
		strv[index] = g_strdup(profiles->data);
		index++;

		profiles = profiles->next;
	}
	strv[index] = NULL;

	packet_service_master_complete_get_profile_list(obj_master,
				invocation,(const gchar *const *)strv);

	g_strfreev(strv);
	profiles = g_slist_nth(profiles, 0);
	g_slist_free_full(profiles, g_free);
	return TRUE;
}

static gboolean on_master_add_profile (PacketServiceMaster *obj_master,
	GDBusMethodInvocation *invocation,
	GVariant *property, gpointer user_data)
{
	GVariantIter g_iter;
	gchar *g_value;
	gchar *g_key;

	GHashTableIter iter;
	gpointer key, value;
	gboolean rv = FALSE;
	gchar *operator = NULL;
	PsMaster *master = user_data;
	GHashTable *profile_property =
		g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	dbg("add profile request");

	g_hash_table_iter_init(&iter, master->modems);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		operator = _ps_modem_ref_operator(value);
		if (operator)
			break;
	}

	if (!operator) {
		err("there is no active modem");
		FAIL_RESPONSE(invocation, PS_ERR_INTERNAL);
		return TRUE;
	}

	/* Create a hash table for the profile property as all fucntion already use ghash table */
	g_variant_iter_init (&g_iter, property);
	while (g_variant_iter_next (&g_iter, "{ss}", &g_key, &g_value)) {
		dbg(" '%s' value '%s'", g_key, g_value);

		g_hash_table_insert(profile_property, g_strdup(g_key), g_strdup(g_value));

		/*  must free data for ourselves */
		g_free (g_value);
		g_free (g_key);
	}

	rv = _ps_context_add_context(value, operator, profile_property);
	if (rv != TRUE) {
		err("Failed to add the Profile");
		FAIL_RESPONSE(invocation, PS_ERR_INTERNAL);
		return TRUE;
	}

	packet_service_master_complete_add_profile(obj_master, invocation, TRUE);

	g_hash_table_destroy(profile_property);
	return TRUE;
}

static gboolean on_master_reset_profile (PacketServiceMaster *obj_master,
	GDBusMethodInvocation *invocation,
	gint type, gpointer user_data)
{
	GHashTableIter iter;
	gpointer key, value;
	gboolean rv = FALSE;
	int b_check = 0;
	PsMaster *master = user_data;

	dbg("reset profile request type(%d)", type);

	if (master->modems == NULL) {
		err("modem does not exist");
		FAIL_RESPONSE(invocation,PS_ERR_INTERNAL);
		return TRUE;
	}

	if (type == 0) {
		b_check = access("/opt/system/csc-default/data/csc-default-data-connection.ini", F_OK);
		if (b_check != 0 ) {
			err("csc file was not there");
			FAIL_RESPONSE(invocation,PS_ERR_INTERNAL);
			return TRUE;
		}
	}

	g_hash_table_iter_init(&iter, master->modems);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		err("key(%s), value(%p) context", key, value);
		_ps_modem_processing_power_enable(value, FALSE);
		_ps_modem_set_sim_enabled(value, FALSE);
	}

	dbg("Reseting the hash table");
	_ps_context_reset_hashtable();

	if (type == 0) {
		_ps_context_reset_profile_table();
		rv = _ps_context_fill_profile_table_from_ini_file();
	}

	g_hash_table_iter_init(&iter, master->modems);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		_ps_get_co_modem_values(value);
	}

	if (type == 0 && !rv) {
		err("csc data was wrong");
		FAIL_RESPONSE(invocation, PS_ERR_INTERNAL);
		return TRUE;
	}

	packet_service_master_complete_reset_profile(obj_master, invocation, TRUE);
	return TRUE;
}

static void _ps_master_setup_interface(PacketServiceMaster *master,
	PsMaster *master_data)
{
	dbg("Entered");

	g_signal_connect (master,
		"handle-get-modems",
		G_CALLBACK (on_master_get_modems),
		master_data);

	g_signal_connect (master,
		"handle-get-profile-list",
		G_CALLBACK (on_master_get_profile_list),
		master_data);

	g_signal_connect (master,
		"handle-add-profile",
		G_CALLBACK (on_master_add_profile),
		master_data);

	g_signal_connect (master,
		"handle-reset-profile",
		G_CALLBACK (on_master_reset_profile),
		master_data);
}
