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
#include <tcore.h>
#include <plugin.h>
#include <server.h>
#include <storage.h>
#include <core_object.h>
#include <co_ps.h>
#include <co_context.h>

#include <iniparser.h>
#include <tzplatform_config.h>

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL
#define BOOL2STRING(a)		((a == TRUE) ? ("TRUE"):("FALSE"))
#define DELAY_TO_SIGNAL_EMIT	1

static TcoreStorage *strg_db;
static gpointer handle;
static GHashTable *contexts;

static void __ps_context_emit_property_changed_signal(PsContext *context);
static void _ps_context_setup_interface(PacketServiceContext *context, PsContext *context_data);

static gboolean __remove_contexts(gpointer key, gpointer value, gpointer user_data);
static gboolean __ps_context_remove_context(gpointer context);
static gboolean __ps_context_create_storage_handle(gpointer plugin);
static gboolean __ps_context_create_context_hash(void);
static gchar *__ps_context_create_path(char *profile_name, gint profile_id, gint svc_ctg_id);
static gboolean __ps_context_create_co_context(gpointer context, GHashTable *property);
static gboolean __ps_context_update_profile(PsContext *context, GHashTable *property);
static gboolean __ps_context_update_database(PsContext *context);
static gboolean __ps_context_update_default_internet_to_db(PsContext *context, gboolean enabled);
static gboolean __ps_context_remove_database(PsContext *context);
static gint __ps_context_insert_network_id_to_database(gchar *mccmnc);
static gint __ps_context_load_network_id_from_database(gchar *mccmnc);
static gchar *__ps_context_load_network_name_from_database(gint network_id);
static gint __ps_context_load_profile_id_from_database(void);
static gint __ps_context_load_num_of_pdn_from_database(gchar *mccmnc);
static gboolean __ps_context_insert_profile_tuple(dictionary *dic, gint index);
static gint __ps_context_insert_profile_to_database(GHashTable *property, gint network_id);
static gint __ps_context_get_network_id(gchar *mccmnc);
GVariant *__ps_context_get_profile_properties(gpointer context, GVariantBuilder *properties);
static gboolean __ps_context_set_default_connection_enable(gpointer object, gboolean enabled);

void __remove_context_handler(gpointer data)
{
	PsContext *context = data;

	dbg("Entered");

	if (!context) {
		dbg("Context is Null");
		return;
	}

	/*Need to UNexport and Unref the master Object */
	g_object_unref(context->if_obj);

	dbg("context removed for the path [%s]", context->path);

	g_free(context->path);
	g_free(context->mccmnc);
	g_free(context);
}

static void __ps_context_emit_property_changed_signal(PsContext *context)
{
	GVariant *gv = NULL;
	GVariantBuilder property;

	dbg("Get context Properties");
	gv = _ps_context_get_properties(context,  &property);

	dbg("Emit property changed signal - context [%p]", context);
	packet_service_context_emit_property_changed(context->if_obj, gv);
}

static gboolean __remove_contexts(gpointer key, gpointer value, gpointer user_data)
{
	gchar *context_path = (gchar *)key;

	dbg("Removing context [%s]", context_path);
	__ps_context_remove_context(value);

	return TRUE;
}

static gboolean __ps_context_remove_context(gpointer context)
{
	PsContext *pscontext = context;

	dbg("Remove context [%p] and profile", pscontext);
	_ps_service_reset_connection_timer(pscontext);

	/* Remove interface */
	g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(pscontext->if_obj));

	_ps_context_set_alwayson_enable(pscontext, FALSE);
	_ps_service_deactivate_context(pscontext->p_service, pscontext);
	_ps_context_set_connected(pscontext, FALSE);
	_ps_service_unref_context(pscontext->p_service, pscontext);

	tcore_context_free(pscontext->co_context);

	return TRUE;
}

static gboolean __ps_context_create_storage_handle(gpointer plugin)
{
	Server *s = tcore_plugin_ref_server((TcorePlugin *)plugin);
	const char *path = NULL;
	strg_db = tcore_server_find_storage(s, "database");
	path = tzplatform_mkpath(TZ_SYS_DB,".dnet.db");

	handle = tcore_storage_create_handle(strg_db, path);
	if (!handle) {
		err("fail to create database handle");
		return FALSE;
	}

	dbg("storage(%p) handle (%p)", strg_db, handle);
	return TRUE;
}

static gboolean __ps_context_create_context_hash()
{
	tcore_check_return_value(contexts == NULL, FALSE);

	contexts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, __remove_context_handler);
	if (contexts == NULL) {
		err("fail to create context hashtable");
		return FALSE;
	}

	dbg("context hashtable(%p)", contexts);
	return TRUE;
}

static gchar* __ps_context_create_path(gchar *profile_name, gint profile_id, gint svc_ctg_id)
{
	gchar *path = NULL, *in_path = NULL;
	int str_len = 0, index = 0;

	if (!profile_name) {
		dbg("profile_name is null");
		return NULL;
	}

	str_len = strlen(profile_name);
	in_path = g_strdup("/context/");

	for (index = 0; index < str_len; index++ ) {
		gchar *buf = NULL, *tmp = NULL;
		buf = g_strdup_printf("%02x", profile_name[index]);
		tmp = g_strconcat(in_path, buf, NULL);

		g_free(buf);
		g_free(in_path);

		in_path = g_strdup(tmp);
		g_free(tmp);
	}

	dbg("converted name(%s) path(%s)", profile_name, in_path);

	path = g_strdup_printf("%s_%d_%d", in_path, profile_id, svc_ctg_id);
	dbg("path (%s)", path);

	g_free(in_path);
	return path;
}

static gboolean __ps_context_create_co_context(gpointer object, GHashTable *property)
{
	GHashTableIter iter;
	gpointer key, value;
	PsContext *context = NULL;
	CoreObject *co_context = NULL;

	gchar *path = NULL;
	gint profile_id = 0;
	gchar *profile_name = NULL;
	gchar *apn = NULL;
	gchar *auth_id = NULL, *auth_pwd = NULL, *home_url = NULL, *proxy_addr = NULL;
	gint auth_type = 0, svc_ctg_id = 0;
	gboolean hidden = FALSE, editable = FALSE, default_conn = FALSE;

	g_hash_table_iter_init(&iter, (GHashTable *) property);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		if (g_str_equal(key, "3") == TRUE) { /*Profile ID*/
			profile_id = atoi((const gchar*) value);
			dbg("profile id (%d)", profile_id);
		} else if (g_str_equal(key, "4") == TRUE) {
			profile_name = g_strdup((const gchar*) value);
			dbg("profile name (%s)", profile_name);
		} else if (g_str_equal(key, "5") == TRUE) {
			apn = g_strdup((const gchar*) value);
			dbg("APN (%s)", apn);
		} else if (g_str_equal(key, "6") == TRUE) {
			auth_type = atoi((const gchar*) value);
			dbg("auth type (%d)", auth_type);
		} else if (g_str_equal(key, "7") == TRUE) {
			auth_id = g_strdup((const gchar*) value);
			dbg("auth id (%s)", auth_id);
		} else if (g_str_equal(key, "8") == TRUE) {
			auth_pwd = g_strdup((const gchar*) value);
			dbg("auth pwd (%s)", auth_pwd);
		} else if (g_str_equal(key, "9") == TRUE) {

			if (!value || g_strcmp0((const gchar*) value, "") == 0 ) {
				proxy_addr = g_strdup((const gchar*) value);
			}
			else {
				gboolean b_regex = FALSE;
				b_regex = g_regex_match_simple("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]*", (const gchar*) value, 0, 0);

				if (b_regex) {
					int port_num = 0;
					gchar **tmp_proxy = NULL;

					tmp_proxy = g_strsplit_set((const gchar*) value, ".:", -1);
					port_num = atoi(tmp_proxy[4]);

					if (port_num <= 0) {
						proxy_addr = g_strdup_printf("%d.%d.%d.%d",
							atoi(tmp_proxy[0]), atoi(tmp_proxy[1]), atoi(tmp_proxy[2]), atoi(tmp_proxy[3]));
					}
					else {
						proxy_addr = g_strdup_printf("%d.%d.%d.%d:%d",
							atoi(tmp_proxy[0]), atoi(tmp_proxy[1]), atoi(tmp_proxy[2]), atoi(tmp_proxy[3]), port_num);
					}
					g_strfreev(tmp_proxy);
				}
				else {
					proxy_addr = g_strdup((const gchar*) value);
				}//not in regular experssion
			}

			dbg("proxy addr (%s)", proxy_addr);
		} else if (g_str_equal(key, "10") == TRUE) {
			home_url = g_strdup((const gchar*) value);
			dbg("home url (%s)", home_url);
		} else if (g_str_equal(key, "19") == TRUE) {
			svc_ctg_id = atoi((const gchar*) value);
			dbg("context category type (%d)", svc_ctg_id);
		} else if (g_str_equal(key, "20") == TRUE) {
			hidden = atoi((const gchar*) value);
			dbg("hidden profile (%d)", hidden);
		} else if (g_str_equal(key, "21") == TRUE) {
			editable = atoi((const gchar*) value);
			dbg("editable profile (%d)", editable);
		} else if (g_str_equal(key, "22") == TRUE) {
			default_conn = atoi((const gchar*) value);
			dbg("default connection profile (%d)", default_conn);
		}
	}

	path = __ps_context_create_path(profile_name, profile_id, svc_ctg_id);

	context = (PsContext *) object;
	co_context = tcore_context_new(context->plg, NULL);
	tcore_context_set_state(co_context, TCORE_CONTEXT_STATE_DEACTIVATED);
	tcore_context_set_role(co_context, svc_ctg_id);
	tcore_context_set_apn(co_context, apn);
	tcore_context_set_auth(co_context, auth_type);
	tcore_context_set_username(co_context, auth_id);
	tcore_context_set_password(co_context, auth_pwd);
	tcore_context_set_proxy(co_context, proxy_addr);
	tcore_context_set_mmsurl(co_context, home_url);
	tcore_context_set_profile_name(co_context, profile_name);

	context->profile_id = profile_id;
	context->hidden = hidden;
	context->editable = editable;
	context->default_internet = default_conn;
	context->path = g_strdup(path);
	context->co_context = co_context;

	g_free(path);
	g_free(apn);
	g_free(auth_pwd);
	g_free(proxy_addr);
	g_free(home_url);
	g_free(profile_name);
	return TRUE;
}

static gpointer __ps_context_create_context(GDBusConnection *conn, TcorePlugin *p,
		gchar *mccmnc, GHashTable *property)
{
	PacketServiceContext *context;
	GError *error = NULL;
	PsContext *new_context;
	gchar *path = NULL;

	dbg("Entered");

	/*Initializing the master list for internal referencing*/
	new_context = g_try_malloc0(sizeof(PsContext));
	if (NULL == new_context) {
		err("Unable to allocate memory for context");
		goto FAILURE;
	}
	dbg("creating the skeleton object");
	context = packet_service_context_skeleton_new();
	if (NULL == context)
		goto FAILURE;

	dbg("Assigning the memory location for the internal data");
	new_context->conn = conn;
	new_context->plg = p;
	new_context->if_obj = context;

	__ps_context_create_co_context(new_context, property);
	_ps_context_set_alwayson_enable(new_context, TRUE);
	path = _ps_context_ref_path(new_context);
	_ps_context_setup_interface(context,new_context);

	dbg("registering the interface object");

	dbg("exporting the interface object to the dbus connection");
	/*exporting the interface object to the path mention for master*/
	g_dbus_interface_skeleton_export((G_DBUS_INTERFACE_SKELETON(context)),
			conn,
			path,
			&error);

	g_assert_no_error (error);

	dbg("Successfully new object created for the interface for path [%s]",path);
	return new_context;

FAILURE:
	/*To do : handle failure */
	dbg("Unable to allocate memory for the new object");
	return NULL;
}

static gboolean __ps_context_update_profile(PsContext *context, GHashTable *property)
{
	CoreObject *co_context = NULL;
	GHashTableIter iter;
	gpointer key, value;

	co_context = context->co_context;
	if (!co_context)
		return FALSE;

	g_hash_table_iter_init(&iter, property);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		if (g_str_equal(key, "apn") == TRUE) {
			tcore_context_set_apn(co_context, (const gchar *) value);
		}
		else if (g_str_equal(key, "auth_type") == TRUE) {
			int i_tmp = 0;
			i_tmp = atoi((const gchar *) value);
			tcore_context_set_auth(co_context, i_tmp);
		}
		else if (g_str_equal(key, "auth_id") == TRUE) {
			tcore_context_set_username(co_context, (const gchar *) value);
		}
		else if (g_str_equal(key, "auth_pwd") == TRUE) {
			tcore_context_set_password(co_context, (const gchar *) value);
		}
		else if (g_str_equal(key, "proxy_addr") == TRUE) {
			tcore_context_set_proxy(co_context, (const gchar *) value);
		}
		else if (g_str_equal(key, "home_url") == TRUE) {
			tcore_context_set_mmsurl(co_context, (const gchar *) value);
		}
	}

	return __ps_context_update_database(context);
}

static gboolean __ps_context_update_default_internet_to_db(PsContext *context, gboolean enabled)
{
	gchar *s_id = NULL, *s_enabled = NULL;
	gboolean rv = FALSE;
	gchar query[3000];
	GHashTable *in_param;

	tcore_check_return_value(context != NULL, FALSE);

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	strcpy(query, " update pdp_profile set ");
	strcat(query, " default_internet_con = ?");
	strcat(query, " where profile_id = ?");

	s_id = g_strdup_printf("%d", context->profile_id);
	s_enabled = g_strdup_printf("%d", enabled);

	g_hash_table_insert(in_param, "1", g_strdup(s_enabled));
	g_hash_table_insert(in_param, "2", g_strdup(s_id));

	rv = tcore_storage_update_query_database(strg_db, handle, query, in_param);
	g_hash_table_destroy(in_param);

	g_free(s_id);
	g_free(s_enabled);

	return rv;
}

static gboolean __ps_context_update_database(PsContext *context)
{
	gchar *s_id = NULL, *s_authtype = NULL;
	gchar *s_apn = NULL, *s_username = NULL, *s_pwd = NULL, *s_proxy = NULL, *s_mms = NULL;
	gboolean rv = FALSE;
	gchar query[3000];
	TcoreContextAuth authtype;

	GHashTable *in_param;
	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	strcpy(query, " update pdp_profile set ");
	strcat(query, " apn = ?, auth_type = ?, auth_id = ?, auth_pwd = ?, ");
	strcat(query, " proxy_ip_addr = ?, home_url = ?");
	strcat(query, " where profile_id = ?");

	tcore_context_get_auth(context->co_context, &authtype);
	s_id = g_strdup_printf("%d", context->profile_id);
	s_authtype = g_strdup_printf("%d", authtype);

	tcore_context_get_apn(context->co_context, &s_apn);
	tcore_context_get_username(context->co_context, &s_username);
	tcore_context_get_password(context->co_context, &s_pwd);
	tcore_context_get_proxy(context->co_context, &s_proxy);
	tcore_context_get_mmsurl(context->co_context, &s_mms);

	dbg("Profile parameter extracted");
	g_hash_table_insert(in_param, "1", g_strdup(s_apn));
	g_hash_table_insert(in_param, "2", g_strdup(s_authtype));
	g_hash_table_insert(in_param, "3", g_strdup(s_username));
	g_hash_table_insert(in_param, "4", g_strdup(s_pwd));
	g_hash_table_insert(in_param, "5", g_strdup(s_proxy));
	g_hash_table_insert(in_param, "6", g_strdup(s_mms));
	g_hash_table_insert(in_param, "7", g_strdup(s_id));

	dbg("Profile Parameter inserted in data base ");
	rv = tcore_storage_update_query_database(strg_db, handle, query, in_param);
	g_hash_table_destroy(in_param);

	g_free(s_id);
	g_free(s_authtype);

	dbg("Exiting");
	return rv;
}

static gboolean __ps_context_remove_database(PsContext *context)
{
	gchar *s_id = NULL;
	gboolean rv = FALSE;
	gchar query[1000];

	GHashTable *in_param;
	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	memset(query, 0, sizeof(query));
	strcpy(query, " delete from pdp_profile where profile_id = ? ");

	s_id = g_strdup_printf("%d", context->profile_id);
	g_hash_table_insert(in_param, "1", g_strdup(s_id));

	rv = tcore_storage_remove_query_database(strg_db, handle, query, in_param);
	g_free(s_id);
	g_hash_table_destroy(in_param);

	return rv;
}

static gint __ps_context_insert_network_id_to_database(gchar *mccmnc)
{
	gchar query[5000];
	gint network_id = 0;
	gboolean rv = FALSE;
	gchar *insert_key = NULL;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
				(GDestroyNotify) g_hash_table_destroy);

	memset(query, 0, sizeof(query));
	strcpy(query,"select max(network_info_id) as network_id from network_info");

	tcore_storage_read_query_database(strg_db, handle, query, NULL, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if (value) {
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				dbg("key2(%s) value2(%s)",key2, value2);
				if (g_str_equal(key2, "0") == TRUE) {
					if (!value2 || g_strcmp0((const gchar*) value2, "") == 0 ) {
						network_id = 0;
					} else {
						network_id = atoi((const gchar*) value2);
					}
				}
			}
			break;
		}
	}

	g_hash_table_destroy(out_param);
	network_id++;


	memset(query, 0, sizeof(query));
	strcpy(query," insert into network_info( network_info_id, network_name, mccmnc) values( ?, ?, ?) ");

	insert_key = g_strdup_printf("%d", network_id);
	g_hash_table_insert(in_param, "1", g_strdup(insert_key));
	g_hash_table_insert(in_param, "2", "TEMP_NETWORK");
	g_hash_table_insert(in_param, "3", g_strdup(mccmnc));

	rv = tcore_storage_insert_query_database(strg_db, handle, query, in_param);
	if (!rv) {
		err("unable to insert query into database");
		return 0;
	}
	g_free(insert_key);
	return network_id;
}

static gint __ps_context_insert_profile_to_database(GHashTable *property, gint network_id)
{
	gint profile_id = 0;
	gchar query[5000];

	gboolean rv = FALSE;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param;
	gchar *insert_key1 = NULL, *insert_key2 = NULL;
	gchar *profile_name=NULL, *apn=NULL, *auth_type=NULL, *auth_id = NULL, *auth_pwd = NULL;
	gchar *proxy_addr = NULL, *home_url = NULL, *svc_id = NULL, *keyword=NULL, *network_name= NULL;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	g_hash_table_iter_init(&iter, property);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {

		if (g_str_equal(key, "apn") == TRUE) {
			apn = g_strdup(value);
		} else if (g_str_equal(key, "keyword") == TRUE) {
			keyword = g_strdup(value);
		} else if (g_str_equal(key, "auth_type") == TRUE) {
			auth_type = g_strdup(value);
		} else if (g_str_equal(key, "auth_id") == TRUE) {
			auth_id = g_strdup(value);
		} else if (g_str_equal(key, "auth_pwd") == TRUE) {
			auth_pwd = g_strdup(value);
		} else if (g_str_equal(key, "proxy_addr") == TRUE) {
			proxy_addr = g_strdup(value);
		} else if (g_str_equal(key, "home_url") == TRUE) {
			home_url = g_strdup(value);
		} else if (g_str_equal(key, "svc_ctg_id") == TRUE) {
			svc_id = g_strdup(value);
		}

	}

	dbg("apn (%s), auth_type (%s), auth_id(%s), auth_pwd(%s), proxy_addr(%s), home_url(%s), svc_id(%s)",
		apn, auth_type, auth_id, auth_pwd, proxy_addr, home_url, svc_id);

	profile_id = __ps_context_load_profile_id_from_database();
	if (profile_id < 0) {
		dbg("fail to get last profile id");
		return 0;
	}
	dbg("last profile id(%d)", profile_id);
	profile_id++;

	memset(query, 0, sizeof(query));
	strcpy(query," insert into pdp_profile( ");
	strcat(query," profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, ");
	strcat(query," pdp_protocol, proxy_ip_addr, home_url, linger_time, ");
	strcat(query," network_info_id, svc_category_id, hidden, editable, default_internet_con, user_defined) values( ");
	strcat(query," ?, ?, ?, ?, ?, ?,");//1,2,3,4,5,6
	strcat(query," 1, ?, ?, 300,");//7,8
	strcat(query," ?, ?, 0, 1, 0, 1)");//9,10

	insert_key1 = g_strdup_printf("%d", profile_id);
	insert_key2 = g_strdup_printf("%d", network_id);
	network_name = __ps_context_load_network_name_from_database(network_id);

	if (keyword) {
		profile_name = g_strdup_printf("%s", keyword);
	} else {
		profile_name = g_strdup_printf("%s", network_name);
	}
	dbg("profile name (%s)", profile_name);

	g_hash_table_insert(in_param, "1", g_strdup(insert_key1));
	g_hash_table_insert(in_param, "2", g_strdup(profile_name));
	g_hash_table_insert(in_param, "3", g_strdup(apn));
	g_hash_table_insert(in_param, "4", g_strdup(auth_type));
	g_hash_table_insert(in_param, "5", g_strdup(auth_id));
	g_hash_table_insert(in_param, "6", g_strdup(auth_pwd));
	g_hash_table_insert(in_param, "7", g_strdup(proxy_addr));
	g_hash_table_insert(in_param, "8", g_strdup(home_url));
	g_hash_table_insert(in_param, "9", g_strdup(insert_key2));
	g_hash_table_insert(in_param, "10", g_strdup(svc_id));

	g_free(insert_key1);g_free(insert_key2);g_free(profile_name);
	g_free(apn);g_free(auth_type);g_free(auth_id);g_free(auth_pwd);
	g_free(proxy_addr);g_free(home_url);g_free(svc_id);

	rv = tcore_storage_insert_query_database(strg_db, handle, query, in_param);
	g_hash_table_destroy(in_param);

	if (!rv) {
		err("unable to insert query into database");
		return 0;
	}
	return profile_id;
}

static gint __ps_context_load_network_id_from_database(gchar *mccmnc)
{
	gchar query[5000];
	gint network_id = 0;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	memset(query, 0, sizeof(query));
	strcpy(query,"select network_info_id from network_info where mccmnc = ? ");

	g_hash_table_insert(in_param, "1", g_strdup(mccmnc));
	tcore_storage_read_query_database(strg_db, handle, query, in_param, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if (value) {
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				if (g_str_equal(key2, "0") == TRUE) {
					if (!value2 || g_strcmp0((const gchar*) value2, "") == 0) {
						network_id = 0;
					} else {
						network_id = atoi((const gchar*) value2);
					}
				}
			}
			break;
		}
	}

	g_hash_table_destroy(in_param);
	g_hash_table_destroy(out_param);

	return network_id;
}

static gchar* __ps_context_load_network_name_from_database(gint network_id)
{
	gchar query[5000];
	gchar *network_name = NULL;
	gchar *insert_key1 = NULL;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	memset(query, 0, sizeof(query));
	strcpy(query,"select network_name from network_info where network_info_id = ? ");

	insert_key1 = g_strdup_printf("%d", network_id);
	g_hash_table_insert(in_param, "1", g_strdup(insert_key1));
	tcore_storage_read_query_database(strg_db, handle, query, in_param, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if (value) {
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				if (g_str_equal(key2, "0") == TRUE) {
					network_name = g_strdup(value2);
				}
			}
			break;
		}
	}

	g_hash_table_destroy(in_param);
	g_hash_table_destroy(out_param);
	g_free(insert_key1);

	return network_name;
}

static gint __ps_context_load_profile_id_from_database(void)
{
	gchar query[5000];
	gint profile_id = 0;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *out_param;

	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	memset(query, 0, sizeof(query));
	strcpy(query,"select max(profile_id) as last_profile from pdp_profile");

	tcore_storage_read_query_database(strg_db, handle, query, NULL, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if (value) {
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				if (g_str_equal(key2, "0") == TRUE) {
					if (!value2 || g_strcmp0((const gchar*) value2, "") == 0) {
						profile_id = 0;
					} else {
						profile_id = atoi((const gchar*) value2);
					}
				}
			}
			break;
		}
	}

	g_hash_table_destroy(out_param);
	return profile_id;
}

static gint __ps_context_load_num_of_pdn_from_database(gchar *mccmnc)
{
	gchar query[5000];
	gint num_of_pdn = 0;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	memset(query, 0, sizeof(query));
	strcpy(query,"select a.max_pdp_3g from max_pdp a, network_info b ");
	strcat(query,"where a.network_info_id = b.network_info_id and b.mccmnc = ? ");

	g_hash_table_insert(in_param, "1", g_strdup(mccmnc));
	tcore_storage_read_query_database(strg_db, handle, query, in_param, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if (value) {
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				if (g_str_equal(key2, "0") == TRUE) {
					if (!value2 || g_strcmp0((const gchar*) value2, "") == 0) {
						num_of_pdn = 3;
						dbg("there is no value / use default");
					} else {
						num_of_pdn = atoi((const gchar*) value2);
						dbg("value (%d)", num_of_pdn);
					}
				}
			}
			break;
		}
	}

	if (num_of_pdn <= 0) {
		dbg("loaded value is wrong");
		num_of_pdn = 3;
	}

	g_hash_table_destroy(in_param);
	g_hash_table_destroy(out_param);

	return num_of_pdn;
}

static gboolean __ps_context_insert_profile_tuple(dictionary *dic, gint index)
{
	gboolean rv = FALSE;
	GHashTable *in_param;
	gchar *item_key = NULL;
	gchar *profile = NULL;
	gchar query[5000] = {0,};

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	/* Profile id */
	item_key = (gchar *) g_strdup_printf("connection:profile_id_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "1", g_strdup(profile));
	g_free(item_key);

	/* Profile name */
	item_key = (gchar *)g_strdup_printf("connection:profile_name_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "2", g_strdup(profile));
	g_free(item_key);

	/* APN */
	item_key = (gchar *)g_strdup_printf("connection:apn_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "3", g_strdup(profile));
	g_free(item_key);


	/* Auth Type */
	item_key =(gchar *) g_strdup_printf("connection:auth_type_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "4", g_strdup(profile));
	g_free(item_key);

	/* Auth ID */
	item_key = (gchar *)g_strdup_printf("connection:auth_id_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "5", g_strdup(profile));
	g_free(item_key);

	/* Auth Password */
	item_key = g_strdup_printf("connection:auth_pwd_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "6", g_strdup(profile));
	g_free(item_key);

	/* PDP Protocol */
	item_key = g_strdup_printf("connection:pdp_protocol_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "7", g_strdup(profile));
	g_free(item_key);

	/* proxy ip */
	item_key = g_strdup_printf("connection:proxy_ip_addr_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "8", g_strdup(profile));
	g_free(item_key);

	/*  Home URL */
	item_key = g_strdup_printf("connection:home_url_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "9", g_strdup(profile));
	g_free(item_key);

	/* Linger Time */
	item_key = g_strdup_printf("connection:linger_time_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "10", g_strdup(profile));
	g_free(item_key);

	/* Traffic Class */
	item_key = g_strdup_printf("connection:traffic_class_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "11", g_strdup(profile));
	g_free(item_key);


	/*  Static IP Address */
	item_key = g_strdup_printf("connection:is_static_ip_addr_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "12", g_strdup(profile));
	g_free(item_key);

	/* IP Address if static ip is true */
	item_key = g_strdup_printf("connection:ip_addr_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "13", g_strdup(profile));
	g_free(item_key);

	/* Static DNS Address */
	item_key = g_strdup_printf("connection:is_static_dns_addr_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "14", g_strdup(profile));
	g_free(item_key);

	/* DNS Address 1 */
	item_key = g_strdup_printf("connection:dns_addr1_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "15", g_strdup(profile));
	g_free(item_key);

	/* DNS Address 2 */
	item_key = g_strdup_printf("connection:dns_addr2_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "16", g_strdup(profile));
	g_free(item_key);

	/* Network INFO ID */
	item_key = g_strdup_printf("connection:network_info_id_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "17", g_strdup(profile));
	g_free(item_key);

	/* Service Category ID */
	item_key = g_strdup_printf("connection:svc_category_id_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "18", g_strdup(profile ));
	g_free(item_key);

	/* Hidden */
	item_key = g_strdup_printf("connection:hidden_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "19", g_strdup(profile ));
	g_free(item_key);

	/* Editable */
	item_key = g_strdup_printf("connection:editable_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "20", g_strdup(profile));
	g_free(item_key);

	/* Default Internet Connection */
	item_key = g_strdup_printf("connection:default_internet_con_%d", index);
	profile = (gchar *) iniparser_getstring(dic, item_key, NULL);
	g_hash_table_insert(in_param, "21", g_strdup(profile));
	g_free(item_key);

	/* Insert data into table */

	memset(query, 0, sizeof(query));
	strcpy(query," insert into pdp_profile( ");
	strcat(query," profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, ");
	strcat(query," pdp_protocol, proxy_ip_addr, home_url, linger_time,");
	strcat(query," traffic_class, is_static_ip_addr, ip_addr, is_static_dns_addr,dns_addr1, dns_addr2,");
	strcat(query," network_info_id, svc_category_id, hidden, editable, default_internet_con, user_defined) values( ");
	strcat(query," ?, ?, ?, ?, ?, ?,");//1,2,3,4,5,6(auth_pwd)
	strcat(query," ?, ?, ?, ?,");//7,8,9,10(linger_time)
	strcat(query," ?, ?, ?, ?, ?, ?,");//11,12,13,14,15,16(dns_addr2)
	strcat(query," ?, ?, ?, ?, ?, 0)");//17,18,19,20,21(default_internet_con)

	rv = tcore_storage_insert_query_database(strg_db, handle, query, in_param);
	dbg("insert into pdp_profile result(%d)", rv);
	g_hash_table_destroy(in_param);

	return rv;
}

static gint __ps_context_get_network_id(gchar *mccmnc)
{
	gint network_id;

	network_id = __ps_context_load_network_id_from_database(mccmnc);
	dbg("network id(%d)", network_id);
	if (network_id > 0)
		return network_id;

	network_id = __ps_context_insert_network_id_to_database(mccmnc);
	if (network_id <= 0 ) {
		err("unable to insert mccmnc into database");
		return -1;
	}

	return network_id;
}

GVariant * __ps_context_get_profile_properties(gpointer object, GVariantBuilder *properties)
{
	gchar *s_authtype = NULL, *s_role = NULL;
	PsContext *context = NULL;
	gchar *apn, *username, *password, *proxy_addr, *home_url;
	TcoreContextAuth auth;
	TcoreContextRole role;
	gchar *profile;


	tcore_check_return_value(object != NULL, FALSE);
	tcore_check_return_value(properties != NULL, FALSE);

	context = (PsContext *) object;
	dbg("get profile properties");
	tcore_context_get_auth(context->co_context, &auth);
	s_authtype = g_strdup_printf("%d", auth);
	tcore_context_get_role(context->co_context, &role);
	s_role = g_strdup_printf("%d", role);

	tcore_context_get_apn(context->co_context , &apn);
	tcore_context_get_username(context->co_context,&username);
	tcore_context_get_password(context->co_context, &password);
	tcore_context_get_proxy(context->co_context, &proxy_addr);
	tcore_context_get_mmsurl(context->co_context, &home_url);
	tcore_context_get_profile_name(context->co_context, &profile);

	g_variant_builder_init(properties,G_VARIANT_TYPE("a{ss}"));

	g_variant_builder_add(properties, "{ss}", "path", g_strdup(context->path));
	if (apn) {
		g_variant_builder_add(properties, "{ss}", "apn", apn);
	}
	if (s_authtype) {
		g_variant_builder_add(properties, "{ss}", "auth_type", g_strdup(s_authtype));
	}
	if (username) {
		g_variant_builder_add(properties, "{ss}", "auth_id", username);
	}
	if (password) {
		g_variant_builder_add(properties, "{ss}", "auth_pwd", password);
	}
	if (proxy_addr) {
		g_variant_builder_add(properties, "{ss}", "proxy_addr", proxy_addr);
	}
	if (home_url) {
		g_variant_builder_add(properties, "{ss}", "home_url", home_url);
	}
	if (s_role) {
		g_variant_builder_add(properties, "{ss}", "svc_ctg_id", g_strdup(s_role));
	}
	g_variant_builder_add(properties, "{ss}", "profile_name", profile );
	g_variant_builder_add(properties, "{ss}", "hidden", g_strdup(BOOL2STRING(context->hidden)));
	g_variant_builder_add(properties, "{ss}", "editable", g_strdup(BOOL2STRING(context->editable)));
	g_variant_builder_add(properties, "{ss}", "default_internet_conn", g_strdup(BOOL2STRING(context->default_internet)));

	g_free(s_authtype);
	g_free(s_role);

	return g_variant_builder_end(properties);
}

static gboolean __ps_context_set_default_connection_enable(gpointer object, gboolean enabled)
{
	PsContext *context = object;
	TcoreContextRole role ;
	tcore_check_return_value(context != NULL, FALSE);

	tcore_context_get_role(context->co_context, &role);

	if (role == TCORE_CONTEXT_ROLE_INTERNET) {
		context->default_internet = enabled;
	}

	return TRUE;
}

static gpointer __ps_context_add_context(gpointer modem, gchar *mccmnc, gint profile_id)
{
	gchar query[5000];
	GDBusConnection *conn = NULL;
	TcorePlugin *p = NULL;

	GHashTableIter iter;
	gpointer object = NULL;
	gpointer key, value;
	gchar *insert_key1 = NULL;
	GHashTable *in_param, *out_param;
	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	dbg("create profile by profile id (%d)", profile_id);
	conn = _ps_modem_ref_dbusconn(modem);
	p = _ps_modem_ref_plugin(modem);

	memset(query, '\0', sizeof(query));
	strcpy(query, "select");
	strcat(query, " a.network_info_id, a.network_name, a.mccmnc,"); //0 , 1, 2
	strcat(query, " b.profile_id, b.profile_name, b.apn, "); //3, 4, 5
	strcat(query, " b.auth_type, b.auth_id, b.auth_pwd,"); //6, 7, 8
	strcat(query, " b.proxy_ip_addr, b.home_url, b.pdp_protocol, "); //9, 10 , 11
	strcat(query, " b.linger_time, b.traffic_class, b.is_static_ip_addr, b.ip_addr,"); //12, 13, 14, 15
	strcat(query, " b.is_static_dns_addr, b.dns_addr1, b.dns_addr2, b.svc_category_id, b.hidden, b.editable, b.default_internet_con"); //16, 17, 18, 19, 20, 21, 22
	strcat(query, " from network_info a, pdp_profile b");
	strcat(query, " where b.profile_id = ? and a.network_info_id = b.network_info_id ");

	insert_key1 = g_strdup_printf("%d", profile_id);
	g_hash_table_insert(in_param, "1", g_strdup(insert_key1));
	tcore_storage_read_query_database(strg_db, handle, query, in_param, out_param, 23);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *path = NULL;

		object = __ps_context_create_context(conn, p, mccmnc, (GHashTable *) value);
		path = _ps_context_ref_path(object);

		g_hash_table_insert(contexts, g_strdup(path), object);
		dbg("context (%p, %s) insert to hash", object, path);
	}

	g_hash_table_destroy(in_param);
	g_hash_table_destroy(out_param);
	g_free(insert_key1);

	return object;
}

gboolean _ps_context_initialize(gpointer plugin)
{
	gboolean rv = TRUE;

	dbg("global variable initialized");
	rv &=__ps_context_create_storage_handle(plugin);
	rv &=__ps_context_create_context_hash();

	return rv;
}

gboolean _ps_context_reset_profile_table(void)
{
	gboolean rv = FALSE;
	GHashTable *in_param;
	gchar query[5000];

	memset(query, '\0', sizeof(query));
	strcat(query, " delete from pdp_profile");

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	rv = tcore_storage_remove_query_database(strg_db, handle, query, in_param);

	g_hash_table_destroy(in_param);
	return rv;
}

/*	Funtion : _ps_context_remove_context
 *	Description : removes and unregister the interface for the context
 */
gboolean _ps_context_remove_context(gpointer context)
{
	PsContext *pscontext = context;

	dbg("Entered");

	/*Unexporting the interface for the modem*/
	g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(pscontext->if_obj));

	/*Removing the context from the static list */
	g_hash_table_remove(contexts, _ps_context_ref_path(pscontext));

	dbg("Exiting");
	return TRUE;
}


gboolean _ps_context_fill_profile_table_from_ini_file(void)
{
	gint index = 1;
	gint data_exist = 0;

	dictionary *dic = NULL;
	dic = iniparser_load("/opt/system/csc-default/data/csc-default-data-connection.ini");

	if (dic == NULL) {
		dbg("fail to load the csc default file");
		return FALSE;
	}

	do {
		gchar *section_key = NULL;

		section_key = g_strdup_printf("connection:profile_id_%d", index);
		dbg("section key (%s)", section_key);
		data_exist = iniparser_find_entry(dic, section_key);
		if (!data_exist) {
			g_free(section_key);
			iniparser_freedict(dic);
			dbg("no more data in ini");
			return TRUE;
		}

		__ps_context_insert_profile_tuple (dic, index);

		g_free(section_key);
		index++;

	} while (data_exist);

	return TRUE;
}

gboolean _ps_context_reset_hashtable(void)
{
	if (!contexts)
		return TRUE;

	g_hash_table_foreach_remove(contexts, __remove_contexts, NULL);
	return TRUE;
}

GHashTable* _ps_context_create_hashtable(GDBusConnection *conn, TcorePlugin *p, gchar *mccmnc)
{
	gchar query[5000];
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;
	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	dbg("create profile by mccmnc (%s)", mccmnc);

	memset(query, '\0', sizeof(query));
	strcpy(query, "select");
	strcat(query, " a.network_info_id, a.network_name, a.mccmnc,"); //0 , 1, 2
	strcat(query, " b.profile_id, b.profile_name, b.apn, "); //3, 4, 5
	strcat(query, " b.auth_type, b.auth_id, b.auth_pwd,"); //6, 7, 8
	strcat(query, " b.proxy_ip_addr, b.home_url, b.pdp_protocol, "); //9, 10 , 11
	strcat(query, " b.linger_time, b.traffic_class, b.is_static_ip_addr, b.ip_addr,"); //12, 13, 14, 15
	strcat(query, " b.is_static_dns_addr, b.dns_addr1, b.dns_addr2, b.svc_category_id, b.hidden, b.editable, b.default_internet_con"); //16,17, 18, 19, 20, 21, 22
	strcat(query, " from network_info a, pdp_profile b");
	strcat(query, " where a.mccmnc= ? and a.network_info_id = b.network_info_id ");

	g_hash_table_insert(in_param, "1", g_strdup(mccmnc));
	tcore_storage_read_query_database(strg_db, handle, query, in_param, out_param, 23);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *path = NULL;
		gpointer object = NULL;

		object = __ps_context_create_context(conn, p, mccmnc, (GHashTable *) value);
		path = _ps_context_ref_path(object);

		g_hash_table_insert(contexts, g_strdup(path), object);
		dbg("context (%p, %s) insert to hash", object, path);
	}

	g_hash_table_destroy(in_param);
	g_hash_table_destroy(out_param);
	dbg("Exiting");
	return contexts;
}

GHashTable* _ps_context_ref_hashtable(void)
{
	tcore_check_return_value(contexts != NULL, NULL);
	return contexts;
}

gboolean _ps_context_add_context(gpointer modem, gchar *operator, GHashTable *property)
{
	GHashTable *services = NULL;
	gpointer context = NULL;

	GHashTableIter iter;
	gpointer key, value;
	gint network_id = 0;
	gint profile_id = 0;

	network_id = __ps_context_get_network_id(operator);
	if (network_id <= 0) {
		err("fail to add network info");
		return FALSE;
	}

	profile_id = __ps_context_insert_profile_to_database(property, network_id);
	if (profile_id <= 0) {
		err("fail to insert profile info to database");
		return FALSE;
	}

	context = __ps_context_add_context(modem, operator, profile_id);
	if (!context) {
		err("fail to add context");
		return FALSE;
	}
	services = _ps_modem_ref_services(modem);
	if (!services) {
		err("Fail to ref service ");
		return FALSE;
	}
	g_hash_table_iter_init(&iter, services);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		_ps_service_ref_context(value, context);
	}

	return TRUE;
}

gboolean _ps_context_get_properties_handler(gpointer object, GVariantBuilder *properties)
{
	TcoreContextState state;
	gboolean active = FALSE;
	PsContext *context = object;
	gchar *ip4, *dns1, *dns2, *gw, *proxy, *dev_name;

	dbg("get context properties");
	tcore_check_return_value(context != NULL, FALSE);
	tcore_check_return_value(properties != NULL, FALSE);

	tcore_context_get_state(context->co_context, &state);
	if (state == TCORE_CONTEXT_STATE_ACTIVATED)
		active = TRUE;

	tcore_context_get_ipv4_addr(context->co_context,&ip4);
	tcore_context_get_ipv4_gw(context->co_context, &gw);
	tcore_context_get_ipv4_dns1(context->co_context, &dns1);
	tcore_context_get_ipv4_dns2(context->co_context, &dns2);
	tcore_context_get_proxy(context->co_context, &proxy);
	tcore_context_get_ipv4_devname(context->co_context, &dev_name);

	g_variant_builder_open(properties, G_VARIANT_TYPE("a{ss}"));

	g_variant_builder_add(properties, "{ss}", "path", g_strdup(context->path));
	g_variant_builder_add(properties, "{ss}", "active",g_strdup(BOOL2STRING(active)));
	if (ip4) {
		g_variant_builder_add(properties, "{ss}", "ipv4_address", ip4);
	}
	if (gw) {
		g_variant_builder_add(properties, "{ss}", "ipv4_gateway", gw);
	}
	if (dns1) {
		g_variant_builder_add(properties, "{ss}", "ipv4_dns1", dns1);
	}
	if (dns2) {
		g_variant_builder_add(properties, "{ss}", "ipv4_dns2", dns2);
	}
	g_variant_builder_add(properties, "{ss}", "ipv6_address", g_strdup("::"));
	g_variant_builder_add(properties, "{ss}", "ipv6_gateway", g_strdup("::"));
	g_variant_builder_add(properties, "{ss}", "ipv6_dns1", g_strdup("::"));
	g_variant_builder_add(properties, "{ss}", "ipv6_dns2", g_strdup("::"));
	if (proxy) {
		g_variant_builder_add(properties, "{ss}", "proxy", proxy);
	}
	if (dev_name) {
		g_variant_builder_add(properties, "{ss}", "dev_name", dev_name);
	}
	g_variant_builder_add(properties, "{ss}", "default_internet_conn", g_strdup(BOOL2STRING(context->default_internet)));
	g_variant_builder_close(properties);

	return TRUE;
}


GVariant * _ps_context_get_properties(gpointer object, GVariantBuilder *properties)
{
	TcoreContextState context_state ;
	gboolean active = FALSE;
	PsContext *context = object;
	gchar *dev_name = NULL;
	gchar *proxy = NULL;
	gchar *ipv4_address,*ipv4_gateway,*ipv4_dns1,*ipv4_dns2;

	dbg("get context properties");
	tcore_check_return_value(context != NULL, FALSE);
	tcore_check_return_value(properties != NULL, FALSE);

	tcore_context_get_state(context->co_context, &context_state);
	if (context_state == TCORE_CONTEXT_STATE_ACTIVATED)
		active = TRUE;


	tcore_context_get_ipv4_addr(context->co_context, &ipv4_address) ;
	tcore_context_get_ipv4_gw(context->co_context, &ipv4_gateway );
	tcore_context_get_ipv4_dns1(context->co_context, &ipv4_dns1);
	tcore_context_get_ipv4_dns2(context->co_context , &ipv4_dns2);
	tcore_context_get_proxy(context->co_context, &proxy);
	tcore_context_get_ipv4_devname(context->co_context, &dev_name);

	g_variant_builder_init(properties, G_VARIANT_TYPE("a{ss}"));

	g_variant_builder_add(properties, "{ss}", "path", g_strdup(context->path));
	g_variant_builder_add(properties, "{ss}", "active",g_strdup(BOOL2STRING(active)));
	if (ipv4_address) {
		g_variant_builder_add(properties, "{ss}", "ipv4_address", ipv4_address);
	}
	if (ipv4_gateway) {
		g_variant_builder_add(properties, "{ss}", "ipv4_gateway", ipv4_gateway);
	}
	if (ipv4_dns1) {
		g_variant_builder_add(properties, "{ss}", "ipv4_dns1", ipv4_dns1);
	}
	if (ipv4_dns2) {
		g_variant_builder_add(properties, "{ss}", "ipv4_dns2", ipv4_dns2);
	}
	g_variant_builder_add(properties, "{ss}", "ipv6_address", g_strdup("::"));
	g_variant_builder_add(properties, "{ss}", "ipv6_gateway", g_strdup("::"));
	g_variant_builder_add(properties, "{ss}", "ipv6_dns1", g_strdup("::"));
	g_variant_builder_add(properties, "{ss}", "ipv6_dns2", g_strdup("::"));
	if (proxy) {
		g_variant_builder_add(properties, "{ss}", "proxy", proxy);
	}
	if (dev_name) {
		g_variant_builder_add(properties, "{ss}", "dev_name", dev_name);
	}
	g_variant_builder_add(properties, "{ss}", "default_internet_conn", g_strdup(BOOL2STRING(context->default_internet)));

	dbg("Exiting");
	return g_variant_builder_end(properties);
}

gboolean _ps_context_set_alwayson_enable(gpointer object, gboolean enabled)
{
	PsContext *context = object;
	TcoreContextRole role;
	tcore_check_return_value(context != NULL, FALSE);

	tcore_context_get_role(context->co_context, &role);

	if (role == TCORE_CONTEXT_ROLE_INTERNET && context->default_internet) {
		context->alwayson = enabled;
	}

	return TRUE;
}

gboolean _ps_context_get_default_internet(gpointer object)
{
	PsContext *context = object;
	TcoreContextRole role;
	tcore_check_return_value(context != NULL, FALSE);

	tcore_context_get_role(context->co_context, &role);
	if (role == TCORE_CONTEXT_ROLE_INTERNET && context->default_internet) {
		return TRUE;
	}

	return FALSE;
}

gboolean _ps_context_set_service(gpointer object, gpointer service)
{
	PsContext *context = object;
	tcore_check_return_value(context != NULL, FALSE);

	context->p_service = service;
	return TRUE;
}

gpointer _ps_context_ref_service(gpointer object)
{
	PsContext *context = object;
	tcore_check_return_value(context != NULL, FALSE);

	return context->p_service;
}

gchar* _ps_context_ref_path(gpointer object)
{
	PsContext *context = object;
	tcore_check_return_value(context != NULL, NULL);

	return context->path;
}

gboolean _ps_context_get_alwayson_enable(gpointer object)
{
	PsContext *context = object;
	tcore_check_return_value(context != NULL, FALSE);

	return context->alwayson;
}

gpointer _ps_context_ref_co_context(gpointer object)
{
	PsContext *context = object;
	tcore_check_return_value(context != NULL, NULL);

	return context->co_context;
}

gboolean _ps_context_set_connected(gpointer object, gboolean enabled)
{
	gchar *ipv4 = NULL;
	PsContext *context = object;

	tcore_context_get_ipv4_addr(context->co_context, &ipv4);
	dbg("IPv4 Address: [%s]", ipv4);

	if (enabled) {
		dbg("Set state - ACTIVATED");
		tcore_context_set_state(context->co_context, TCORE_CONTEXT_STATE_ACTIVATED);

		if ( g_str_equal(ipv4, "0.0.0.0") == TRUE ) {
			dbg("ip address is 0.0.0.0");
			_ps_service_deactivate_context(context->p_service, context);
			return TRUE;
		}

		_ps_service_reset_connection_timer(context);

	} else {
		dbg("Set state - DEACTIVATED");
		tcore_context_set_state(context->co_context, TCORE_CONTEXT_STATE_DEACTIVATED);

		/* Reset device information */
		tcore_context_reset_devinfo(context->co_context);

		/* Reset connection timer */
        _ps_service_connection_timer(context->p_service, context);
	}

	/* Emit Property changed signal */
	__ps_context_emit_property_changed_signal(context);

	/* Free memory */
	g_free(ipv4);
	return TRUE;
}

gboolean _ps_context_set_ps_defined(gpointer *object, gboolean value, int cid)
{
	PsContext *context = (PsContext *)object;
	guint id;
	tcore_check_return_value(context != NULL, FALSE);
	tcore_context_get_id(context->co_context, &id);
	if (id == (unsigned int)cid) {
		context->ps_defined = value;
		dbg("context(%p) ps_defined(%d) cid(%d)", context, context->ps_defined, cid);
		return TRUE;
	}
	dbg("context(%p) does not have cid(%d)",context, cid);

	return FALSE;
}

gboolean _ps_context_get_ps_defined(gpointer *object)
{
	PsContext *context = (PsContext *)object;

	dbg("context(%p), ps_defined(%d)", context, context->ps_defined);

	return context->ps_defined;
}

gboolean _ps_context_reset_user_data(gpointer object)
{
	PsContext *context = (PsContext *)object;

	tcore_check_return_value(context != NULL, FALSE);
	context->user_data = NULL;

	return TRUE;
}

gpointer _ps_context_get_user_data(gpointer object)
{
	PsContext *context = (PsContext *)object;
	return context->user_data;
}

TelReturn _ps_connection_hdlr(gpointer object)
{
	TelReturn rv = TEL_RETURN_FAILURE;
	PsContext *pscontext = object;

	_ps_context_set_alwayson_enable(pscontext, TRUE);
	rv = _ps_service_activate_context(pscontext->p_service, pscontext);
	if (rv != TEL_RETURN_SUCCESS) {
		dbg("fail to activate context connection");
		return rv;
	}

	dbg("success to activate context");
	return rv;
}

void _ps_default_connection_hdlr(gpointer object)
{
	//int rv = TEL_RETURN_FAILURE;
	PsContext *pscontext = (PsContext *)object;

	_ps_service_reset_connection_timer(pscontext);
	__ps_context_update_default_internet_to_db(pscontext, TRUE);

	//set request profile
	__ps_context_set_default_connection_enable(pscontext, TRUE);
	_ps_context_set_alwayson_enable(pscontext, TRUE);
	__ps_context_emit_property_changed_signal(pscontext);
#if 0
	//request to connect
	rv = _ps_service_connect_default_context(pscontext->p_service);
	if (rv == TEL_RETURN_PS_NETWORK_NOT_READY) {
		int cid = -1;
		PsService * p_service = (PsService *)pscontext->p_service;

		dbg("PS is not attached yet, release resources.");

		tcore_context_get_id(pscontext->co_context , &cid);
		_ps_context_set_ps_defined((gpointer)pscontext, FALSE, cid);
		tcore_ps_set_cid_active(p_service->co_ps, cid, FALSE);
		tcore_ps_clear_context_id(p_service->co_ps, pscontext->co_context);
	}
#endif
	dbg("complete to change the default connection");
	return;
}

gint _ps_context_get_number_of_pdn(gchar *operator)
{
	gint num_of_pdn = 0;

	num_of_pdn = __ps_context_load_num_of_pdn_from_database(operator);
	dbg("loaded num_of_pdn (%d)", num_of_pdn);

	return num_of_pdn;
}

gboolean _ps_context_handle_ifaceup(gpointer user_data)
{
	PsContext *pscontext = user_data;
	TcoreContextState context_state ;
	gchar *devname = NULL;
	tcore_context_get_state(pscontext->co_context , &context_state);
	dbg("context_state: %d", context_state);
	if (context_state == TCORE_CONTEXT_STATE_ACTIVATED) {
		tcore_context_get_ipv4_devname(pscontext->co_context, &devname );
		dbg("Celluar profile: Emit property signal to provide IP configuration, devname(%s)", devname);
		pscontext->b_active = TRUE;
		if (TEL_RETURN_SUCCESS != tcore_util_netif(devname, TRUE)) {
			dbg("Failed to bring up interface");
		}
		/*
		 * 20131212, Deprecated: Fixed by HTTP stack.
		 * ===============================================================================
		 * 20130801, JIRA DCM-2221: HTTP communication behavior while bearer switching
		 * Observations: When contiguous HTTP requests while ME handovers from wi-fi to 3G,
		 * libcurl does not make Aborted event to application
		 * even if libcurl receives socket closed event by SIOCKILLADDR.
		 * So, we add work-around patch set here.
		 * ===============================================================================
		 */
		__ps_context_emit_property_changed_signal(pscontext);
		return TRUE;
	}
	return FALSE;
}
#if 0
gboolean _ps_context_handle_ifacedown(gpointer user_data)
{
	PsContext *pscontext = user_data;
	gchar * devname;
	gchar *ipv4;
	TcoreContextState context_state ;

	tcore_context_get_state(pscontext->co_context, &context_state);
	dbg("context_state: %d", context_state);
	if (context_state == TCORE_CONTEXT_STATE_ACTIVATED) {
		tcore_context_get_ipv4_devname(pscontext->co_context, &devname);
		dbg("Cellular profile: Do not send PDP deactivation request message to Modem.");
		pscontext->b_active = FALSE;
		dbg("reset socket connections, devname(%s)", devname);
		tcore_context_get_ipv4_addr(pscontext->co_context, &ipv4);
		tcore_util_reset_ipv4_socket(devname, ipv4);
		if (TEL_RETURN_SUCCESS != tcore_util_netif(devname, FALSE)) {
			dbg("Failed to bring down interface");
		}
		__ps_context_emit_property_changed_signal(pscontext);
		return TRUE;
	}
	return FALSE;
}
#endif

static gboolean on_context_get_properties (PacketServiceContext *obj_context,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	GVariant *gv = NULL;
	GVariantBuilder property;

	dbg("Entered");
	gv = _ps_context_get_properties(user_data, &property);
	packet_service_context_complete_get_properties(obj_context, invocation, gv);
	return TRUE;
}

static gboolean on_context_get_profile (PacketServiceContext *obj_context,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	GVariant *gv = NULL;
	GVariantBuilder profile;

	dbg("Entered");
	gv = __ps_context_get_profile_properties(user_data, &profile);
	packet_service_context_complete_get_profile(obj_context, invocation, gv);
	return TRUE;
}

static gboolean on_context_handle_activate (PacketServiceContext *obj_context,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	gint rv = 0;
	TelReturn result = TEL_RETURN_FAILURE;

	gchar *apn = NULL;
	TcoreContextState context_state = 0;
	gpointer p_service = NULL; gpointer co_ps = NULL;
	gpointer c_def_context = NULL; unsigned int cid_def = 0;

	PsContext *pscontext = user_data;

	dbg("Entered");
	if (pscontext == NULL) {
		err("activation request object is NULL");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}

	p_service = pscontext->p_service;
	if (!p_service) {
		err("service object is null");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}

	co_ps = _ps_service_ref_co_ps(p_service);
	if (!co_ps) {
		err("core object is null");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}

	dbg("activate context(%s)", _ps_context_ref_path(pscontext));

	tcore_context_get_apn(pscontext->co_context, &apn);
	if (!apn) {
		err("requested apn is null");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}

	tcore_context_get_state(pscontext->co_context, &context_state);
	if (context_state != TCORE_CONTEXT_STATE_DEACTIVATED) {
		warn("operation is in progress");
		FAIL_RESPONSE(invocation,  PS_ERR_INTERNAL);
		return TRUE;
	}

	dbg("requested context(%p) co_context(%p) apn (%s)", pscontext, pscontext->co_context, apn);
	//check apn is activated or not
	rv = tcore_ps_is_active_apn(co_ps, (const gchar*)apn);
	if (rv) {
		dbg("requested apn is already activated");

		result = _ps_connection_hdlr(pscontext);
		if (result != TEL_RETURN_SUCCESS) {
			FAIL_RESPONSE(invocation,  PS_ERR_INTERNAL);
			return TRUE;
		}

		packet_service_context_complete_activate(obj_context, invocation, pscontext->path);
		tcore_context_get_state(pscontext->co_context, &context_state);
		if (context_state == TCORE_CONTEXT_STATE_ACTIVATED) {
			dbg("context is already connected");
			_ps_context_set_connected(pscontext, TRUE);
		}

		dbg("success to open connection request");
		return TRUE;
	}

	//find the current default connection
	c_def_context = _ps_service_return_default_context(p_service);
	tcore_context_get_id(((PsContext *)c_def_context)->co_context, &cid_def );
	if (cid_def == 0) {
		err("it is not avaiable to open connection");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}

	//check the status of def context
	tcore_context_get_state(((PsContext *)c_def_context)->co_context, &context_state);
	if (context_state != TCORE_CONTEXT_STATE_ACTIVATED) {
		err("default connection is in progress");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}

	_ps_service_reset_connection_timer(c_def_context);

#if 0
	((PsContext *)c_def_context)->user_data = pscontext;
	result = tcore_ps_deactivate_cid(co_ps, cid_def);
	if (result != TEL_RETURN_SUCCESS) {
		err("fail to deactivate exist network connection");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}
#endif
	packet_service_context_complete_activate(obj_context, invocation, pscontext->path);
	return TRUE;

}

static gboolean on_context_handle_deactivate (PacketServiceContext *obj_context,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{

	gboolean rv = FALSE;

	TcoreContextState context_state;
	PsContext *pscontext = user_data;

	dbg("Entered");
	if (pscontext == NULL) {
		err("deactivation request object is NULL");
		FAIL_RESPONSE(invocation,  PS_ERR_NO_PROFILE);
		return TRUE;
	}

	tcore_context_get_state(pscontext->co_context, &context_state);
	if (context_state != TCORE_CONTEXT_STATE_ACTIVATED) {
		err("operation is in progress");
		FAIL_RESPONSE(invocation,  PS_ERR_INTERNAL);
		return TRUE;
	}

	dbg("deactivate context(%s)", _ps_context_ref_path(pscontext));

	_ps_service_reset_connection_timer(pscontext);
	_ps_context_set_alwayson_enable(pscontext, FALSE);

	rv = _ps_service_deactivate_context(pscontext->p_service, pscontext);
	if (rv != TEL_RETURN_SUCCESS) {
		err("fail to deactivate context connection");
		FAIL_RESPONSE(invocation,  PS_ERR_TRASPORT);
		return TRUE;
	}

	dbg("success to deactivate context");
	packet_service_context_complete_deactivate(obj_context, invocation, pscontext->path);

	tcore_context_get_state(pscontext->co_context, &context_state);
	if (context_state == TCORE_CONTEXT_STATE_DEACTIVATED) {
		dbg("context is already disconnected");
		pscontext->ps_defined = FALSE;
		_ps_context_set_connected(pscontext, FALSE);
	}

	return TRUE;
}

static gboolean on_context_set_default_connection (PacketServiceContext *obj_context,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	TcoreContextRole role;
	TcoreContextState context_state;

	gpointer co_ps = NULL;
	gpointer service = NULL;
	gpointer cur_default_ctx = NULL;
	PsContext *pscontext = user_data;

	dbg("enter set default connection PsContext(%p)", pscontext);
	if (pscontext == NULL) {
		err("activation request object is NULL");
		FAIL_RESPONSE(invocation, PS_ERR_NO_PROFILE);
		return TRUE;
	}

	dbg("start default connection");
	tcore_context_get_role(pscontext->co_context, &role);
	if (role != TCORE_CONTEXT_ROLE_INTERNET) {
		warn("only internet profile type can be set to default internet profile");
		FAIL_RESPONSE(invocation, PS_ERR_WRONG_PROFILE);
		return TRUE;
	}

	service = pscontext->p_service;
	cur_default_ctx = _ps_service_return_default_context(service);
	dbg("current default connection (%p)", cur_default_ctx);

	if (!cur_default_ctx) {
		err("No current default connection.");
		goto OUT;
	}

	if (pscontext == cur_default_ctx) {
		err("already default internet connection.");
		goto OUT;
	}
#if 0
	// First, send deactivation request first.
	rv = _ps_service_deactivate_context(((PsContext *)cur_default_ctx)->p_service, cur_default_ctx);
	if (rv == TEL_RETURN_PS_ACTIVATING) {
		dbg("fail to deactivate default connection, rv(%d)", rv);
		FAIL_RESPONSE(invocation, PS_ERR_INTERNAL);
		return TRUE;
	}
#endif
	/* Normal deactivation case. */
	tcore_context_get_state(((PsContext *)cur_default_ctx)->co_context, &context_state);
	if (context_state == TCORE_CONTEXT_STATE_DEACTIVATING) {
		dbg("deactivation request in current ps (%p)", cur_default_ctx);
		((PsContext *)cur_default_ctx)->user_data = pscontext;
	}
	else{
		guint cid = 0;

		dbg("[Not normal] deactivation request in current ps (%p)", cur_default_ctx);

		tcore_context_get_id(((PsContext *)cur_default_ctx)->co_context, &cid);
		_ps_context_set_ps_defined(cur_default_ctx, FALSE, cid);
		co_ps = _ps_service_ref_co_ps(service);
		//tcore_ps_set_cid_active((CoreObject *)co_ps, cid, FALSE);
		tcore_ps_clear_context_id((CoreObject *)co_ps, ((PsContext *)cur_default_ctx)->co_context);
	}

	//unset default info of previous connection
	_ps_context_set_alwayson_enable(cur_default_ctx, FALSE);
	__ps_context_set_default_connection_enable(cur_default_ctx, FALSE);

	//db update - release default connection
	dbg("context(%p): release default connection property.", cur_default_ctx);
	__ps_context_update_default_internet_to_db((PsContext *)cur_default_ctx, FALSE);
	/* Allow Connman to update profile information. */
	__ps_context_emit_property_changed_signal(cur_default_ctx);

	dbg("activation requeset in new ps (%p)", pscontext);
OUT:
	_ps_default_connection_hdlr(pscontext);
	packet_service_context_complete_set_default_connection(obj_context, invocation, TRUE);
	return TRUE;

}

static gboolean on_context_modify_profile(PacketServiceContext *obj_context,
	GDBusMethodInvocation *invocation,
	GVariant *property, gpointer user_data)
{
	GVariantIter g_iter;
	gchar *g_value;
	gchar *g_key;

	gboolean result = FALSE;
	TcoreContextState context_state = 0;
	PsContext *context = user_data;
	GHashTable *profile_property = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	dbg("modify context's profile properties");

	tcore_context_get_state(context->co_context, &context_state);
	if (context_state == TCORE_CONTEXT_STATE_ACTIVATING) {
		FAIL_RESPONSE(invocation,  PS_ERR_INTERNAL);
		return TRUE;
	}

	/* Creating the profile property hash for for internal handling */
	/* Create a hash table for the profile property as all fucntion already use ghash table */
	g_variant_iter_init (&g_iter, property);
	while (g_variant_iter_next (&g_iter, "{ss}", &g_key, &g_value)) {
		g_hash_table_insert(profile_property, g_strdup(g_key), g_strdup(g_value));

		/* must free data for ourselves */
		g_free (g_value);
		g_free (g_key);
	}

	result = __ps_context_update_profile(context, profile_property);
	if (result != TRUE) {
		FAIL_RESPONSE(invocation,  PS_ERR_INTERNAL);
		return TRUE;
	}

	_ps_service_deactivate_context(context->p_service, context);
	if (context_state == TCORE_CONTEXT_STATE_DEACTIVATED) {
		dbg("context is already disconnected");
		_ps_context_set_connected(context, FALSE);
	}

	packet_service_context_complete_modify_profile(obj_context, invocation, TRUE);
	return TRUE;
}

static gboolean on_context_remove_profile (PacketServiceContext *obj_context,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	PsContext *context = user_data;
	gboolean result = FALSE;

	dbg("Entered");

	__ps_context_remove_database(context);
	result = __ps_context_remove_context(context);
	if (result) {
		gchar *ctx_path = g_strdup(_ps_context_ref_path(context));

		/* Remove context from HASH table */
		g_hash_table_remove(contexts, ctx_path);
		g_free(ctx_path);
	}
	else {
		err("Failed to remove context [%p]", context);
	}

	packet_service_context_complete_remove_profile(obj_context, invocation, result);

	return TRUE;
}

static void _ps_context_setup_interface(PacketServiceContext *context,
	PsContext *context_data)
{
	dbg("Entered");

	g_signal_connect (context,
		"handle-get-properties",
		G_CALLBACK (on_context_get_properties),
		context_data);

	g_signal_connect (context,
		"handle-get-profile",
		G_CALLBACK (on_context_get_profile),
		context_data);

	g_signal_connect (context,
		"handle-activate",
		G_CALLBACK (on_context_handle_activate),
		context_data);

	g_signal_connect (context,
		"handle-deactivate",
		G_CALLBACK (on_context_handle_deactivate),
		context_data);

	g_signal_connect (context,
		"handle-set-default-connection",
		G_CALLBACK (on_context_set_default_connection),
		context_data);

	g_signal_connect (context,
		"handle-modify-profile",
		G_CALLBACK (on_context_modify_profile),
		context_data);

	g_signal_connect (context,
		"handle-remove-profile",
		G_CALLBACK (on_context_remove_profile),
		context_data);

	dbg("Exiting");
	return;
}
