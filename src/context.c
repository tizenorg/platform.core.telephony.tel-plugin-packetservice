/*
 * PacketService Control Module
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: DongHoo Park <donghoo.park@samsung.com>
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
 *
 */

#include "ps-context.h"

#include "ps.h"
#include "ps-error.h"

#include <tcore.h>
#include <plugin.h>
#include <server.h>
#include <storage.h>
#include <core_object.h>
#include <co_context.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL
#define BOOL2STRING(a)		((a==TRUE) ? ("TRUE"):("FALSE"))
#define DATABASE_PATH		"/opt/dbspace/.dnet.db"

/*Properties*/
enum {
	PROP_CONTEXT_O,

	PROP_CONTEXT_PATH,
	PROP_CONTEXT_CONN,
	PROP_CONTEXT_PLUGIN,
	PROP_CONTEXT_MCCMNC
};

enum {
	SIG_CONTEXT_PROPERTY_CHANGED,
	SIG_CONTEXT_LAST
};

static guint32 signals[SIG_CONTEXT_LAST] = { 0, };

struct PsContextClass {
	GObjectClass parent;

	//method and signals
	void (*property_changed)(PsContext *context, GHashTable *context_property);
};

struct PsContext {
	GObject parent;

	gchar* path;
	gchar* mccmnc;
	DBusGConnection *conn;
	TcorePlugin *plg;

	gboolean alwayson;
	gpointer p_service;
	int profile_id;
	CoreObject *co_context;
};

static Storage *strg_db;
static gpointer handle;
static GHashTable *contexts;

G_DEFINE_TYPE(PsContext, ps_context, G_TYPE_OBJECT);

static void     __ps_context_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);
static void     __ps_context_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);

gboolean        ps_iface_context_get_properties(PsContext *pscontext, DBusGMethodInvocation *context);
gboolean        ps_iface_context_get_profile(PsContext *pscontext, DBusGMethodInvocation *context);
gboolean        ps_iface_context_activate(PsContext *pscontext, DBusGMethodInvocation *context);
gboolean        ps_iface_context_deactivate(PsContext *pscontext, DBusGMethodInvocation *context);
gboolean        ps_iface_context_modify_profile(PsContext *pscontext, GHashTable *profile_property, gboolean* result, GError **error);
gboolean        ps_iface_context_remove_profile(PsContext *pscontext, gboolean* result, GError **error);

static void     __ps_context_emit_property_changed_signal(PsContext *context);

static void     __remove_context(gpointer data);
static gboolean __remove_contexts(gpointer key, gpointer value, gpointer user_data);
static gboolean __ps_context_remove_context(PsContext *context);
static gboolean __ps_context_create_storage_handle(gpointer plugin);
static gboolean __ps_context_create_context_hash(void);
static gchar*   __ps_context_create_path(char *profile_name,int svc_ctg_id);
static gboolean __ps_context_create_co_context(gpointer context, GHashTable *property);
static gboolean __ps_context_update_profile(PsContext *context, GHashTable *property);
static gboolean __ps_context_update_database(PsContext *context);
static gboolean __ps_context_remove_database(PsContext *context);
static int      __ps_context_insert_network_id_to_database(gchar *mccmnc);
static int      __ps_context_load_network_id_from_database(gchar *mccmnc);
static int      __ps_context_load_profile_id_from_database(void);
static int      __ps_context_insert_profile_to_database(GHashTable *property, int network_id);
static gboolean __ps_context_reset_database(void);
static int      __ps_context_get_network_id(gchar *mccmnc);
static gboolean __ps_context_get_profile_properties(gpointer context, GHashTable *properties);
static gboolean __ps_context_set_alwayson_enable(gpointer object, gboolean enabled);

#include "ps-iface-context-glue.h"

static void ps_context_init(PsContext *context)
{
	dbg("context initialize");

	context->path = NULL;
	context->mccmnc = NULL;
	context->conn = NULL;
	context->plg = NULL;

	context->alwayson = PROP_DEFAULT;
	context->p_service = NULL;
	context->profile_id = 0;
	context->co_context = NULL;

	return;
}

static void ps_context_class_init(PsContextClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	//class init
	dbg("context class init");

	object_class->get_property = __ps_context_get_property;
	object_class->set_property = __ps_context_set_property;

	//dbus register
	dbus_g_object_type_install_info(PS_TYPE_CONTEXT, &dbus_glib_ps_iface_context_object_info);

	//property add
	g_object_class_install_property(
			object_class,
			PROP_CONTEXT_CONN,
			g_param_spec_boxed("conn", "CONNECTION", "DBus connection", DBUS_TYPE_G_CONNECTION,
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(
			object_class,
			PROP_CONTEXT_PATH,
			g_param_spec_string("path", "PATH", "Context Path", PROP_DEFAULT_STR,
					G_PARAM_READWRITE));
	g_object_class_install_property(
			object_class,
			PROP_CONTEXT_MCCMNC,
			g_param_spec_string("mccmnc", "MCCMNC", "Profile Country and Context Provider Code",
					PROP_DEFAULT_STR, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(
			object_class,
			PROP_CONTEXT_PLUGIN,
			g_param_spec_pointer("plg", "PLUGIN", "Plug in Object",
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	//add signal handler
	signals[SIG_CONTEXT_PROPERTY_CHANGED] = g_signal_new("property-changed",
			G_OBJECT_CLASS_TYPE(klass), G_SIGNAL_RUN_LAST,
			G_STRUCT_OFFSET(PsContextClass, property_changed), NULL, NULL,
			g_cclosure_marshal_VOID__BOXED, G_TYPE_NONE, 1, DBUS_TYPE_G_STRING_STRING_HASHTABLE);

	return;
}

static void __ps_context_set_property(GObject *object, guint prop_id, const GValue *value,
		GParamSpec *pspec)
{
	PsContext *context = PS_CONTEXT(object);

	switch (prop_id) {
		case PROP_CONTEXT_CONN: {
			context->conn = g_value_get_boxed(value);
			msg("context (%p) set conn(%p)", context, context->conn);
		}
			break;
		case PROP_CONTEXT_PLUGIN: {
			context->plg = g_value_get_pointer(value);
			msg("context (%p) set plg(%p)", context, context->plg);
		}
			break;
		case PROP_CONTEXT_PATH: {
			if (context->path) {
				g_free(context->path);
			}
			context->path = g_value_dup_string(value);
			msg("context (%p) path(%s)", context, context->path);
		}
			break;
		case PROP_CONTEXT_MCCMNC: {
			if (context->mccmnc) {
				g_free(context->mccmnc);
			}
			context->mccmnc = g_value_dup_string(value);
			msg("context (%p) mccmnc(%s)", context, context->mccmnc);
		}
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	} //end of switch

	return;
}

static void __ps_context_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	return;
}

static void __ps_context_emit_property_changed_signal(PsContext *context)
{
	GHashTable *property;

	property = g_hash_table_new(g_str_hash, g_str_equal);
	_ps_context_get_properties(context, property);
	g_signal_emit(context, signals[SIG_CONTEXT_PROPERTY_CHANGED], 0, property);
	g_hash_table_destroy(property);
	dbg("context (%p) emit the context property changed signal", context);
	return;
}

gboolean ps_iface_context_get_properties(PsContext *pscontext, DBusGMethodInvocation *context)
{
	GHashTable *property;

	dbg("Get properties of context(%s)", _ps_context_ref_path(pscontext));
	property = g_hash_table_new(g_str_hash, g_str_equal);
	_ps_context_get_properties(pscontext, property);

	dbus_g_method_return(context, property);
	g_hash_table_destroy(property);
	return TRUE;
}

gboolean ps_iface_context_get_profile(PsContext *pscontext, DBusGMethodInvocation *context)
{
	GHashTable *profile;

	dbg("Get profile properties of context(%s)", _ps_context_ref_path(pscontext));
	profile = g_hash_table_new(g_str_hash, g_str_equal);
	__ps_context_get_profile_properties(pscontext, profile);

	dbus_g_method_return(context, profile);
	g_hash_table_destroy(profile);
	return TRUE;
}

gboolean ps_iface_context_activate(PsContext *pscontext, DBusGMethodInvocation *context)
{
	int rv = 0;
	int context_state = 0;
	GError *error = NULL;

	dbg("activate context(%s)", _ps_context_ref_path(pscontext));

	/*support always on connection*/
	__ps_context_set_alwayson_enable(pscontext, TRUE);
	_ps_service_reset_connection_timer(pscontext);

	rv = _ps_service_activate_context(pscontext->p_service, pscontext);
	if (rv != TCORE_RETURN_SUCCESS) {
		dbg("fail to activate context connection");
		g_set_error(&error, PS_ERROR, PS_ERR_TRASPORT, "fail to activate context err(%d)", rv);
		goto FAIL;
	}

	dbg("success to activate context");
	dbus_g_method_return(context, pscontext->path);

	context_state =    tcore_context_get_state(pscontext->co_context);
	if (context_state == CONTEXT_STATE_ACTIVATED) {
		dbg("context is already connected");
		_ps_context_set_connected(pscontext, TRUE);
	}

	return TRUE;

	FAIL: dbus_g_method_return_error(context, error);
	return TRUE;
}

gboolean ps_iface_context_deactivate(PsContext *pscontext, DBusGMethodInvocation *context)
{
	int rv = 0;
	int context_state = 0;
	GError *error = NULL;

	dbg("deactivate context(%s)", _ps_context_ref_path(pscontext));

	__ps_context_set_alwayson_enable(pscontext, FALSE);
	rv = _ps_service_deactivate_context(pscontext->p_service, pscontext);
	if (rv != TCORE_RETURN_SUCCESS) {
		dbg("fail to deactivate context connection");
		g_set_error(&error, PS_ERROR, PS_ERR_TRASPORT, "fail to deactivate context err(%d)", rv);
		goto FAIL;
	}

	dbg("success to deactivate context");
	dbus_g_method_return(context, pscontext->path);

	context_state =    tcore_context_get_state(pscontext->co_context);
	if (context_state == CONTEXT_STATE_DEACTIVATED) {
		dbg("context is already disconnected");
		_ps_context_set_connected(pscontext, FALSE);
	}

	return TRUE;

	FAIL: dbus_g_method_return_error(context, error);
	return TRUE;
}

gboolean ps_iface_context_modify_profile(PsContext *context, GHashTable *profile_property,
		gboolean* result, GError **error)
{
	gboolean rv = FALSE;
	int context_state = 0;

	*result = TRUE;
	dbg("modify context's profile properties");

	rv = __ps_context_update_profile(context, profile_property);
	if (rv != TRUE) {
		g_set_error(error, PS_ERROR, PS_ERR_INTERNAL, "fail to modify profile");
		*result = FALSE;
		return TRUE;
	}

	context_state =    tcore_context_get_state(context->co_context);
	if (context_state == CONTEXT_STATE_DEACTIVATED)
		return TRUE;

	_ps_service_deactivate_context(context->p_service, context);
	context_state =    tcore_context_get_state(context->co_context);
	if (context_state == CONTEXT_STATE_DEACTIVATED) {
		dbg("context is already disconnected");
		_ps_context_set_connected(context, FALSE);
	}

	return TRUE;
}

gboolean ps_iface_context_remove_profile(PsContext *context, gboolean* result, GError **error)
{
	gboolean rv = FALSE;
	__ps_context_remove_database(context);
	rv = __ps_context_remove_context(context);
	*result = rv;
	return TRUE;
}

static void __remove_context(gpointer data)
{
	dbg("context removed");
	return;
}

static gboolean __remove_contexts(gpointer key, gpointer value, gpointer user_data)
{
	gchar *context_path = (gchar *) key;
	dbg("context(%s) remove", context_path);
	__ps_context_remove_context(value);
	return TRUE;
}

static gboolean __ps_context_remove_context(PsContext *context)
{
	dbg("remove context and profile");

	dbus_g_connection_unregister_g_object(context->conn, (GObject *) context);

	__ps_context_set_alwayson_enable(context, FALSE);
	_ps_service_deactivate_context(context->p_service, context);
	_ps_context_set_connected(context, FALSE);
	_ps_service_unref_context(context->p_service, context);
	g_hash_table_remove(contexts, _ps_context_ref_path(context));

	tcore_context_free(context->co_context);
	//__ps_context_remove_database(context);
	g_object_unref(context);

	return TRUE;
}

static gboolean __ps_context_create_storage_handle(gpointer plugin)
{
	TcorePlugin *p = plugin;
	Server *s = tcore_plugin_ref_server(p);
	strg_db = tcore_server_find_storage(s, "database");

	handle = tcore_storage_create_handle(strg_db, DATABASE_PATH);
	if (!handle)
		err("fail to create database handle");

	dbg("storage(%p) handle (%p)", strg_db, handle);
	return TRUE;
}

static gboolean __ps_context_create_context_hash()
{
	g_return_val_if_fail(contexts == NULL, FALSE);

	contexts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, __remove_context);
	if (contexts == NULL) {
		err("fail to create context hashtable");
		return FALSE;
	}

	dbg("context hashtable(%p)", contexts);
	return TRUE;
}

static gchar* __ps_context_create_path(char *profile_name, int svc_ctg_id)
{
	gchar **strv, *str, *path;

	strv = g_strsplit(profile_name, " ", 0);
	str = g_strjoinv("_", strv);
	path = g_strdup_printf("/context/%s_%d", str, svc_ctg_id);
	g_strfreev(strv);
	g_free(str);
	dbg("path (%s)", path);

	return path;
}

static gboolean __ps_context_create_co_context(gpointer object, GHashTable *property)
{
	GHashTableIter iter;
	gpointer key, value;
	PsContext *context = NULL;
	CoreObject *co_context = NULL;

	gchar *path = NULL;
	int profile_id = 0;
	gchar *profile_name = NULL;
	gchar *apn = NULL;
	int auth_type = 0;
	gchar *auth_id = NULL, *auth_pwd = NULL, *home_url = NULL, *proxy_addr = NULL;
	int pdp_protocol = 0, svc_ctg_id = 0;

	g_hash_table_iter_init(&iter, (GHashTable *) property);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		if (g_str_equal(key, "3") == TRUE) { /*Profile ID*/
			profile_id = atoi((const char*) value);
			dbg("profile id (%d)", profile_id);
		}
		else if (g_str_equal(key, "4") == TRUE) {
			profile_name = g_strdup((const char*) value);
			dbg("profile name (%s)", profile_name);
		}
		else if (g_str_equal(key, "5") == TRUE) {
			apn = g_strdup((const char*) value);
			dbg("APN (%s)", apn);
		}
		else if (g_str_equal(key, "6") == TRUE) {
			auth_type = atoi((const char*) value);
			dbg("auth type (%d)", auth_type);
		}
		else if (g_str_equal(key, "7") == TRUE) {
			auth_id = g_strdup((const char*) value);
			dbg("auth id (%s)", auth_id);
		}
		else if (g_str_equal(key, "8") == TRUE) {
			auth_pwd = g_strdup((const char*) value);
			dbg("auth pwd (%s)", auth_pwd);
		}
		else if (g_str_equal(key, "9") == TRUE) {
			proxy_addr = g_strdup((const char*) value);
			dbg("proxy addr (%s)", proxy_addr);
		}
		else if (g_str_equal(key, "10") == TRUE) {
			home_url = g_strdup((const char*) value);
			dbg("home url (%s)", home_url);
		}
		else if (g_str_equal(key, "11") == TRUE) {
			pdp_protocol = atoi((const char*) value);
			dbg("pdp protocol (%d)", pdp_protocol);
		}
		else if (g_str_equal(key, "21") == TRUE) {
			svc_ctg_id = atoi((const char*) value);
			dbg("context category type (%d)", svc_ctg_id);
		}
	}

	path = __ps_context_create_path(profile_name, svc_ctg_id);

	context = (PsContext *) object;
	co_context = tcore_context_new(context->plg, path, NULL);
	tcore_context_set_state(co_context, CONTEXT_STATE_DEACTIVATED);
	tcore_context_set_role(co_context, svc_ctg_id);
	tcore_context_set_apn(co_context, apn);
	tcore_context_set_auth(co_context, auth_type);
	tcore_context_set_username(co_context, auth_id);
	tcore_context_set_password(co_context, auth_pwd);
	tcore_context_set_proxy(co_context, proxy_addr);
	tcore_context_set_mmsurl(co_context, home_url);

	context->profile_id = profile_id;
	context->path = g_strdup(path);
	context->co_context = co_context;

	g_free(path);
	return TRUE;
}

static gpointer __ps_context_create_context(DBusGConnection *conn, TcorePlugin *p,
		gchar *mccmnc, GHashTable *property)
{
	guint rv = 0;
	GError *error = NULL;
	DBusGProxy *proxy;
	GObject *object = NULL;
	gchar *path = NULL;

	proxy = dbus_g_proxy_new_for_name(conn, "org.freedesktop.DBus", "/org/freedesktop/DBus",
			"org.freedesktop.DBus");

	if (!dbus_g_proxy_call(proxy, "RequestName", &error, G_TYPE_STRING, PS_DBUS_SERVICE,
			G_TYPE_UINT, 0, G_TYPE_INVALID, G_TYPE_UINT, &rv, G_TYPE_INVALID)) {
		err("Failed to acquire context(%s) error(%s)", PS_DBUS_SERVICE, error->message);
		return NULL;
	}

	object = g_object_new(PS_TYPE_CONTEXT, "conn", conn, "plg", p, "mccmnc", mccmnc);

	__ps_context_create_co_context(object, property);
	__ps_context_set_alwayson_enable(object, TRUE);
	path = _ps_context_ref_path(object);

	dbus_g_connection_register_g_object(conn, g_strdup(path), object);
	msg("context(%p) register dbus path(%s)", object, path);

	return object;
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
			tcore_context_set_apn(co_context, (const char *) value);
		}
		else if (g_str_equal(key, "auth_type") == TRUE) {
			int i_tmp = 0;
			i_tmp = atoi((const char *) value);
			tcore_context_set_auth(co_context, i_tmp);
		}
		else if (g_str_equal(key, "auth_id") == TRUE) {
			tcore_context_set_username(co_context, (const char *) value);
		}
		else if (g_str_equal(key, "auth_pwd") == TRUE) {
			tcore_context_set_password(co_context, (const char *) value);
		}
		else if (g_str_equal(key, "proxy_addr") == TRUE) {
			tcore_context_set_proxy(co_context, (const char *) value);
		}
		else if (g_str_equal(key, "home_url") == TRUE) {
			tcore_context_set_mmsurl(co_context, (const char *) value);
		}
	}

	return __ps_context_update_database(context);
}

static gboolean __ps_context_update_database(PsContext *context)
{
	gchar *s_id = NULL, *s_authtype = NULL;
	gchar *s_apn = NULL, *s_username = NULL, *s_pwd = NULL, *s_proxy = NULL, *s_mms = NULL;
	gboolean rv = FALSE;
	char szQuery[3000];

	GHashTable *in_param;
	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	strcpy(szQuery, " update pdp_profile set ");
	strcat(szQuery, " apn = ?, auth_type = ?, auth_id = ?, auth_pwd = ?, ");
	strcat(szQuery, " proxy_ip_addr = ?, home_url = ?");
	strcat(szQuery, " where profile_id = ?");

	s_id = g_strdup_printf("%d", context->profile_id);
	s_authtype = g_strdup_printf("%d", tcore_context_get_auth(context->co_context));

	s_apn = tcore_context_get_apn(context->co_context);
	s_username = tcore_context_get_username(context->co_context);
	s_pwd = tcore_context_get_password(context->co_context);
	s_proxy = tcore_context_get_proxy(context->co_context);
	s_mms = tcore_context_get_mmsurl(context->co_context);

	g_hash_table_insert(in_param, "1", g_strdup(s_apn));
	g_hash_table_insert(in_param, "2", g_strdup(s_authtype));
	g_hash_table_insert(in_param, "3", g_strdup(s_username));
	g_hash_table_insert(in_param, "4", g_strdup(s_pwd));
	g_hash_table_insert(in_param, "5", g_strdup(s_proxy));
	g_hash_table_insert(in_param, "6", g_strdup(s_mms));
	g_hash_table_insert(in_param, "7", g_strdup(s_id));

	rv = tcore_storage_update_query_database(strg_db, handle, szQuery, in_param);
	g_hash_table_destroy(in_param);

	g_free(s_id);
	g_free(s_authtype);
	g_free(s_apn);
	g_free(s_username);
	g_free(s_pwd);
	g_free(s_proxy);
	g_free(s_mms);

	return rv;
}

static gboolean __ps_context_remove_database(PsContext *context)
{
	gchar *s_id = NULL;
	gboolean rv = FALSE;
	char szQuery[1000];

	GHashTable *in_param;
	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	memset(szQuery, 0, sizeof(szQuery));
	strcpy(szQuery, " delete from pdp_profile where profile_id = ? ");

	s_id = g_strdup_printf("%d", context->profile_id);
	g_hash_table_insert(in_param, "1", g_strdup(s_id));

	rv = tcore_storage_remove_query_database(strg_db, handle, szQuery, in_param);
	g_free(s_id);
	g_hash_table_destroy(in_param);

	return rv;
}

static int __ps_context_insert_network_id_to_database(gchar *mccmnc)
{
	char szQuery[5000];
	int network_id = 0;
	gboolean rv = FALSE;
	gchar *insert_key = NULL;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
				(GDestroyNotify) g_hash_table_destroy);

	memset(szQuery, 0, sizeof(szQuery));
	strcpy(szQuery," select  max(network_info_id) from network_info ");

	tcore_storage_read_query_database(strg_db, handle, szQuery, NULL, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if(value){
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				if (g_str_equal(key, "0") == TRUE) {
					network_id = atoi((const char*) value2);
				}
			}
			break;
		}
	}

	g_hash_table_destroy(out_param);
	network_id++;


	memset(szQuery, 0, sizeof(szQuery));
	strcpy(szQuery," insert into network_info( network_info_id, network_name, mccmnc) values( ?, ?, ?) ");

	insert_key = g_strdup_printf("%d", network_id);
	g_hash_table_insert(in_param, "1", g_strdup(insert_key));
	g_hash_table_insert(in_param, "2", "TEMP_NETWORK");
	g_hash_table_insert(in_param, "3", g_strdup(mccmnc));

	rv = tcore_storage_insert_query_database(strg_db, handle, szQuery, in_param);
	if(!rv)
		return 0;

	g_free(insert_key);
	return network_id;
}

static int __ps_context_insert_profile_to_database(GHashTable *property, int network_id)
{
	int profile_id = 0;
	char szQuery[5000];

	gboolean rv = FALSE;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param;
	gchar *insert_key1 = NULL, *insert_key2 = NULL;
	gchar *profile_name=NULL, *apn=NULL, *auth_type=NULL, *auth_id = NULL, *auth_pwd = NULL;
	gchar *proxy_addr = NULL, *home_url = NULL, *svc_id = NULL;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	g_hash_table_iter_init(&iter, property);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {

		if (g_str_equal(key, "apn") == TRUE) {
			apn = g_strdup(value);
		}
		else if (g_str_equal(key, "auth_type") == TRUE) {
			auth_type = g_strdup(value);
		}
		else if (g_str_equal(key, "auth_id") == TRUE) {
			auth_id = g_strdup(value);
		}
		else if (g_str_equal(key, "auth_pwd") == TRUE) {
			auth_pwd = g_strdup(value);
		}
		else if (g_str_equal(key, "proxy_addr") == TRUE) {
			proxy_addr = g_strdup(value);
		}
		else if (g_str_equal(key, "home_url") == TRUE) {
			home_url = g_strdup(value);
		}
		else if (g_str_equal(key, "svc_ctg_id") == TRUE) {
			svc_id = g_strdup(value);
		}

	}

	dbg("apn (%s), auth_type (%s), auth_id(%s), auth_pwd(%s), proxy_addr(%s), home_url(%s), svc_id(%s)",
		apn, auth_type, auth_id, auth_pwd, proxy_addr, home_url, svc_id);

	profile_id = __ps_context_load_profile_id_from_database();
	if(profile_id <= 0){
		dbg("fail to get last profile id");
		return 0;
	}
	profile_id++;

	memset(szQuery, 0, sizeof(szQuery));
	strcpy(szQuery," insert into pdp_profile( ");
	strcat(szQuery," profile_id, transport_type, profile_name, apn, auth_type, auth_id, auth_pwd, ");
	strcat(szQuery," pdp_protocol, proxy_ip_addr, home_url, linger_time, is_secure_connection, app_protocol_type, ");
	strcat(szQuery," network_info_id, svc_category_id) values( ");
	strcat(szQuery," ?, 1, ? , ?, ?, ?, ?, ");//1,2,3,4,5,6
	strcat(szQuery," 1, ?, ?, 300, 0, 1, ");//7,8
	strcat(szQuery," ?, ? )");//9,10

	insert_key1 = g_strdup_printf("%d", profile_id);
	insert_key2 = g_strdup_printf("%d", network_id);
	profile_name = g_strdup_printf("tmp_profile%d", profile_id);

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

	rv = tcore_storage_insert_query_database(strg_db, handle, szQuery, in_param);
	g_hash_table_destroy(in_param);

	if(!rv)
		return 0;

	return profile_id;
}

static int __ps_context_load_network_id_from_database(gchar *mccmnc)
{
	char szQuery[5000];
	int network_id = 0;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;

	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	memset(szQuery, 0, sizeof(szQuery));
	strcpy(szQuery,"select network_info_id from network_info where mccmnc = ? ");

	g_hash_table_insert(in_param, "1", g_strdup(mccmnc));
	tcore_storage_read_query_database(strg_db, handle, szQuery, in_param, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if(value){
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				if (g_str_equal(key, "0") == TRUE) {
					network_id = atoi((const char*) value2);
				}
			}
			break;
		}
	}

	g_hash_table_destroy(in_param);
	g_hash_table_destroy(out_param);

	return network_id;
}

static int __ps_context_load_profile_id_from_database(void)
{
	char szQuery[5000];
	int profile_id = 0;
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *out_param;

	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	memset(szQuery, 0, sizeof(szQuery));
	strcpy(szQuery,"select max(profile_id) as last_profile from pdp_profile");

	tcore_storage_read_query_database(strg_db, handle, szQuery, NULL, out_param, 1);

	g_hash_table_iter_init(&iter, out_param);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		GHashTableIter iter2;
		gpointer key2, value2;

		if(value){
			g_hash_table_iter_init(&iter2, (GHashTable *) value);
			while (g_hash_table_iter_next(&iter2, &key2, &value2) == TRUE) {
				if (g_str_equal(key, "0") == TRUE) {
					profile_id = atoi((const char*) value2);
				}
			}
			break;
		}
	}

	g_hash_table_destroy(out_param);
	return profile_id;
}

static gboolean __ps_context_reset_database(void)
{
	int rv = 0;
	gchar *extract_sql, *recover_sql, *remove_tmp;

	extract_sql = g_strdup("tar --extract --file=/opt/system/customer_selected/preconfig/customer.tar.gz opt/dbspace/.dnet.db -C /tmp");
	dbg("system extract command (%s)", extract_sql);
	rv = system(extract_sql);

	recover_sql = g_strdup("sqlite3 /opt/dbspace/.dnet.db \"attach database '/tmp/opt/dbspace/.dnet.db' as csc; replace into pdp_profile select * from csc.pdp_profile;\" ");
	dbg("system recover db command (%s)", recover_sql);
	rv = system(recover_sql);

	remove_tmp = g_strdup("rm -rf /tmp/opt/dbspace/.dnet.db");
	dbg("system recover db command (%s)", remove_tmp);
	rv = system(remove_tmp);

	g_free(extract_sql);
	g_free(recover_sql);
	g_free(remove_tmp);

	return TRUE;
}

static int __ps_context_get_network_id(gchar *mccmnc)
{
	int network_id;

	network_id = __ps_context_load_network_id_from_database(mccmnc);
	if(network_id > 0)
		return network_id;

	network_id = __ps_context_insert_network_id_to_database(mccmnc);
	if(network_id <= 0 )
		return -1;

	return network_id;
}

static gboolean __ps_context_get_profile_properties(gpointer object, GHashTable *properties)
{
	gchar *s_authtype = NULL, *s_role = NULL;
	PsContext *context = NULL;

	g_return_val_if_fail(object != NULL, FALSE);
	g_return_val_if_fail(properties != NULL, FALSE);

	context = (PsContext *) object;
	dbg("get profile properties");

	s_authtype = g_strdup_printf("%d", tcore_context_get_auth(context->co_context));
	s_role = g_strdup_printf("%d", tcore_context_get_role(context->co_context));

	g_hash_table_insert(properties, "path", g_strdup(context->path));
	g_hash_table_insert(properties, "apn", tcore_context_get_apn(context->co_context));
	g_hash_table_insert(properties, "auth_type", g_strdup(s_authtype));
	g_hash_table_insert(properties, "auth_id", tcore_context_get_username(context->co_context));
	g_hash_table_insert(properties, "auth_pwd", tcore_context_get_password(context->co_context));
	g_hash_table_insert(properties, "proxy_addr", tcore_context_get_proxy(context->co_context));
	g_hash_table_insert(properties, "home_url", tcore_context_get_mmsurl(context->co_context));
	g_hash_table_insert(properties, "svc_ctg_id", g_strdup(s_role));

	g_free(s_authtype);
	g_free(s_role);

	return TRUE;
}

static gboolean __ps_context_set_alwayson_enable(gpointer object, gboolean enabled)
{
	PsContext *context = object;
	int role = CONTEXT_ROLE_UNKNOWN;
	g_return_val_if_fail(context != NULL, FALSE);

	role = tcore_context_get_role(context->co_context);
	if(role == CONTEXT_ROLE_INTERNET){
		context->alwayson = enabled;
	}

	return TRUE;
}

static gpointer __ps_context_add_context(gpointer modem, gchar *mccmnc, int profile_id)
{
	char szQuery[5000];
	DBusGConnection *conn = NULL;
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

	memset(szQuery, '\0', 5000);
	strcpy(szQuery, "select");
	strcat(szQuery, " a.network_info_id, a.network_name, a.mccmnc,"); //0 , 1, 2
	strcat(szQuery, " b.profile_id, b.profile_name, b.apn, "); //3, 4, 5
	strcat(szQuery, " b.auth_type, b.auth_id, b.auth_pwd,"); //6, 7, 8
	strcat(szQuery, " b.proxy_ip_addr, b.home_url, b.pdp_protocol, "); //9, 10 , 11
	strcat(szQuery, " b.linger_time, b.is_secure_connection, b.app_protocol_type, b.traffic_class,"); //12, 13, 14, 15
	strcat(szQuery, " b.is_static_ip_addr, b.ip_addr, b.is_static_dns_addr, b.dns_addr1, b.dns_addr2, b.svc_category_id"); //16,17, 18, 19, 20, 21
	strcat(szQuery, " from network_info a, pdp_profile b");
	strcat(szQuery, " where b.profile_id = ? and a.network_info_id = b.network_info_id ");

	insert_key1 = g_strdup_printf("%d", profile_id);
	g_hash_table_insert(in_param, "1", g_strdup(insert_key1));
	tcore_storage_read_query_database(strg_db, handle, szQuery, in_param, out_param, 22);

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

gboolean _ps_context_reset_hashtable(void)
{
	if(!contexts)
		return TRUE;

	g_hash_table_foreach_remove(contexts, __remove_contexts, NULL);
	__ps_context_reset_database();
	return TRUE;
}

GHashTable* _ps_context_create_hashtable(DBusGConnection *conn, TcorePlugin *p, gchar *mccmnc)
{
	char szQuery[5000];
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *in_param, *out_param;
	in_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	out_param = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	dbg("create profile by mccmnc (%s)", mccmnc);

	memset(szQuery, '\0', 5000);
	strcpy(szQuery, "select");
	strcat(szQuery, " a.network_info_id, a.network_name, a.mccmnc,"); //0 , 1, 2
	strcat(szQuery, " b.profile_id, b.profile_name, b.apn, "); //3, 4, 5
	strcat(szQuery, " b.auth_type, b.auth_id, b.auth_pwd,"); //6, 7, 8
	strcat(szQuery, " b.proxy_ip_addr, b.home_url, b.pdp_protocol, "); //9, 10 , 11
	strcat(szQuery, " b.linger_time, b.is_secure_connection, b.app_protocol_type, b.traffic_class,"); //12, 13, 14, 15
	strcat(szQuery, " b.is_static_ip_addr, b.ip_addr, b.is_static_dns_addr, b.dns_addr1, b.dns_addr2, b.svc_category_id"); //16,17, 18, 19, 20, 21
	strcat(szQuery, " from network_info a, pdp_profile b");
	strcat(szQuery, " where a.mccmnc= ? and a.network_info_id = b.network_info_id ");

	g_hash_table_insert(in_param, "1", g_strdup(mccmnc));
	tcore_storage_read_query_database(strg_db, handle, szQuery, in_param, out_param, 22);

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

	return contexts;
}

GHashTable* _ps_context_ref_hashtable(void)
{
	g_return_val_if_fail(contexts != NULL, NULL);
	return contexts;
}

gboolean _ps_context_add_context(gpointer modem, gchar *operator, GHashTable *property)
{
	GHashTable *services = NULL;
	gpointer context = NULL;

	GHashTableIter iter;
	gpointer key, value;
	int network_id = 0;
	int profile_id = 0;

	network_id = __ps_context_get_network_id(operator);
	if(network_id <= 0){
		dbg("fail to add network info");
		return FALSE;
	}

	profile_id = __ps_context_insert_profile_to_database(property, network_id);
	if(profile_id <= 0){
		dbg("fail to insert profile info to database");
		return FALSE;
	}

	context = __ps_context_add_context(modem, operator, profile_id);
	if(!context)
		return FALSE;

	services = _ps_modem_ref_services(modem);
	if(!services)
		return FALSE;

	g_hash_table_iter_init(&iter, services);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		_ps_service_ref_context(value, context);
	}

	return TRUE;
}

gboolean _ps_context_get_properties(gpointer object, GHashTable *properties)
{
	int context_state = 0;
	gboolean active = FALSE;
	PsContext *context = object;

	dbg("get context properties");
	g_return_val_if_fail(context != NULL, FALSE);
	g_return_val_if_fail(properties != NULL, FALSE);

	context_state =    tcore_context_get_state(context->co_context);
	if (context_state == CONTEXT_STATE_ACTIVATED)
		active = TRUE;

	g_hash_table_insert(properties, "path", g_strdup(context->path));
	g_hash_table_insert(properties, "active", g_strdup(BOOL2STRING(active)));
	g_hash_table_insert(properties, "ipv4_address", tcore_context_get_ipv4_addr(context->co_context));
	g_hash_table_insert(properties, "ipv4_gateway", tcore_context_get_ipv4_gw(context->co_context));
	g_hash_table_insert(properties, "ipv4_dns1", tcore_context_get_ipv4_dns1(context->co_context));
	g_hash_table_insert(properties, "ipv4_dns2", tcore_context_get_ipv4_dns2(context->co_context));
	g_hash_table_insert(properties, "ipv6_address", "::" );
	g_hash_table_insert(properties, "ipv6_gateway", "::" );
	g_hash_table_insert(properties, "ipv6_dns1", "::" );
	g_hash_table_insert(properties, "ipv6_dns2", "::" );
	g_hash_table_insert(properties, "proxy", tcore_context_get_proxy(context->co_context));
	g_hash_table_insert(properties, "dev_name", tcore_context_get_ipv4_devname(context->co_context));

	return TRUE;
}

gboolean _ps_context_set_service(gpointer object, gpointer service)
{
	PsContext *context = object;
	g_return_val_if_fail(context != NULL, FALSE);

	context->p_service = service;
	return TRUE;
}

gpointer _ps_context_ref_service(gpointer object)
{
	PsContext *context = object;
	g_return_val_if_fail(context != NULL, FALSE);

	return context->p_service;
}

gchar* _ps_context_ref_path(gpointer object)
{
	PsContext *context = object;
	g_return_val_if_fail(context != NULL, NULL);

	return context->path;
}

gboolean _ps_context_get_alwayson_enable(gpointer object)
{
	PsContext *context = object;
	g_return_val_if_fail(context != NULL, FALSE);

	return context->alwayson;
}

gpointer _ps_context_ref_co_context(gpointer object)
{
	PsContext *context = object;
	g_return_val_if_fail(context != NULL, NULL);

	return context->co_context;
}

gboolean _ps_context_set_connected(gpointer object, gboolean enabled)
{
	gchar *ipv4 = NULL;
	PsContext *context = object;
	g_return_val_if_fail(context != NULL, FALSE);


	ipv4 = tcore_context_get_ipv4_addr(context->co_context);

	if (enabled) {

		tcore_context_set_state(context->co_context, CONTEXT_STATE_ACTIVATED);
		if( g_str_equal(ipv4, "0.0.0.0") == TRUE ){
			dbg("ip address is 0.0.0.0");
			_ps_service_deactivate_context(context->p_service, context);
			return TRUE;
		}
		_ps_service_reset_connection_timer(context);

	}
	else {
		tcore_context_set_state(context->co_context, CONTEXT_STATE_DEACTIVATED);
		tcore_context_reset_devinfo(context->co_context);
		_ps_service_connection_timer(context->p_service, context);
	}

	__ps_context_emit_property_changed_signal(context);
	g_free(ipv4);
	return TRUE;
}
