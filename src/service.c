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

#include <core_object.h>
#include <co_ps.h>
#include <co_context.h>


#define PROP_DEFAULT	FALSE
#define PROP_DEFAULT_STR   NULL
#define BOOL2STRING(a)	((a == TRUE) ? ("TRUE"):("FALSE"))

#define TIMEOUT_DEFAULT		5
#define TIMEOUT_MAX			1280

guint connection_timeout;
guint timer_src;

static void __ps_service_emit_property_changed_signal(PsService *service);
static void __ps_service_emit_context_added_signal(PsService *service, gpointer context);
static void __ps_service_emit_context_removed_signal(PsService *service, gpointer context);
static void _ps_service_setup_interface(PacketServiceService *service, PsService *service_data);

static char *__ps_service_act2string(TelNetworkAct act);
static gboolean __ps_service_check_connection_option(gpointer service, gpointer context);
static gboolean __ps_service_connetion_timeout_handler(gpointer user_data);

void __remove_service_handler(gpointer data)
{
	PsService *service = data;

	dbg("Entered");
	if (!service) {
		dbg("Service is Null");
		return;
	}

	/*Need to remove the compelete hash table*/
	g_hash_table_remove_all(service->contexts);

	/*Need to UNexport and Unref the master Object */
	if (service->if_obj) {
		g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(service->if_obj));
		g_object_unref(service->if_obj);
		service->if_obj = NULL;
	}

	/*Need to free the memory of the internal structure*/
	g_free(service->path);
	g_free(service);
}

static void __ps_service_emit_property_changed_signal(PsService *service)
{
	GVariant *gv = NULL;
	GVariantBuilder property;

	dbg("get service properties");

	gv = _ps_service_get_properties(service, &property);
	packet_service_service_emit_property_changed(service->if_obj, gv);

	dbg("Exiting");
}

static void __ps_service_emit_context_added_signal(PsService *service, gpointer context)
{
	GVariant *gv = NULL;
	GVariantBuilder property;

	dbg("get service properties");

	gv = _ps_context_get_properties(context, &property);
	packet_service_service_emit_context_added(service->if_obj, gv);

	dbg("Exiting");
}

static void __ps_service_emit_context_removed_signal(PsService *service, gpointer context)
{
	PsContext *pscontext = context;

	dbg("Entered");
	packet_service_service_emit_context_removed(service->if_obj, pscontext->path);

	dbg("Exiting");
}

static char *__ps_service_act2string(TelNetworkAct act)
{
	switch (act) {
		case TEL_NETWORK_ACT_GSM:
		case TEL_NETWORK_ACT_GPRS:
		case TEL_NETWORK_ACT_EGPRS:
		case TEL_NETWORK_ACT_UMTS:
		case TEL_NETWORK_ACT_GSM_AND_UMTS:
			return "GSM";
		case TEL_NETWORK_ACT_LTE:
			return "LTE";
		case TEL_NETWORK_ACT_UNKNOWN:
		default:
			return "unknown";
	}

	return NULL;
}

static gboolean __ps_service_check_connection_option(gpointer object, gpointer context)
{
	gboolean b_connect = TRUE;
	gboolean power, sim, data, flight;


	PsService *service = object;

	power = _ps_modem_get_power(service->p_modem);
	sim = _ps_modem_get_sim_init(service->p_modem);
	data = _ps_modem_get_data_allowed(service->p_modem);
	flight = _ps_modem_get_flght_mode(service->p_modem);
	b_connect &= power;
	b_connect &= sim;
	b_connect &= data;
	b_connect &= !flight;
	b_connect &= !service->restricted;

	dbg("power(%d), sim init(%d), data allowed(%d), flight mode(%d) ",
		power, sim, data, flight);

	return b_connect;
}

static gboolean __ps_service_connetion_timeout_handler(gpointer context)
{
	gint rv = 0;
	PsService *service = NULL;

	service = _ps_context_ref_service(context);
	rv = _ps_service_activate_context(service, context);
	dbg("return rv(%d)", rv);

	return FALSE;
}

gpointer _ps_service_create_service(GDBusConnection *conn, TcorePlugin *p, gpointer p_modem,
		CoreObject *co_network, CoreObject *co_ps, gchar* path)
{
	PacketServiceService *service;
	GError *error = NULL;
	PsService *new_service;

	dbg("service object create");
	tcore_check_return_value(conn != NULL, NULL);
	tcore_check_return_value(p_modem != NULL, NULL);

	/*creating the master object for the interface com.tcore.ps.modem*/
	service = packet_service_service_skeleton_new();

	/*Initializing the modem list for internal referencing*/
	new_service = g_try_malloc0(sizeof(PsService));
	if (NULL == new_service) {
		err("Unable to allocate memory for master");
		goto FAILURE;
	}

	new_service->conn = conn;
	new_service->plg = p;
	new_service->p_modem = p_modem;
	new_service->co_network = co_network;
	new_service->co_ps = co_ps;
	new_service->path = g_strdup(path);
	new_service->if_obj = service;
	new_service->contexts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	_ps_hook_co_network_event(new_service);
	_ps_get_co_network_values(new_service);
	_ps_hook_co_ps_event(new_service);

	/*Setting up the interface for the service */
	_ps_service_setup_interface(service, new_service);

	/*exporting the interface object to the path mention for master*/
	g_dbus_interface_skeleton_export((G_DBUS_INTERFACE_SKELETON(service)),
			conn,
			path,
			&error);

	g_assert_no_error (error);

	connection_timeout = TIMEOUT_DEFAULT;
	dbg("Successfully Created the service");
	return new_service;

FAILURE:
	/*To Do: Handle failure case*/
	return NULL;
}

gboolean _ps_service_ref_context(gpointer object, gpointer context)
{
	gpointer tmp = NULL;
	gchar *s_path = NULL;
	PsService *service = object;

	dbg("service refer to context");
	tcore_check_return_value(service != NULL, FALSE);

	s_path = _ps_context_ref_path(context);
	tmp = g_hash_table_lookup(service->contexts, s_path);
	if (tmp != NULL) {
		dbg("context(%p) already existed", tmp);
		return FALSE;
	}

	/* Setting service */
	_ps_context_set_service(context, service);

	/* Add Context to PS Core object */
	tcore_ps_add_context(service->co_ps, (CoreObject *) _ps_context_ref_co_context(context));

	/* Insert conetxt to Hash Table */
	g_hash_table_insert(service->contexts, g_strdup(s_path), context);

	dbg("context(%p) insert to hash", context);

	/* Emit Context added signal */
	__ps_service_emit_context_added_signal(service, context);

	//_ps_service_connect_default_context(service);
	return TRUE;
}

gboolean _ps_service_ref_contexts(gpointer object, GHashTable *contexts, gchar *operator)
{
	GHashTableIter iter;
	gpointer key, value;
	PsService *service = object;
	gboolean ret = TRUE;
	gint rv;

	dbg("service refer to contexts");
	tcore_check_return_value(service != NULL, FALSE);

	g_hash_table_iter_init(&iter, contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *s_path = NULL;
		gpointer tmp = NULL;
		gboolean f_awo = FALSE;

		s_path = _ps_context_ref_path(value);
		dbg("Path: [%s]", s_path);

		/* Hash lookup */
		tmp = g_hash_table_lookup(service->contexts, s_path);
		if (tmp != NULL) {
			dbg("context(%p) already existed", tmp);
			continue;
		}

		/* Setting service */
		_ps_context_set_service(value, service);

		/* Add Context to PS Core object */
		tcore_ps_add_context(service->co_ps, (CoreObject *) _ps_context_ref_co_context(value));

		/* Insert context to Service  Hash Table */
		g_hash_table_insert(service->contexts, g_strdup(s_path), value);

		dbg("Inserted context to Hash table - context [%p]", value);

		/* Emit Context added signal */
		__ps_service_emit_context_added_signal(service, value);

		f_awo = _ps_context_get_alwayson_enable(value);
		if (f_awo) {
			rv = _ps_service_define_context(service, value);
			dbg("return rv(%d)", rv);
		}
	}

	/* Update cellular state key */
	_ps_update_cellular_state_key(service);

	return ret;
}

gboolean _ps_service_unref_context(gpointer object, gpointer context)
{
	PsService *service = object;

	dbg("service unref contexts");
	tcore_check_return_value(service != NULL, FALSE);
	tcore_check_return_value(context != NULL, FALSE);

	dbg("remove context(%p) from service(%p)", context, service);

	/* Remove Context from PS Core object */
	tcore_ps_remove_context(service->co_ps, (CoreObject *) _ps_context_ref_co_context(context));

	/* Remove context to Hash Table */
	g_hash_table_remove(service->contexts, _ps_context_ref_path(context));

	/* Emit Context Remove signal */
	__ps_service_emit_context_removed_signal(service, context);

	return TRUE;
}

gboolean _ps_service_get_properties_handler(gpointer object, GVariantBuilder *properties)
{
	PsService *service = object;

	dbg("get service properties");
	tcore_check_return_value(service != NULL, FALSE);
	tcore_check_return_value(properties != NULL, FALSE);

	g_variant_builder_open(properties, G_VARIANT_TYPE("a{ss}"));
	g_variant_builder_add(properties, "{ss}", "path", g_strdup(service->path));
	g_variant_builder_add(properties, "{ss}", "ps_attached", g_strdup(BOOL2STRING(service->ps_attached)));
	g_variant_builder_add(properties, "{ss}", "roaming", g_strdup(BOOL2STRING(service->roaming)));
	g_variant_builder_add(properties, "{ss}", "act", g_strdup(__ps_service_act2string(service->act)));
	g_variant_builder_close(properties);

	return TRUE;
}

GVariant * _ps_service_get_properties(gpointer object, GVariantBuilder *properties)
{
	PsService *service = object;

	dbg("get service properties");
	tcore_check_return_value(service != NULL, FALSE);
	tcore_check_return_value(properties != NULL, FALSE);

	g_variant_builder_init(properties, G_VARIANT_TYPE("a{ss}"));

	g_variant_builder_add(properties, "{ss}", "path", g_strdup(service->path));
	g_variant_builder_add(properties, "{ss}", "ps_attached", g_strdup(BOOL2STRING(service->ps_attached)));
	g_variant_builder_add(properties, "{ss}", "roaming", g_strdup(BOOL2STRING(service->roaming)));
	g_variant_builder_add(properties, "{ss}", "act", g_strdup(__ps_service_act2string(service->act)));

	return g_variant_builder_end(properties);
}

gchar* _ps_service_ref_path(gpointer object)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, NULL);

	return service->path;
}

gpointer _ps_service_ref_plugin(gpointer object)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, NULL);

	return service->plg;
}

gpointer _ps_service_ref_co_network(gpointer object)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, NULL);

	return service->co_network;
}

gpointer _ps_service_ref_co_ps(gpointer object)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, NULL);

	return service->co_ps;
}

gpointer _ps_service_ref_modem(gpointer object)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, NULL);

	return service->p_modem;
}

gboolean _ps_service_set_context_info(gpointer object, TcorePsPdpIpConf *devinfo)
{
	GSList* contexts = NULL;
	PsService *service = object;

	dbg("Set context information");

	tcore_check_return_value(service != NULL, FALSE);

	/* Refer context */
	dbg("Context ID: [%d]", devinfo->context_id);
	tcore_ps_ref_context_by_id(service->co_ps, devinfo->context_id, &contexts);
	if (NULL == contexts) {
		err("Failed to refer context");
		return FALSE;
	}

	for (; contexts != NULL; contexts = g_slist_next(contexts)) {
		CoreObject *co_context = NULL;

		co_context = contexts->data;
		if (NULL == co_context) {
			err("Context is NULL");
			continue;
		}

		/* Set device information */
		tcore_context_set_devinfo(co_context, devinfo);
	}

	return TRUE;
}

gint _ps_service_define_context(gpointer object, gpointer context)
{
	PsService *service = object;
	CoreObject *co_context = NULL;
	gboolean b_connect = TRUE;
	TelReturn ret;

	dbg("define context(%p)", context);
	tcore_check_return_value(service != NULL, TEL_RETURN_FAILURE);

	co_context = (CoreObject *)_ps_context_ref_co_context(context);

	b_connect = __ps_service_check_connection_option(service, co_context);
	if (!b_connect) {
		return TEL_RETURN_FAILURE;

	}

	ret = tcore_plugin_dispatch_request(tcore_object_ref_plugin(service->co_ps), TRUE,
		TCORE_COMMAND_PS_DEFINE_CONTEXT,
		&co_context, sizeof(CoreObject *),
		NULL, NULL);

	return ret;
}

gint _ps_service_activate_context(gpointer object, gpointer context)
{
	PsService *service = object;
	CoreObject *co_context = NULL;
	gboolean b_connect = TRUE;
	gboolean ps_defined;
	gint ret = TEL_RETURN_FAILURE;

	dbg("Activate context [0x%x]", context);
	tcore_check_return_value(service != NULL, TEL_RETURN_INVALID_PARAMETER);

	co_context = (CoreObject *)_ps_context_ref_co_context(context);

	b_connect = __ps_service_check_connection_option(service, co_context);
	if (!b_connect) {
		err("Connection option failed");
		return TEL_RETURN_FAILURE;
	}

	ps_defined = _ps_context_get_ps_defined(context);
	if (!ps_defined) {
		dbg("PDP profile is NOT defined!!! Need to define it first... co_context: [%p]");
		ret = tcore_plugin_dispatch_request(tcore_object_ref_plugin(service->co_ps), TRUE,
			TCORE_COMMAND_PS_DEFINE_CONTEXT,
			&co_context, sizeof(CoreObject *),
			NULL, NULL);
	} else {
		dbg("PDP profile is defined!!! Activate context...");
		ret = tcore_plugin_dispatch_request(tcore_object_ref_plugin(service->co_ps), TRUE,
			TCORE_COMMAND_PS_ACTIVATE_CONTEXT,
			&co_context, sizeof(CoreObject *),
			NULL, NULL);
	}

	return ret;
}

gint _ps_service_deactivate_context(gpointer object, gpointer context)
{
	PsService *service = object;
	CoreObject *co_context = NULL;
	TelReturn ret = TEL_RETURN_FAILURE ;

	dbg("deactivate context(%p)", context);
	tcore_check_return_value(service != NULL, TEL_RETURN_INVALID_PARAMETER);

	co_context = (CoreObject *)_ps_context_ref_co_context(context);
	ret = tcore_plugin_dispatch_request(tcore_object_ref_plugin(service->co_ps), TRUE,
		TCORE_COMMAND_PS_DEACTIVATE_CONTEXT,
		&co_context, sizeof(CoreObject *),
		NULL, NULL);

	return ret;
}

void _ps_service_set_retry_timeout_value(int value)
{
	connection_timeout = value;
	dbg("current timeout (%d)", connection_timeout);
}

void _ps_service_connection_timer(gpointer object, gpointer context)
{
	gboolean f_awo = FALSE;

	f_awo = _ps_context_get_alwayson_enable(context);
	if (!f_awo)
		return;

	if (timer_src != 0) {
		dbg("remove connection retry timer (%d)", timer_src);
		g_source_remove(timer_src);
		timer_src = 0;
	}

	timer_src = g_timeout_add_seconds(connection_timeout, __ps_service_connetion_timeout_handler, context);

	dbg("cellular service timer started timer src(%d), timeout(%d)", timer_src, connection_timeout);
	connection_timeout = connection_timeout*2;
	if (connection_timeout >= TIMEOUT_MAX)
		connection_timeout = TIMEOUT_DEFAULT;
}

void _ps_service_reset_connection_timer(gpointer context)
{
	gboolean f_awo = FALSE;

	f_awo = _ps_context_get_alwayson_enable(context);
	dbg("Always ON: [%s]", (f_awo ? "YES" : "NO"));
	if(f_awo == FALSE)
		return;

	connection_timeout = TIMEOUT_DEFAULT;

	if (timer_src != 0) {
		dbg("Remove connection Retry timer [%d]", timer_src);

		g_source_remove(timer_src);
		timer_src = 0;
	}
}

void _ps_service_remove_contexts(gpointer object)
{
	GHashTableIter iter;
	gpointer key, value;
	PsService *service = object;

	dbg("service remove all contexts");
	tcore_check_return(service != NULL);

	g_hash_table_iter_init(&iter, service->contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gpointer co_context = NULL;

		dbg("key(%s), value(%p) context", key, value);
		co_context = _ps_context_ref_co_context(value);

		_ps_service_reset_connection_timer(value);
		_ps_context_set_alwayson_enable(value, FALSE);
		_ps_service_deactivate_context(service, value);
		_ps_context_set_connected(value, FALSE);
		tcore_ps_remove_context(service->co_ps, co_context);
		tcore_context_free(co_context);

		__ps_service_emit_context_removed_signal(service, value);
		_ps_context_remove_context(value);
	}

	g_hash_table_remove_all(service->contexts);
}

void _ps_service_disconnect_contexts(gpointer object)
{
	GHashTableIter iter;
	gpointer key, value;
	PsService *service = object;

	dbg("service disconnect all contexts");
	tcore_check_return(service != NULL);

	g_hash_table_iter_init(&iter, service->contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		_ps_service_reset_connection_timer(value);
		_ps_service_deactivate_context(service, value);
	}
}

gint _ps_service_connect_default_context(gpointer object)
{
	gint rv = TEL_RETURN_FAILURE;
	GHashTableIter iter;
	gpointer key, value;
	PsService *service = object;

	dbg("service connect default context");
	tcore_check_return_value(service != NULL, TEL_RETURN_INVALID_PARAMETER);

	g_hash_table_iter_init(&iter, service->contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gboolean f_awo = FALSE;
		f_awo = _ps_context_get_alwayson_enable(value);

		if (f_awo) {
			_ps_service_reset_connection_timer(value);

			/* Activate Context */
			rv = _ps_service_activate_context(service, value);
			dbg("return rv(%d)", rv);
			break;
		}
	}

	return rv;
}

gpointer _ps_service_return_default_context(gpointer object)
{
	GHashTableIter iter;
	gpointer key, value;
	PsService *service = object;

	tcore_check_return_value(service != NULL, NULL);

	g_hash_table_iter_init(&iter, service->contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gboolean b_default = FALSE;
		b_default = _ps_context_get_default_internet(value);

		if (b_default) {
			return value;
		}
	}

	return NULL;
}

gboolean _ps_service_processing_network_event(gpointer object, gboolean ps_attached, gboolean roaming)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, FALSE);

	_ps_service_set_ps_attached(service, ps_attached);
	_ps_update_cellular_state_key(service);
	if (service->roaming != roaming) {
		gboolean roaming_allowed = FALSE;
		_ps_service_set_roaming(service, roaming);
		roaming_allowed = _ps_modem_get_data_roaming_allowed(service->p_modem);
		if (!roaming_allowed && roaming) {
			dbg("Roaming allowed (%d), Roaming status (%d)", roaming_allowed, roaming);
			_ps_service_disconnect_contexts(service);
			return TRUE;
		}
	}

	if (service->ps_attached)
		_ps_service_connect_default_context(service);

	return TRUE;
}

gboolean _ps_service_set_connected(gpointer object, gint context_id, gboolean enabled)
{
	GHashTableIter iter;
	gpointer key, value;

	PsService *service = NULL;

	service = (PsService *) object;
	g_hash_table_iter_init(&iter, service->contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		guint tmp_cid;
		CoreObject *context = NULL;

		context = _ps_context_ref_co_context(value);
		tcore_context_get_id(context, &tmp_cid);

		if (tmp_cid != (guint)context_id) continue;

		if (!enabled) {
			dbg("Reset socket connections.");
			tcore_ps_clear_context_id(service->co_ps, context);
		}

		_ps_context_set_connected(value, enabled);
	}

	return TRUE;
}

void _ps_service_set_ps_defined(gpointer *object, gboolean value, int cid)
{
	PsService *service = (PsService*)object;
	GHashTableIter iter;
	gpointer key, out;

	tcore_check_return(service != NULL);

	g_hash_table_iter_init(&iter, service->contexts);
	while (g_hash_table_iter_next(&iter, &key, &out) == TRUE) {
		gboolean r_actvate = 0;
		r_actvate = _ps_context_set_ps_defined(out, value, cid);
		r_actvate &= value;
		if (r_actvate) {
			int rv;
			dbg("define is complete, activate context for cid(%d)", cid);
			rv = _ps_service_activate_context(service, out);
			dbg("rv(%d)", rv);
			break;
		}
	}
}

gboolean _ps_service_set_ps_attached(gpointer object, gboolean value)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, FALSE);

	service->ps_attached = value;
	dbg("service(%p) ps_attached(%d)", service, service->ps_attached);

	return TRUE;
}

gboolean _ps_service_get_restricted(gpointer object)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, FALSE);

	return service->restricted;
}

gboolean _ps_service_set_restricted(gpointer object, gboolean value)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, FALSE);

	service->restricted = value;
	dbg("service(%p) restricted(%d)", service, service->restricted);

	_ps_update_cellular_state_key(service);
	return TRUE;
}

#if 0
gboolean _ps_service_set_number_of_pdn_cnt(gpointer object, gchar *operator)
{
	int rv = 0;
	int num_of_pdn = 0;
	PsService *service = object;
	tcore_check_return_value(service != NULL, FALSE);
	dbg("Entered");
	num_of_pdn = _ps_context_get_number_of_pdn(operator);
	rv = tcore_ps_set_num_of_pdn(service->co_ps, num_of_pdn);

	if (rv != TEL_RETURN_SUCCESS) {
		dbg("error to get maximum number of pdn");
	}
	dbg("Exiting");
	return TRUE;
}
#endif

gboolean _ps_service_get_roaming(gpointer object)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, FALSE);

	return service->roaming;
}

gboolean _ps_service_set_roaming(gpointer object, gboolean value)
{
	PsService *service = object;
	tcore_check_return_value(service != NULL, FALSE);

	service->roaming = value;
	dbg("service(%p) roaming(%d)", service, service->roaming);
	__ps_service_emit_property_changed_signal(service);

	return TRUE;
}

static void _indicator_cb_dns_reply(GObject *src, GAsyncResult *res, gpointer user_data)
{
	GList *list, *cur;
	GInetAddress *addr;
	gchar *str_addr;
	GError *error = NULL;

	list = g_resolver_lookup_by_name_finish((GResolver *)src, res, &error);
	if (!list) {
		dbg("fail to get dns resolving");
		if (error) {
			dbg ("error:%d, %s", error->code, error->message);
			g_error_free (error);
		}
		return;
	}

	for (cur = list; cur; cur = cur->next) {
		addr = cur->data;
		str_addr = g_inet_address_to_string(addr);
		if (!str_addr)
			continue;
		dbg("addr(%s)", str_addr);

		g_free(str_addr);
		g_object_unref(cur->data);
		break;
	}

	g_object_unref(src);
	g_list_free(list);
}

gboolean _ps_service_set_access_technology(gpointer object,
		TelNetworkAct value)
{
	PsService *service = object;
	TelNetworkAct p_act = 0;
	tcore_check_return_value(service != NULL, FALSE);

	p_act = service->act;
	service->act = value;
	dbg("service(%p) P ACT(%d) Access Technology(%d)", service, p_act, service->act);

	if (p_act == TEL_NETWORK_ACT_LTE
			&& (service->act >= TEL_NETWORK_ACT_GSM
			&& service->act < TEL_NETWORK_ACT_LTE)) {
		GResolver *r = NULL;

		dbg("send the dns pkt for keeping connection");

		r = g_resolver_get_default();
		g_resolver_lookup_by_name_async(r, "www.google.com", NULL, _indicator_cb_dns_reply, NULL);
	}

	if (service->act > TEL_NETWORK_ACT_UNKNOWN) {
		_ps_update_cellular_state_key(service);
		_ps_service_connect_default_context(service);
	}

	return TRUE;
}

TcorePsState _ps_service_check_cellular_state(gpointer object)
{
	gboolean state = FALSE;
	PsService *service = object;
	tcore_check_return_value(service != NULL, TCORE_PS_STATE_NO_SERVICE);

	state = _ps_modem_get_power(service->p_modem);
	if (!state) {
		dbg("NO SERVICE");
		return TCORE_PS_STATE_NO_SERVICE;
	}

	state = _ps_modem_get_sim_init(service->p_modem);
	if (!state) {
		dbg("NO SERVICE");
		return TCORE_PS_STATE_NO_SERVICE;
	}

	state = _ps_modem_get_flght_mode(service->p_modem);
	if (state) {
		dbg("FLIGHT MODE ON");
		return TCORE_PS_STATE_FLIGHT_MODE;
	}

	if (!service->ps_attached) {
		dbg("NO SERVICE");
		return TCORE_PS_STATE_NO_SERVICE;
	}

	state = _ps_modem_get_data_allowed(service->p_modem);
	if (!state) {
		dbg("DATA OFF");
		return TCORE_PS_STATE_3G_OFF;
	}

	state = _ps_modem_get_data_roaming_allowed(service->p_modem);
	if (service->roaming && !state) {
		dbg("DATA ROAMING OFF");
		return TCORE_PS_STATE_ROAMING_OFF;
	}

	return TCORE_PS_STATE_ON;
}
static gboolean on_service_get_properties (PacketServiceService *obj_service,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	GVariant *gv = NULL;
	GVariantBuilder property;
	dbg("get service properties");

	gv = _ps_service_get_properties(user_data, &property);
	packet_service_service_complete_get_properties(obj_service, invocation, gv);
	return TRUE;
}

static gboolean on_service_get_context (PacketServiceService *obj_service,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	GVariantBuilder b_context;
	GVariant *contexts;

	GHashTableIter iter;
	gpointer key, value;
	PsService *service = user_data;

	dbg("modem get contexts interface");

	if (service->contexts == NULL) {
		err("No context present for service");
		FAIL_RESPONSE(invocation,PS_ERR_INTERNAL);
		return TRUE;
	}

	g_variant_builder_init(&b_context, G_VARIANT_TYPE("a{sa{ss}}"));
	g_hash_table_iter_init(&iter, service->contexts);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		gchar *path = NULL;
		g_variant_builder_open(&b_context,G_VARIANT_TYPE("{sa{ss}}"));
		path = _ps_service_ref_path(value);

		g_variant_builder_add(&b_context, "s",g_strdup(path));
		if (FALSE == _ps_context_get_properties_handler(value, &b_context)) {
			err("Failed to get property");
			g_variant_builder_close(&b_context);
			FAIL_RESPONSE(invocation,PS_ERR_INTERNAL);
			return TRUE;
		}
		g_variant_builder_close(&b_context);

	}

	contexts = g_variant_builder_end(&b_context);
	packet_service_service_complete_get_contexts(obj_service, invocation,contexts);
	return TRUE;
}

static void _ps_service_setup_interface(PacketServiceService *service,
	PsService *service_data)
{
	dbg("Entered");
	g_signal_connect (service,
		"handle-get-properties",
		G_CALLBACK (on_service_get_properties),
		service_data);

	g_signal_connect (service,
		"handle-get-contexts",
		G_CALLBACK (on_service_get_context),
		service_data);

	dbg("Exiting");
}
