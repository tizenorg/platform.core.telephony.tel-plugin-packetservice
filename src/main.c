/*
 * PacketService Control Module
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: DongHoo Park <donghoo.park@samsung.com>
 *			Arun Shukla <arun.shukla@samsung.com>
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

#include "main.h"

#include <stdio.h>
#include <glib.h>

#include <ps.h>

/* PS plugin Private information  */
typedef struct {
	GDBusConnection *conn;
	guint bus_id;
	TcorePlugin *p;
	GSList *master;
	cynara *p_cynara;
} ps_plugin_private_info;

static void _packet_service_cleanup(ps_plugin_private_info *priv_info)
{
	/* Sanity Check */
	if (priv_info == NULL)
		return;

	/* Free cynara handle */
	if (priv_info->p_cynara) {
		cynara_finish(priv_info->p_cynara);
		priv_info->p_cynara = NULL;
	}

	/* Cleaning up the master list */
	g_slist_foreach(priv_info->master, __remove_master, NULL);

	/* Unowning the Gdbus */
	g_bus_unown_name(priv_info->bus_id);

	/* Free GDBusConnection */
	g_object_unref(priv_info->conn);

	/* Freeing the memory allocated to the custom data for Packet Service	 */
	g_free(priv_info);

	return;
}

static void on_bus_acquired(GDBusConnection *conn, const gchar *name, gpointer user_data)
{
	gboolean rv = FALSE;
	gpointer *master = NULL;

	TcorePlugin *p = user_data;
	ps_plugin_private_info *priv_info = tcore_plugin_ref_user_data(p);

	dbg("Bus is acquired");

	master = _ps_master_create_master(conn, p);
	if (!master) {
		err("Failed to create master Object for Packet Service ");
		goto FAILURE;
	}

	priv_info->master = g_slist_append(priv_info->master, master);

	rv = _ps_master_create_modems(master, NULL);
	if (!rv) {
		dbg("Failure : Modem creation Failed ");
		goto FAILURE;
	}

	dbg("Initialized PacketService plugin!Successfully ");
	return;

FAILURE:
	ps_main_exit(p);
	return;
}

gboolean ps_main_init(TcorePlugin *p)
{
	guint id;
	gboolean rv = FALSE;
	gchar *address = NULL;
	GError *error = NULL;
	GDBusConnection *conn = NULL;
	ps_plugin_private_info *priv_info = NULL;
	cynara *p_cynara = NULL;

	if (!p)
		return FALSE;

	rv = _ps_context_initialize(p);
	if (rv != TRUE) {
		err("Failure : Initialize context global variable");
		return FALSE;
	}

	priv_info = g_try_malloc0(sizeof(ps_plugin_private_info));
	if (!priv_info) {
		err("Failure :Memory allocation !!");
		return FALSE;
	}

	/* Initialize cynara handle */
	if (CYNARA_API_SUCCESS == cynara_initialize(&p_cynara, NULL)) {
		dbg("cynara handle is successfully initialized.");
	} else {
		err("Failed to initialize cynara handle.");
		return FALSE;
	}

	address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	g_assert_no_error(error);

	conn = g_dbus_connection_new_for_address_sync(address,
			G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
			G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
			NULL, NULL, &error);
	g_assert_no_error(error);
	if (!conn)
		dbg("Failure : GdBus Connection failed"); /* TODO, cleanup */

	/* Storing the GDbus connection in Private inforamtion of PS Plugin */
	priv_info->conn = conn;

	id = g_bus_own_name_on_connection(conn, PS_DBUS_SERVICE,
			G_BUS_NAME_OWNER_FLAGS_REPLACE,
			on_bus_acquired, NULL,
			p, NULL);

	dbg("i'm init - PacketService with bus address :[%s] and buss connection id=[%d]", address , id);

	/* Initializing the custom data for PacketService */
	priv_info->bus_id = id;
	priv_info->master = NULL;
	priv_info->p = p;
	priv_info->p_cynara = p_cynara;

	/* Setting User data of PS plugin */
	tcore_plugin_link_user_data(p, (void *) priv_info);

	return TRUE;
}

void ps_main_exit(TcorePlugin *p)
{
	ps_plugin_private_info *priv_info = tcore_plugin_ref_user_data(p);

	_packet_service_cleanup(priv_info);
	tcore_plugin_link_user_data(p, NULL);
	dbg("Packet Service exited!! ");
}
