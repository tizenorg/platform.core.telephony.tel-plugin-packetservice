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

#include <glib.h>

#include <tcore.h>
#include <plugin.h>

#include <ps.h>

PsCustom *ps_ctx = NULL;

void _packet_service_cleanup()
{
	dbg("Entered");

	/*Cleaning up the master list*/
	g_slist_foreach(ps_ctx->master, __remove_master, NULL);

	/*Unowning the Gdbus */
	g_bus_unown_name(ps_ctx->bus_id);

	/*Freeing the memory allocated to the custom data for Packet Service*/
	g_free(ps_ctx);
	ps_ctx =  NULL;

	dbg("Exiting");
	return;
}


TcoreHookReturn __on_hook_modem_added(Server *server,
	TcoreServerNotification command,
	guint data_len, void *data, void *user_data)
{
	gpointer *master = user_data;
	gboolean rv = FALSE;
	dbg("Entered");

	rv = _ps_master_create_modems(master);
	dbg("Modem Added hook operation: [%s]", (rv ? "SUCCESS" : "FAIL"));

	return TCORE_HOOK_RETURN_CONTINUE;
}

static gboolean on_load()
{
	dbg("PacketService plugin load!");
	return TRUE;
}

static void on_bus_acquired(GDBusConnection *conn,
	const gchar *name, gpointer user_data)
{
	gboolean rv=FALSE;
	gpointer *master = NULL;

	TcorePlugin *p = user_data;

	dbg("Bus is acquired");

	/*Storing the GDbus connection in custom data */
	ps_ctx->conn = conn;

	master = _ps_master_create_master(conn, p);
	if (!master) {
		err("Unable to Intialize the Packet Service");
		_packet_service_cleanup();
		return;
	}

	ps_ctx->master = g_slist_append(ps_ctx->master, master);

	rv = _ps_master_create_modems(master);
	if (!rv) {
		dbg("_ps_master_create_modems failed");
		_packet_service_cleanup();
	}

	dbg("initialized PacketService plugin!");
	return ;
}

static gboolean on_init(TcorePlugin *p)
{
	guint id;
	gboolean rv=FALSE;
	gchar *address = NULL;
	GError *error = NULL;
	GDBusConnection *conn = NULL;

	if (!p)
		return FALSE;

	rv = _ps_context_initialize(p);
	if (rv != TRUE) {
		dbg("fail to initialize context global variable");
		return FALSE;
	}

	ps_ctx = g_try_malloc0(sizeof(PsCustom));
	if (!ps_ctx) {
		err("Memory allocation failed for the custom data of PS");
		return FALSE;
	}

	dbg("i'm init - PacketService!");
	address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	g_assert_no_error(error);
	dbg("address of the bus  [%s]", address);

	conn = g_dbus_connection_new_for_address_sync(address,
		G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
		G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
		NULL, NULL, &error);
	g_assert_no_error(error);
	if (!conn) {
		dbg("connection failed");
	}

	id = g_bus_own_name_on_connection(conn,
		PS_DBUS_SERVICE,
		G_BUS_NAME_OWNER_FLAGS_REPLACE,
		on_bus_acquired, NULL,
		p, NULL);

	dbg("id=[%d]", id);


	/* Initializing the custom data for PacketService */
	ps_ctx->bus_id = id;
	ps_ctx->conn = NULL;
	ps_ctx->master = NULL;
	ps_ctx->p = p;

	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	dbg("i'm unload!");

	_packet_service_cleanup();
}

EXPORT_API struct tcore_plugin_define_desc plugin_define_desc = {
	.name = "PACKETSERVICE",
	.priority = TCORE_PLUGIN_PRIORITY_MID + 1,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
