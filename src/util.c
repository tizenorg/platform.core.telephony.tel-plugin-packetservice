/*
 * PacketService Control Module
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: DongHoo Park <donghoo.park@samsung.com>
 *	    Arun Shukla <arun.shukla@samsung.com>
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

#include <unistd.h>
#include <wait.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <cynara-session.h>

#include "ps.h"

gboolean ps_util_check_access_control (cynara *p_cynara, GDBusMethodInvocation *invoc, const char *label, const char *perm)
{
	GDBusConnection *conn;
	GVariant *result_pid;
	GVariant *param;
	GError *error = NULL;
	const char *sender;
	unsigned int pid;
	int ret;
	int result = FALSE;
	/* For cynara */
	GVariant *result_uid;
	GVariant *result_smack;
	const gchar *unique_name = NULL;
	gchar *client_smack = NULL;
	char *client_session = NULL;
	unsigned int uid;
	gchar *uid_string = NULL;
	const char *privilege = NULL;
	gchar *address = NULL;

	conn = g_dbus_method_invocation_get_connection (invoc);
	if (!conn) {
		warn ("access control denied (no connection info)");
		goto OUT;
	}

	address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
	if (!address) {
		warn ("access control denied (fail to get dbus address");
		goto OUT;
	}

	if (!p_cynara) {
		warn ("access control denied (fail to get cynara handle)");
		goto OUT;
	}

	unique_name = g_dbus_connection_get_unique_name(conn);
	if (!unique_name) {
		warn ("access control denied (fail to get unique name)");
		goto OUT;
	}

	sender = g_dbus_method_invocation_get_sender (invoc);

	param = g_variant_new ("(s)", sender);
	if (!param) {
		warn ("access control denied (sender info fail)");
		goto OUT;
	}

	/* Get PID */
	result_pid = g_dbus_connection_call_sync (conn, "org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus",
			"GetConnectionUnixProcessID",
			param, NULL,
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error) {
		warn ("access control denied (dbus error: %d(%s))",
				error->code, error->message);
		g_error_free (error);
		goto OUT;
	}

	if (!result_pid) {
		warn ("access control denied (fail to get pid)");
		goto OUT;
	}

	g_variant_get (result_pid, "(u)", &pid);
	g_variant_unref (result_pid);

	/* Get UID */
	result_uid = g_dbus_connection_call_sync (conn, "org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus",
			"GetConnectionUnixUser",
			g_variant_new("(s)", unique_name), G_VARIANT_TYPE("(u)"),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error) {
		warn ("access control denied (dbus error: %d(%s))",
				error->code, error->message);
		g_error_free (error);
		goto OUT;
	}

	if (!result_uid) {
		warn ("access control denied (fail to get uid for cynara)");
		goto OUT;
	}

	g_variant_get (result_uid, "(u)", &uid);
	g_variant_unref (result_uid);
	uid_string = g_strdup_printf("%u", uid);

	/* Get Smack label */
	result_smack = g_dbus_connection_call_sync (conn, "org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus",
			"GetConnectionSmackContext",
			g_variant_new("(s)", unique_name), G_VARIANT_TYPE("(s)"),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error) {
		warn ("access control denied (dbus error: %d(%s))",
				error->code, error->message);
		g_error_free (error);
		goto OUT;
	}
	if (!result_smack) {
		warn ("access control denied (fail to get smack for cynara)");
		goto OUT;
	}
	g_variant_get (result_smack, "(s)", &client_smack);
	g_variant_unref (result_smack);

	dbg ("sender: %s pid = %u uid = %u smack = %s", sender, pid, uid, client_smack);

	client_session = cynara_session_from_pid(pid);
	if (!client_session) {
		warn ("access control denied (fail to get cynara client session)");
		goto OUT;
	}

	if (g_strrstr(perm, "w") == NULL && g_strrstr(perm, "x") == NULL) {
		privilege = "http://tizen.org/privilege/telephony";
	} else {
		privilege = "http://tizen.org/privilege/telephony.admin";
	}

	ret = cynara_check(p_cynara, client_smack, client_session, uid_string, privilege);
	if (ret != CYNARA_API_ACCESS_ALLOWED) {
		warn ("pid(%u) access (%s - %s) denied(%d)", pid, label, perm, ret);
	}
	else
		result = TRUE;
OUT:
	if (result == FALSE) {
		g_dbus_method_invocation_return_error (invoc,
				G_DBUS_ERROR,
				G_DBUS_ERROR_ACCESS_DENIED,
				"No access rights");
	}
	if (client_session)
		free(client_session);
	g_free(client_smack);
	g_free(uid_string);

	return result;
}

GSource * ps_util_gsource_dispatch(GMainContext *main_context, gint priority, GSourceFunc cb, gpointer data)
{
	GSource *request_source = NULL;
	request_source = g_idle_source_new();
	g_source_set_callback(request_source, cb, data, NULL);
	g_source_set_priority(request_source, priority);
	g_source_attach(request_source, main_context);
	return request_source;
}

gboolean ps_util_thread_dispatch(GMainContext *main_context, gint priority, GSourceFunc cb, gpointer data)
{

	GSource *request_source;

	if (main_context == NULL || cb == NULL) {
		err("Failed to dispatch");
		return FALSE;
	}
	request_source = ps_util_gsource_dispatch(main_context, priority, cb, data);
	g_source_unref(request_source);

	return TRUE;
}

int ps_util_system_command(char *command)
{
    int pid = 0,
        status = 0;
    const char *environ[] = { NULL };

    if (command == NULL)
        return -1;

	dbg("%s", command);

    pid = fork();
    if (pid == -1)
        return -1;
    if (pid == 0) {
        char *argv[4];
        argv[0] = "sh";
        argv[1] = "-c";
        argv[2] = (char *)command;
        argv[3] = 0;
        execve("/bin/sh", argv, (char **)environ);
        exit(127);
    }
    do {
        if (waitpid(pid, &status, 0) == -1) {
            if (errno != EINTR)
                return -1;
        } else {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                return WTERMSIG(status);
            } else if (WIFSTOPPED(status)) {
                return WSTOPSIG(status);
            }
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    return 0;
}

void ps_util_load_xml_file(const char *docname, const char *groupname, void **i_doc, void **i_root_node)
{
	xmlDocPtr *doc = (xmlDocPtr *)i_doc;
	xmlNodePtr *root_node = (xmlNodePtr *)i_root_node;

	dbg("docname:%s, groupname:%s", docname, groupname);

	*doc = xmlParseFile(docname);
	if (*doc) {
		*root_node = xmlDocGetRootElement(*doc);
		if (*root_node) {
			dbg("*root_node->name:%s", (*root_node)->name);
			if (0 == xmlStrcmp((*root_node)->name, (const xmlChar *) groupname)) {
				dbg("root_node is found !!!");
				return;
			} else {
				err("Cannot find root node.");
				*root_node = NULL;
			}
		}
		xmlFreeDoc(*doc);
		*doc = NULL;
	} else {
		err("fail to parse doc(%s)", docname);
	}
}

void ps_util_unload_xml_file(void **i_doc, void **i_root_node)
{
	xmlDocPtr *doc = (xmlDocPtr *)i_doc;
	xmlNodePtr *root_node = (xmlNodePtr *)i_root_node;

	dbg("unloading XML");
	if (doc && *doc) {
		xmlFreeDoc(*doc);
		*doc = NULL;
		if (root_node)
			*root_node = NULL;
	}
}
