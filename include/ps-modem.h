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

#ifndef __PS_MODEM_H__
#define __PS_MODEM_H__

#include <glib.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

typedef struct PsModem		PsModem;
typedef struct PsModemClass	PsModemClass;

#define PS_TYPE_MODEM				( ps_modem_get_type() )
#define PS_MODEM(obj)				( G_TYPE_CHECK_INSTANCE_CAST( (obj),PS_TYPE_MODEM, PsModem ) )
#define PS_IS_MODEM(obj)			( G_TYPE_CHECK_INSTANCE_TYPE( (obj), PS_TYPE_MODEM) )

#define PS_MODEM_CLASS(klass)		( G_TYPE_CHECK_CLASS_CAST( (klass), PS_TYPE_MODEM, PsModemClass ) )
#define PS_IS_MODEM_CLASS(klass)	( G_TYPE_CHECK_CLASS_TYPE( (klass), PS_TYPE_MODEM ) )
#define PS_MODEM_GET_CLASS(obj)		( G_TYPE_INSTANCE_GET_CLASS( (obj), PS_TYPE_MODEM, PsModemClass ) )

GType ps_modem_get_type(void);

G_END_DECLS

#endif /* __PS_MODEM_H__ */
