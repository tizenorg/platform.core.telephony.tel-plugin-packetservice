%define major 0
%define minor 3
%define patchlevel 28

Name:           tel-plugin-packetservice
Version:        %{major}.%{minor}.%{patchlevel}
Release:        0
License:        Apache-2.0
Summary:        Telephony Packet Service library
Group:          System/Libraries
Source0:        tel-plugin-packetservice-%{version}.tar.gz
Source1:        tel-plugin-ps.conf
BuildRequires:  cmake
BuildRequires:  python
BuildRequires:  python-xml
#BuildRequires:  model-build-features
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(tcore)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(vconf)
BuildRequires: 	pkgconfig(alarm-service)
BuildRequires:  pkgconfig(libtzplatform-config)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Telephony Packet Service library

%prep
%setup -q

%build
%cmake . -DSYSCONFDIR=%{_sysconfdir} \
	-DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DLIB_INSTALL_DIR=%{_libdir} \
#%if 0%{?model_build_feature_connect_default_connection_without_timer}
#	-DCONNECT_DEFAULT_CONNECTION_WITHOUT_TIMER=1 \
#%endif
#%if 0%{?prepaid_sim_apn_support}
#	-DPREPAID_SIM_APN_SUPPORT=1 \
#%endif

make %{?_smp_mflags}

%post
/sbin/ldconfig

#create db
mkdir -p %TZ_SYS_DB

if [ ! -f %TZ_SYS_DB/.dnet.db ]
then
  sqlite3 %TZ_SYS_DB/.dnet.db < %{_datadir}/ps-plugin/dnet_db.sql
  sqlite3 %TZ_SYS_DB/.dnet.db < %{_datadir}/ps-plugin/dnet_db_init.sql
fi
if [ ! -f %TZ_SYS_DB/.dnet2.db ]
then
  sqlite3 %TZ_SYS_DB/.dnet2.db < %{_datadir}/ps-plugin/dnet_db.sql
  sqlite3 %TZ_SYS_DB/.dnet2.db < %{_datadir}/ps-plugin/dnet_db_init.sql
fi

rm -f %{_datadir}/ps-plugin/dnet_db.sql

#change file permission
if [ -f %TZ_SYS_DB/.dnet.db ]
then
	chmod 660 %TZ_SYS_DB/.dnet.db
	chown telephony:telephony %TZ_SYS_DB/.dnet.db
	chsmack -a System %TZ_SYS_DB/.dnet.db
fi

if [ -f %TZ_SYS_DB/.dnet.db-journal ]
then
	chmod 664 %TZ_SYS_DB/.dnet.db-journal
	chown telephony:telephony %TZ_SYS_DB/.dnet.db-journal
	chsmack -a System %TZ_SYS_DB/.dnet.db-journal
fi

if [ -f %TZ_SYS_DB/.dnet2.db ]
then
	chmod 660 %TZ_SYS_DB/.dnet2.db
	chown telephony:telephony %TZ_SYS_DB/.dnet2.db
	chsmack -a System %TZ_SYS_DB/.dnet2.db
fi

if [ -f %TZ_SYS_DB/.dnet2.db-journal ]
then
	chmod 664 %TZ_SYS_DB/.dnet2.db-journal
	chown telephony:telephony %TZ_SYS_DB/.dnet2.db-journal
	chsmack -a System %TZ_SYS_DB/.dnet2.db-journal
fi

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}%{_datadir}/license
mkdir -p %{buildroot}/etc/dbus-1/system.d/
cp %{SOURCE1} %{buildroot}/etc/dbus-1/system.d/tel-plugin-ps.conf

%files
%manifest tel-plugin-packetservice.manifest
%defattr(644,root,root,-)
#%doc COPYING
%{_datadir}/ps-plugin/dnet_db.sql
%{_datadir}/ps-plugin/dnet_db_init.sql
#%{_datadir}/ps-plugin/apns-conf.xml
%{_libdir}/telephony/plugins/ps-plugin*
%{_datadir}/license/tel-plugin-packetservice
/etc/dbus-1/system.d/tel-plugin-ps.conf
