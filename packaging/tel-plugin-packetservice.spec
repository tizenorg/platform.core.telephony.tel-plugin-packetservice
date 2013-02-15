#sbs-git:slp/pkgs/t/tel-plugin-packetservice
Name:       tel-plugin-packetservice
Summary:    Telephony Packet Service library
Version: 0.1.36
Release:    1
Group:      System/Libraries
License:    Apache
Source0:    tel-plugin-packetservice-%{version}.tar.gz
%ifarch %ix86
%if "%{simulator}" != "1"
patch0: 0001-main-Create-modems-only-when-one-modem-is-added.patch
patch1: 0002-dnet_db_data-Change-SFR-internet-APN-and-add-Bouygue.patch
patch2: 0003-context-Fix-context-creation-issue.patch
%endif
%endif
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(tcore)
BuildRequires:  pkgconfig(iniparser)

%description
Telephony Packet Service library

%prep
%setup -q
%ifarch %ix86
%if "%{simulator}" != "1"
%patch0 -p1
%patch1 -p1
%patch2 -p1
%endif
%endif

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DSYSCONFDIR=%{_sysconfdir}
make %{?jobs:-j%jobs}

%post 
/sbin/ldconfig

#create db
mkdir -p /opt/dbspace

if [ ! -f /opt/dbspace/.dnet.db ]
then
  sqlite3 /opt/dbspace/.dnet.db < /usr/share/ps-plugin/dnet_db.sql
  sqlite3 /opt/dbspace/.dnet.db < /usr/share/ps-plugin/dnet_db_data.sql
fi

rm -f /usr/share/ps-plugin/dnet_db.sql
rm -f /usr/share/ps-plugin/dnet_db_data.sql

#change file permission
if [ -f /opt/dbspace/.dnet.db ]
then
	chmod 660 /opt/dbspace/.dnet.db
fi

if [ -f /opt/dbspace/.dnet.db-journal ]
then
	chmod 664 /opt/dbspace/.dnet.db-journal
fi

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license

%files
%manifest tel-plugin-packetservice.manifest
%defattr(-,root,root,-)
#%doc COPYING
/usr/share/ps-plugin/dnet_db.sql
/usr/share/ps-plugin/dnet_db_data.sql
%{_sysconfdir}/dbus-1/system.d/*
%{_libdir}/telephony/plugins/ps-plugin*
/usr/share/license/tel-plugin-packetservice
