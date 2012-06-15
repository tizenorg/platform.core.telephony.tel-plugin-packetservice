Name:       tel-plugin-packetservice
Summary:    Telephony Packet Service library
Version: 0.1.7
Release:    1
Group:      System/Libraries
License:    Apache
Source0:    tel-plugin-packetservice-%{version}.tar.gz
Source1001: packaging/tel-plugin-packetservice.manifest 
Patch0:     0001-Support-sysconfdir-in-the-makefile.patch
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(tcore)
BuildRequires:  pkgconfig(db-util)

%description
Telephony Packet Service library

%prep
%setup -q
%patch0 -p1

%build
cp %{SOURCE1001} .
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DSYSCONFDIR=%{_sysconfdir}
make %{?_smp_mflags}

%install
%make_install


%post 
/sbin/ldconfig

#create db
mkdir -p /opt/dbspace

if [ ! -f /opt/dbspace/.dnet.db ]
then
sqlite3 /opt/dbspace/.dnet.db < /tmp/dnet_db.sql
sqlite3 /opt/dbspace/.dnet.db < /tmp/dnet_db_data.sql
fi

rm -f /tmp/dnet_db.sql
rm -f /tmp/dnet_db_data.sql

#change file permission
if [ -f /opt/dbspace/.dnet.db ]
then
	chmod 600 /opt/dbspace/.dnet.db
fi

if [ -f /opt/dbspace/.dnet.db-journal ]
then
	chmod 644 /opt/dbspace/.dnet.db-journal
fi

%postun -p /sbin/ldconfig

%files
%manifest tel-plugin-packetservice.manifest
/tmp/dnet_db.sql
/tmp/dnet_db_data.sql
%{_sysconfdir}/dbus-1/system.d/*
%{_libdir}/telephony/plugins/ps-plugin*
