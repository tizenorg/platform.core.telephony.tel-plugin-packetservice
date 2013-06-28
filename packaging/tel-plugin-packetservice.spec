Name:       tel-plugin-packetservice
Summary:    Telephony Packet Service library
Version:    0.1.34
Release:    1
Group:      System/Libraries
License:    Apache
Source0:    tel-plugin-packetservice-%{version}.tar.gz
Source1001: 	tel-plugin-packetservice.manifest
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
cp %{SOURCE1001} .

%build
%cmake . -DSYSCONFDIR=%{_sysconfdir}
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
%manifest %{name}.manifest
%defattr(-,root,root,-)
/usr/share/ps-plugin/dnet_db.sql
/usr/share/ps-plugin/dnet_db_data.sql
%{_sysconfdir}/dbus-1/system.d/*
%{_libdir}/telephony/plugins/ps-plugin*
/usr/share/license/tel-plugin-packetservice
