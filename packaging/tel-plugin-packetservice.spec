%define major 3
%define minor 0
%define patchlevel 1

Name:       tel-plugin-packetservice
Summary:    Telephony Packet Service library
Version:    %{major}.%{minor}.%{patchlevel}
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    tel-plugin-packetservice-%{version}.tar.gz
Source1001: 	tel-plugin-packetservice.manifest
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  python
BuildRequires:  python-xml
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(tcore)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(libtzplatform-config)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
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
mkdir -p %{TZ_SYS_DB}  

if [ ! -f %{TZ_SYS_DB}/.dnet.db ]
then
  sqlite3 %{TZ_SYS_DB}/.dnet.db < /usr/share/ps-plugin/dnet_db.sql
  sqlite3 %{TZ_SYS_DB}/.dnet.db < /usr/share/ps-plugin/dnet_db_data.sql
fi

rm -f /usr/share/ps-plugin/dnet_db.sql
rm -f /usr/share/ps-plugin/dnet_db_data.sql

#change file permission
if [ -f %{TZ_SYS_DB}/.dnet.db ]
then
  chmod 660 %{TZ_SYS_DB}/.dnet.db
  chsmack -a 'System' %{TZ_SYS_DB}/.dnet.db
fi

if [ -f %{TZ_SYS_DB}/.dnet.db-journal ]
then
  chmod 664 %{TZ_SYS_DB}/.dnet.db-journal
  chsmack -a 'System' %{TZ_SYS_DB}/.dnet.db-journal
fi

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
/usr/share/ps-plugin/dnet_db.sql
/usr/share/ps-plugin/dnet_db_data.sql
%{_sysconfdir}/dbus-1/system.d/*
%{_libdir}/telephony/plugins/ps-plugin*
/usr/share/license/%{name}
