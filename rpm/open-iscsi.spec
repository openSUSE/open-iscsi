#
# spec file for package open-iscsi
#
# Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           open-iscsi
BuildRequires:  bison
BuildRequires:  db-devel
BuildRequires:  flex
BuildRequires:  openssl-devel
BuildRequires:  autoconf automake libtool make
%if 0%{?suse_version} >= 1230
BuildRequires:  systemd
%endif
Url:            http://www.open-iscsi.org
License:        GPL-2.0+
Group:          Productivity/Networking/Other
PreReq:         %fillup_prereq %insserv_prereq
Version:        2.0.873
Release:        0
%{?systemd_requires}
Provides:       linux-iscsi
Obsoletes:      linux-iscsi
%define iscsi_release 873
Summary:        Linux* Open-iSCSI Software Initiator
Source:         %{name}-2.0-%{iscsi_release}.tar.bz2
Patch1:         %{name}-git-update.diff.bz2
Patch2:         %{name}-sles12-update.diff.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
Open-iSCSI is a high-performance, transport independent, multi-platform
implementation of RFC3720 iSCSI.

Open-iSCSI is partitioned into user and kernel parts.

The kernel portion of Open-iSCSI is a from-scratch code licensed under
GPL. The kernel part implements iSCSI data path (that is, iSCSI Read
and iSCSI Write), and consists of two loadable modules: iscsi_if.ko and
iscsi_tcp.ko.

User space contains the entire control plane: configuration manager,
iSCSI Discovery, Login and Logout processing, connection-level error
processing, Nop-In and Nop-Out handling, and (in the future:) Text
processing, iSNS, SLP, Radius, etc.

The user space Open-iSCSI consists of a daemon process called iscsid,
and a management utility iscsiadm.



Authors:
--------
    open-iscsi@googlegroups.com

%prep
%setup -n %{name}-2.0-%{iscsi_release}
%patch1 -p1
%patch2 -p1

%build
%{__make} OPTFLAGS="${RPM_OPT_FLAGS} -fno-strict-aliasing -DLOCK_DIR=\\\"/etc/iscsi\\\"" LDFLAGS="" user

%install
make DESTDIR=${RPM_BUILD_ROOT} install_user
# install service files
make DESTDIR=${RPM_BUILD_ROOT} install_initd_suse
(cd ${RPM_BUILD_ROOT}/etc; ln -sf iscsi/iscsid.conf iscsid.conf)
touch ${RPM_BUILD_ROOT}/etc/iscsi/initiatorname.iscsi
install -m 0755 usr/iscsistart %{buildroot}/sbin

%clean
[ "${RPM_BUILD_ROOT}" != "/" -a -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}

%post
if [ ! -f /etc/iscsi/initiatorname.iscsi ] ; then
    /sbin/iscsi-gen-initiatorname
fi
%{service_add_post iscsid.socket iscsid.service iscsi.service}

%postun
%{service_del_postun iscsid.socket iscsid.service iscsi.service}

%pre
%{service_add_pre iscsid.socket iscsid.service iscsi.service}

%preun
%{stop_on_removal iscsid}
%{service_del_preun iscsid.socket iscsid.service iscsi.service}

%files
%defattr(-,root,root)
%dir /etc/iscsi
%attr(0600,root,root) %config(noreplace) /etc/iscsi/iscsid.conf
%ghost /etc/iscsi/initiatorname.iscsi
%dir /etc/iscsi/ifaces
%config /etc/iscsi/ifaces/iface.example
/etc/iscsid.conf
%config %{_unitdir}/iscsid.service
%{_unitdir}/iscsid.socket
%config %{_unitdir}/iscsi.service
/sbin/*
%doc COPYING README
%doc %{_mandir}/man8/*

%changelog
