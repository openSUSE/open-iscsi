#
# spec file for package open-iscsi
#
# Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

# norootforbuild


Name:           open-iscsi
BuildRequires:  autoconf bison db-devel flex openssl-devel
Url:            http://www.open-iscsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Other
PreReq:         %fillup_prereq %insserv_prereq
AutoReqProv:    on
Version:        2.0.873
Release:        0.<RELEASE9>
Provides:       linux-iscsi
Obsoletes:      linux-iscsi
Recommends:     logrotate
%define iscsi_release 873
Summary:        Linux* Open-iSCSI Software Initiator
Source:         %{name}-2.0-%{iscsi_release}.tar.bz2
Patch1:         %{name}-sles11-sp2-update.diff.bz2
Patch2:         %{name}-sles11-sp2-latest.diff.bz2
Patch3:         %{name}-sles11-sp3-iscsiuio-update.diff.bz2
Patch4:         %{name}-sles11-sp3-flash-update.diff.bz2
Patch5:         %{name}-sles11-sp3-general-updates-1.diff.bz2
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
%patch3 -p1
%patch4 -p1
%patch5 -p1

%build
%{__make} OPTFLAGS="${RPM_OPT_FLAGS} -DLOCK_DIR=\\\"/etc/iscsi\\\" -DOFFLOAD_BOOT_SUPPORTED" user
cd iscsiuio
touch NEWS
touch AUTHORS
autoreconf --install
%configure --sbindir=/sbin
make CFLAGS="${RPM_OPT_FLAGS}"

%install
make DESTDIR=${RPM_BUILD_ROOT} install_user
make DESTDIR=${RPM_BUILD_ROOT} install_initd_suse
(cd iscsiuio; make DESTDIR=${RPM_BUILD_ROOT} install)
[ -d $RPM_BUILD_ROOT/usr/sbin ] || mkdir $RPM_BUILD_ROOT/usr/sbin
ln -sf ../../etc/init.d/open-iscsi $RPM_BUILD_ROOT/usr/sbin/rcopen-iscsi
(cd ${RPM_BUILD_ROOT}/etc; ln -sf iscsi/iscsid.conf iscsid.conf)
touch ${RPM_BUILD_ROOT}/etc/iscsi/initiatorname.iscsi

%clean
[ "${RPM_BUILD_ROOT}" != "/" -a -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}

%post
%{fillup_and_insserv -Y boot.open-iscsi}
if [ ! -f /etc/iscsi/initiatorname.iscsi ] ; then
    /sbin/iscsi-gen-initiatorname
fi
if [ -x /sbin/mkinitrd ] ; then
    /sbin/mkinitrd || :
fi

%postun
%{insserv_cleanup}
if [ -x /sbin/mkinitrd ] ; then
    /sbin/mkinitrd || :
fi

%preun
%{stop_on_removal open-iscsi}

%files
%defattr(-,root,root)
%dir /etc/iscsi
%attr(0600,root,root) %config(noreplace) /etc/iscsi/iscsid.conf
%ghost /etc/iscsi/initiatorname.iscsi
%dir /etc/iscsi/ifaces
%config /etc/iscsi/ifaces/iface.example
/etc/iscsid.conf
%config /etc/init.d/open-iscsi
%config /etc/init.d/boot.open-iscsi
/sbin/*
/usr/sbin/rcopen-iscsi
%config /etc/logrotate.d/iscsiuiolog
%dir /lib/mkinitrd
%dir /lib/mkinitrd/scripts
/lib/mkinitrd/scripts/setup-iscsi.sh
/lib/mkinitrd/scripts/boot-iscsi.sh
/lib/mkinitrd/scripts/boot-killiscsi.sh
%doc COPYING README
%doc %{_mandir}/man8/*

%changelog
