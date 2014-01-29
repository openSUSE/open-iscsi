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


Name:           open-iscsi
BuildRequires:  bison
BuildRequires:  db-devel
BuildRequires:  flex
BuildRequires:  openssl-devel
%if 0%{?suse_version} >= 1230
BuildRequires:  systemd
%endif
BuildRequires:  zypper
Url:            http://www.open-iscsi.org
License:        GPL-2.0+
Group:          Productivity/Networking/Other
PreReq:         %fillup_prereq %insserv_prereq
Version:        2.0.873
Release:        0
%{?systemd_requires}
%define iscsi_release 873
Summary:        Linux* Open-iSCSI Software Initiator
Source:         %{name}-2.0-%{iscsi_release}.tar.bz2
Patch1:         %{name}-Factory-latest.diff.bz2
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

%package -n open-isns
Summary: Linux iSNS server
Version: 0.90
Obsoletes: isns <= 2.1.02
Provides: isns = 2.1.03

%description -n open-isns
This is a partial implementation of iSNS, according to RFC4171.
The implementation is still somewhat incomplete, but I am releasing
it for your reading pleasure.

Authors:
--------
    Olaf Kirch <okir@suse.de>

%prep
%setup -n %{name}-2.0-%{iscsi_release}
%patch1 -p1

%build
%{__make} OPTFLAGS="${RPM_OPT_FLAGS} -fno-strict-aliasing -DOFFLOAD_BOOT_SUPPORTED -DLOCK_DIR=\\\"/etc/iscsi\\\"" user
%{__make} OPTFLAGS="${RPM_OPT_FLAGS}" -C utils/open-isns programs

%install
make DESTDIR=${RPM_BUILD_ROOT} install_user
make DESTDIR=${RPM_BUILD_ROOT} install_mkinitrd_suse
# install service files
%if 0%{?suse_version} >= 1230
make DESTDIR=${RPM_BUILD_ROOT} install_service_suse
%else
make DESTDIR=${RPM_BUILD_ROOT} install_initd_suse
# rename open-iscsi service to iscsid for openSUSE
mv ${RPM_BUILD_ROOT}/etc/init.d/boot.open-iscsi \
	${RPM_BUILD_ROOT}/etc/init.d/boot.iscsid-early
mv ${RPM_BUILD_ROOT}/etc/init.d/open-iscsi \
	${RPM_BUILD_ROOT}/etc/init.d/iscsid
# create rc shortcut
[ -d ${RPM_BUILD_ROOT}/usr/sbin ] || mkdir -p ${RPM_BUILD_ROOT}/usr/sbin
ln -sf ../../etc/init.d/iscsid ${RPM_BUILD_ROOT}/usr/sbin/rciscsid
%endif
(cd ${RPM_BUILD_ROOT}/etc; ln -sf iscsi/iscsid.conf iscsid.conf)
touch ${RPM_BUILD_ROOT}/etc/iscsi/initiatorname.iscsi
install -m 0755 usr/iscsistart %{buildroot}/sbin
mkdir -p %{buildroot}/usr/sbin
install -m 0755 utils/open-isns/isnsd %{buildroot}/usr/sbin
install -m 0755 utils/open-isns/isnsdd %{buildroot}/usr/sbin
install -m 0755 utils/open-isns/isnsadm %{buildroot}/usr/sbin
mkdir -p %{buildroot}/etc/isns
install -m 0644 utils/open-isns/etc/isnsd.conf %{buildroot}/etc/isns
install -m 0644 utils/open-isns/etc/isnsdd.conf %{buildroot}/etc/isns
mkdir -p %{buildroot}%{_mandir}/man8
install -m 0644 utils/open-isns/doc/*.8 %{buildroot}%{_mandir}/man8
mkdir -p %{buildroot}%{_mandir}/man5
install -m 0644 utils/open-isns/doc/*.5 %{buildroot}%{_mandir}/man5
:
%clean
[ "${RPM_BUILD_ROOT}" != "/" -a -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}

%post
[ -x /sbin/mkinitrd_setup ] && mkinitrd_setup
if [ ! -f /etc/iscsi/initiatorname.iscsi ] ; then
    /sbin/iscsi-gen-initiatorname
fi
%if 0%{?suse_version} >= 1230
%{service_add_post iscsid.socket iscsid.service iscsi.service}
%else
%{fillup_and_insserv -Y boot.iscsid-early}
%endif

%postun
[ -x /sbin/mkinitrd_setup ] && mkinitrd_setup
%if 0%{?suse_version} >= 1230
%{service_del_postun iscsid.socket iscsid.service iscsi.service}
%else
%{insserv_cleanup}
%endif

%pre
%if 0%{?suse_version} >= 1230
%{service_add_pre iscsid.socket iscsid.service iscsi.service}
%endif

%preun
%{stop_on_removal iscsid}
%if 0%{?suse_version} >= 1230
%{service_del_preun iscsid.socket iscsid.service iscsi.service}
%endif

%preun -n open-isns
%{stop_on_removal isnsd isnsdd}

%files
%defattr(-,root,root)
%dir /etc/iscsi
%attr(0600,root,root) %config(noreplace) /etc/iscsi/iscsid.conf
%ghost /etc/iscsi/initiatorname.iscsi
%dir /etc/iscsi/ifaces
%config /etc/iscsi/ifaces/iface.example
/etc/iscsid.conf
%if 0%{?suse_version} >= 1230
%{_unitdir}/iscsid.service
%{_unitdir}/iscsid.socket
%{_unitdir}/iscsi.service
%else
%config /etc/init.d/iscsid
%config /etc/init.d/boot.iscsid-early
/usr/sbin/rciscsid
%endif
/sbin/iscsid
/sbin/iscsiadm
/sbin/iscsi-iname
/sbin/iscsistart
/sbin/iscsiuio
/sbin/iscsi-gen-initiatorname
/sbin/iscsi_offload
/sbin/iscsi_discovery
%if %(zypper --terse vcmp %{kernel_ver} 3.11) < 0
%dir /lib/mkinitrd
%dir /lib/mkinitrd/scripts
/lib/mkinitrd/scripts/setup-iscsi.sh
/lib/mkinitrd/scripts/boot-iscsi.sh
/lib/mkinitrd/scripts/boot-killiscsi.sh
%endif
%doc COPYING README
%doc %{_mandir}/man8/iscsiadm.8.gz
%doc %{_mandir}/man8/iscsid.8.gz
%doc %{_mandir}/man8/iscsi_discovery.8.gz
%doc %{_mandir}/man8/iscsiuio.8.gz

%files -n open-isns
%defattr(-,root,root)
%dir /etc/isns
%attr(0600,root,root) %config(noreplace) /etc/isns/isnsd.conf
%attr(0600,root,root) %config(noreplace) /etc/isns/isnsdd.conf
/usr/sbin/isnsd
/usr/sbin/isnsdd
/usr/sbin/isnsadm
%doc %{_mandir}/man8/isnsadm.8.gz
%doc %{_mandir}/man8/isnsd.8.gz
%doc %{_mandir}/man8/isnsdd.8.gz
%doc %{_mandir}/man5/isns_config.5.gz

%changelog
