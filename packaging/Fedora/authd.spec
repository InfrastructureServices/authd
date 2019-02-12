Summary: A RFC 1413 ident protocol daemon
Name: authd
Version: @VERSION@
Release: @RELEASE@%{?dist}
License: GPLv2+
URL: https://github.com/InfrastructureServices/authd
Obsoletes: pidentd < 3.2
Provides: pidentd = 3.2
Requires(post): openssl
Source0: https://github.com/InfrastructureServices/authd/archive/authd-%{version}.tar.gz
Source1: auth.socket
Source2: auth@.service

BuildRequires:  gcc
BuildRequires: openssl-devel gettext help2man systemd-units
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
authd is a small and fast RFC 1413 ident protocol daemon
with both xinetd server and interactive modes that
supports IPv6 and IPv4 as well as the more popular features
of pidentd.

%prep
%autosetup

%build
CFLAGS=%{optflags} make prefix=%{_prefix}

%install
make install

install -d %{buildroot}%{_unitdir}/
install -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/
install -m 644 %{SOURCE2} %{buildroot}%{_unitdir}/

install -d %{buildroot}%{_sysconfdir}/
touch %{buildroot}%{_sysconfdir}/ident.key

install -d %{buildroot}/%{_mandir}/man1/
help2man -N -v -V %{buildroot}/%{_sbindir}/in.authd -o \
         %{buildroot}/%{_mandir}/man1/in.authd.1

%find_lang %{name}

%post
/usr/sbin/adduser -s /sbin/nologin -u 98 -r -d '/' ident 2>/dev/null || true
/usr/bin/openssl rand -base64 -out %{_sysconfdir}/ident.key 32
echo CHANGE THE LINE ABOVE TO A PASSPHRASE >> %{_sysconfdir}/ident.key
/bin/chown ident:ident %{_sysconfdir}/ident.key
chmod o-rw %{_sysconfdir}/ident.key
%systemd_post auth.socket

%postun
%systemd_postun_with_restart auth.socket

%preun
%systemd_preun auth.socket

%files -f authd.lang
%verify(not md5 size mtime user group) %config(noreplace) %attr(640,root,root) %{_sysconfdir}/ident.key
%doc COPYING README.html rfc1413.txt
%{_sbindir}/in.authd
%{_mandir}/*/*
%{_unitdir}/*

%changelog
* Thu Jan 31 2019 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.3-51
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Thu Jul 12 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.3-50
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.3-49
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Wed Aug 02 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.3-48
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.3-47
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.3-46
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Thu Dec 22 2016 CAI Qian <caiqian@redhat.com> - 1.4.3-45
- Fix some lint warnings

* Wed Feb 03 2016 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.3-44
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-43
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Fri Aug 15 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-42
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-41
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Mon Aug 05 2013 Roman Rakus <rrakus@redhat.com> - 1.4.3-40
- Fix doc dir to satisfy new policy
- Don't return negative uid
  Resolves: #991998, #482811

* Sat Aug 03 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-39
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-38
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Fri Nov 30 2012 Roman Rakus <rrakus@redhat.com> - 1.4.3-37
- Fix a typo in build requirements

* Fri Nov 30 2012 Roman Rakus <rrakus@redhat.com> - 1.4.3-36
- Provide native systemd service file
  Resolves: #737153

* Thu Nov 29 2012 Roman Rakus <rrakus@redhat.com> - 1.4.3-35
- Generate and include man page

* Mon Nov 19 2012 Roman Rakus <rrakus@redhat.com> - 1.4.3-34
- Fixed address in license text

* Wed Jul 18 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-33
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Thu Jan 12 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-32
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Mon Feb 07 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-31
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Mon Jun 14 2010 Roman Rakus <rrakus@redhat.com> - 1.4.3-30
- Use only once defattr macro
- Use RPM_OPT_FLAGS for CFLAGS in build section

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 1.4.3-28
- rebuilt with new openssl

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-27
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Apr 09 2009 Roman Rakus <rrakus@redhat.com> - 1.4.3-26
- get back to older version of jiffies64 patch

* Tue Mar 31 2009 Roman Rakus <rrakus@redhat.com> - 1.4.3-25
- Fixed source tag

* Tue Mar 31 2009 Roman Rakus <rrakus@redhat.com> - 1.4.3-24
- Fixed using valist with log option on.
  Resolves: #446844
- user ident has home dir set to /
  Resolves: #458144

* Mon Feb 23 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-23
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Thu Jan 15 2009 Tomas Mraz <tmraz@redhat.com> - 1.4.3-22
- rebuild with new openssl

* Wed Jul 23 2008 Roman Rakus <rrakus@redhat.com> - 1.4.3-21
- Corrected config directive for ident.key to noreplace
- Fixed some typos in specfile

* Tue Apr 29 2008 Roman Rakus <rrakus@redhat.com> - 1.4.3-20
- another corrections of jiffies64 patch

* Wed Mar 26 2008 Roman Rakus <rrakus@redhat.com> - 1.4.3-19
- corrected jiffies64 patch

* Thu Mar  6 2008 Roman Rakus <rrakus@redhat.com> - 1.4.3-18
- corrected Source0
- corrected link in URL
- source added to svn on fedorahosted

* Wed Mar  5 2008 Roman Rakus <rrakus@redhat.com> - 1.4.3-16
- fixed Source0

* Wed Mar  5 2008 Roman Rakus <rrakus@redhat.com> - 1.4.3-15
- added dist tag
- added URL

* Tue Feb 26 2008 Roman Rakus <rrakus@redhat.com> - 1.4.3-14
- fix 234262 bug

* Wed Feb 13 2008 Jan Safranek <jsafrane@redhat.com> - 1.4.3-13
- fix rpmlint errors

* Tue Feb 12 2008 Jan Safranek <jsafrane@redhat.com> - 1.4.3-12
- fix build with new gcc

* Fri Dec 07 2007 Release Engineering <rel-eng at fedoraproject dot org> - 1.4.3-11
- Rebuild for deps

* Wed Sep 19 2007 Ondrej Dvoracek <odvorace@redhat.com> - 1.4.3-10
- corrected illegal identifier in longopt enumeration (#245436)
- corrected summary and license

* Mon Jul 24 2006 Martin Stransky <stransky@redhat.com> - 1.4.3-9
- added locale patch (#199721)

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 1.4.3-8.1
- rebuild

* Sun May 28 2006 Martin Stransky <stransky@redhat.com> - 1.4.3-8
- added gettext dependency (#193350)

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 1.4.3-7.1
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Martin Stransky <stransky@redhat.com> - 1.4.3-7
- re-tag

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 1.4.3-6.devel.2
- rebuilt for new gcc4.1 snapshot and glibc changes

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Tue Nov 8  2005 Martin Stransky <stransky@redhat.com>
- rebuilt

* Fri Jun 24 2005 Martin Stransky <stransky@redhat.com> - 1.4.3-5.devel
- add xinetd to Prereq
- fix for #150502 (authd doesn't map IPv6 to IPv4 from xinetd)

* Fri Apr  8 2005 Martin Stransky <stransky@redhat.com> - 1.4.3-4.devel
- clear last update

* Fri Apr  8 2005 Martin Stransky <stransky@redhat.com> - 1.4.3-3.devel
- delete user "ident" after uninstalation

* Thu Apr  7 2005 Martin Stransky <stransky@redhat.com> - 1.4.3-2.devel
- in.authd disabled by default (#151905)

* Mon Mar  7 2005 Martin Stransky <stransky@redhat.com> - 1.4.3-1.devel
- update to 1.4.3
- gcc4.0 patch
- add post-uninstall reconfiguration (#150460)

* Mon Feb 14 2005 Adrian Havill <havill@redhat.com>
- rebuilt

* Fri Oct 15 2004 Adrian Havill <havill@redhat.com> - 1.4.2-8
- tweak setting of uid/gid for key file so systems with no prior
  ident user/group don't generate a warning (#135837)

* Thu Oct 14 2004 Adrian Havill <havill@redhat.com> - 1.4.2-4
- slightly better error checking for insane cases
- tweak of the openssl requires dependency loop (#131291)
- as ident.key is created in %%post, tweak so verify passes (#131530)
- make the uid/gid for ident conform to the past (#135752)

* Wed Jul 28 2004 Adrian Havill <havill@redhat.com> - 1.4.1-1
- only scan for ESTABLISHED connections
- extra debug output for crypto

* Mon Jul 26 2004 Adrian Havill <havill@redhat.com> - 1.4.0-1
- revise makefile; don't over-optimize as gcc can produce bad code
- ptr cleanup when multiquery and missing /proc/net/tcp*
- improve create_opt (error handling, debugging, identifiers)
- add --prefix option for matching IPv4 to IPv6

* Tue Jul 13 2004 Adrian Havill <havill@redhat.com> - 1.3.4-1
- retry reading proc with pauses to reduce false negatives
- match IPv4 addresses against IPv6 compatibility addresses

* Mon Jul 12 2004 Adrian Havill <havill@redhat.com> - 1.3.3-1
- use gnu *_unlocked stream funcs for faster I/O

* Sat Jul 10 2004 Adrian Havill <havill@redhat.com> - 1.3.2-1
- enforce rfc restriction limiting port search to the connected
  local/foreign pair

* Thu Jul 08 2004 Adrian Havill <havill@redhat.com> - 1.3.1-1
- increase default connections-per-sec/max-instances for HP
- more doc cleanup
- remove unnecessary rootdir check for -N/--ident

* Fri Jul 02 2004 Adrian Havill <havill@redhat.com> - 1.3.0-1
- add unknown-error only -e option
- edit readme, add rfc to docdir
- code cleanup; remove static buffers, orthagonalize id names
- ipv6 hybrid addr zero run correction
- extra eight bits added to random key

* Wed Jun 30 2004 Adrian Havill <havill@redhat.com> - 1.2.8-1
- zero out invalid port(s)

* Tue Jun 29 2004 Adrian Havill <havill@redhat.com> - 1.2.7-1
- added Provides to satisfy HP pkg rpm dep (#121447, #111640)
- more code cleanup; minimize --resolve dns lookups

* Mon Jun 28 2004 Adrian Havill <havill@redhat.com> - 1.2.6-1
- incorporated suggestions from Thomas Zehetbauer (#124914)

* Sat Jun 26 2004 Adrian Havill <havill@redhat.com> - 1.2.5-1
- clean up src

* Thu Jun 24 2004 Adrian Havill <havill@redhat.com> - 1.2.4-1
- code vet and minor changes re alan@'s comments
- default operating mode to alias all usernames as 'nobody'
  to prevent noobies from getting their mail addr harvested
- clean up README documentation

* Wed Jun 23 2004 Adrian Havill <havill@redhat.com> - 1.2.3-1
- mark xinetd conf file as a noreplace config file
- more robust error checking for proper rfc1413 tokens

* Tue Jun 22 2004 Adrian Havill <havill@redhat.com> - 1.2.1-1
- add Requires and BuildRequires

* Mon Jun 21 2004 Adrian Havill <havill@redhat.com> - 1.2.0-1
- A few tweaks in the cmdline options for orthagonality
- minor bug fix regarding reading from stdin in some multiquery cmdline cases
- add --resolve

* Sun Jun 20 2004 Adrian Havill <havill@redhat.com> - 1.1.0-1
- add extra options for --help, --usage

* Sat Jun 19 2004 Adrian Havill <havill@redhat.com> - 1.0.0-2
- Obsolete pidentd -- authd and pidentd can't/shouldn't coexist on FC/RHEL
- license tweak to allow openssl under any condition
- no spec url needed; package is not worthy enough.

* Fri Jun 18 2004 Jens Petersen <petersen@redhat.com> - 1.0.0-1
- Initial packaging
