Name:		latency
Version:	1.0
Release:	1%{?dist}
Summary:	Utility to help test network latency/bandwidth problems

Group:		Development/Debug
License:	GPLv2
URL:		https://github.com/freddy77/latency
Source0:	latency-%{version}.tar.gz

BuildRequires:	rubygem-ronn

%description
This project provide an utility to help testing environments with high
latency and low bandwidth.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man1 $RPM_BUILD_ROOT/%{_bindir}
cp latency.1 $RPM_BUILD_ROOT%{_mandir}/man1/latency.1
cp latency $RPM_BUILD_ROOT/%{_bindir}/latency

%files
%defattr(-,root,root,-)
%attr(4751, root, root) %{_bindir}/latency
%{_mandir}/man1/*

%changelog

