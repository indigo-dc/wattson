%define name    ttsc
%define buildroot	%{_topdir}/build-rpm-root


Name:		%{name}
Version:        {{VERSION}}
Release:	1%{?dist}
Summary:	Orchestrator command line client.

Group:		Applications/Web
License:	apache2
URL:		https://github.com/indigo-dc/ttsc


%description
a simple command line client for the token translation service (TTS) of the INDIGO DataCloud

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
cp %{_topdir}/SOURCES/%{name} %{buildroot}/usr/bin/%{name}

%files
/usr/bin/%{name}

%changelog

%post
if [ -f /usr/bin/%{name} ]; then
  chmod 555 /usr/bin/%{name}
fi

chown root:root /usr/bin/%{name}
