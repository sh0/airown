# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="2"

inherit autotools subversion

MY_P="lorcon2"
S=${WORKDIR}/${MY_P}

DESCRIPTION="lorcon2"
HOMEPAGE="http://802.11ninja.net/"
ESVN_REPO_URI="http://802.11ninja.net/svn/lorcon/tags/lorcon2-200911-rc1"
ESVN_PROJECT="lorcon2-rc1"
RESTRICT="nomirror"
LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

DEPEND="dev-libs/libnl
		net-libs/libpcap"
RDEPEND="${DEPEND}"

src_prepare() {
	eautoreconf
}

src_install() {
	emake DESTDIR=${D} install || die "install failed"
	# Punt useless libtool's .la files
	find "${D}" -name '*.la' -delete
}
