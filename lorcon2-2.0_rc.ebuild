# Copyright 1999-2006 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $
# Nonofficial ebuild by sh0

inherit eutils distutils subversion

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

DEPEND=""
RDEPEND=""

src_unpack() {
    subversion_fetch
}

src_compile() {
	econf --prefix=/usr || die "econf failed"
	emake CC="gcc" || die "compile failed"
}

src_install() {
	dodir /usr/lib
	dodir /usr/include
	emake DESTDIR=${D} install || die "install failed"
}
