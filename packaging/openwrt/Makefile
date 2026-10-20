include $(TOPDIR)/rules.mk

PKG_NAME:=knock-control
PKG_VERSION:=3.0.0
PKG_RELEASE:=6
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=COPYING
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/knock-control
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=TOTP emergency access with browser control and QR enrollment
  URL:=https://github.com/rdmitry0911/knock
  DEPENDS:=+libpcap +libopenssl +libjson-c +libsqlite3 +libqrencode +libuci +zlib +openssl-util +uhttpd +libustream-mbedtls +firewall4 +nftables-json
endef

define Package/knock-control/description
 Server-issued TOTP profiles, native TCP/UDP knocks and authenticated HTTPS
 control with per-IP traffic idle timeouts. Includes procd services, native
 firewall4/nftables integration and the mobile web client. Native C controller
 and a dedicated uhttpd HTTPS instance; no Python or systemd required.
endef

define Package/knock-control/conffiles
/etc/config/knock-control
/etc/knock-control/
endef

# Older releases persisted only INPUT/OUTPUT definitions. Regenerate the
# include before a subsequent fw4 reload reads the upgraded hook file.
define Package/knock-control/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/usr/sbin/knock-control prepare-firewall
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/packaging/openwrt
	$(CP) ./control.c $(PKG_BUILD_DIR)/packaging/openwrt/control.c
endef

define Build/Configure
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -D_DEFAULT_SOURCE -o $(PKG_BUILD_DIR)/knock-control-daemon $(PKG_BUILD_DIR)/src/knockd.c $(PKG_BUILD_DIR)/src/list.c $(TARGET_LDFLAGS) -lpcap -lcrypto
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -std=gnu11 -Wall -Wextra -Werror -Wno-misleading-indentation -o $(PKG_BUILD_DIR)/knock-control $(PKG_BUILD_DIR)/packaging/openwrt/control.c $(TARGET_LDFLAGS) -ljson-c -lsqlite3 -lqrencode -luci -lcrypto -lz
endef

define Package/knock-control/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/share/knock-control/app $(1)/usr/share/knock-control/http/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/knock-control-daemon $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/knock-control $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/control.cgi $(1)/usr/share/knock-control/http/cgi-bin/control
	$(CP) $(PKG_BUILD_DIR)/web-app/. $(1)/usr/share/knock-control/app/
	$(INSTALL_DIR) $(1)/etc/knock-control $(1)/etc/config $(1)/etc/init.d
	$(INSTALL_CONF) ./files/knock-control.config $(1)/etc/config/knock-control
	chmod 700 $(1)/etc/knock-control
	$(INSTALL_CONF) ./files/firewall.nft $(1)/etc/knock-control/firewall.nft
	$(INSTALL_BIN) ./files/knock-control.init $(1)/etc/init.d/knock-control
	$(INSTALL_BIN) ./files/knock-control-api.init $(1)/etc/init.d/knock-control-api
	$(INSTALL_BIN) ./files/knock-control-firewall.init $(1)/etc/init.d/knock-control-firewall
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/table-post $(1)/usr/share/nftables.d/ruleset-post
	$(INSTALL_DATA) ./files/table.nft $(1)/usr/share/nftables.d/table-post/90-knock-control.nft
	$(INSTALL_DATA) ./files/hooks.nft $(1)/usr/share/nftables.d/ruleset-post/90-knock-control.nft
endef

$(eval $(call BuildPackage,knock-control))
