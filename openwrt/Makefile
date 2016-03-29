include $(TOPDIR)/rules.mk

PKG_NAME:=xTun
PKG_VERSION:=0.5.0
PKG_RELEASE=

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/lparam/xTun.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=v$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=lparam

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/xTun/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A secure and fast VPN for protect your network traffic
  URL:=https://github.com/lparam/xTun
endef

define Package/xTun
  $(call Package/xTun/Default)
  DEPENDS:=+libpthread +librt
endef

define Package/xTun/description
  xTun is a secure and fast VPN for protect your network traffic
endef

define Package/xTun/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/xTun.init $(1)/etc/init.d/xTun
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xTun $(1)/usr/bin
endef

$(eval $(call BuildPackage,xTun))
