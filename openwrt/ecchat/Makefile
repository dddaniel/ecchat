include $(TOPDIR)/rules.mk

PKG_NAME:=ecchat
PKG_VERSION:=1
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git@github.com:dddaniel/ecchat.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=x
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_MAINTAINER:=daniel danzberger <daniel@dd-wrt.com>

CONFIG_SRC_TREE_OVERRIDE:=y

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/ecchatd
  CATEGORY:=Network
  TITLE:=ECchatd
  DEPENDS:= +libubox +libblobmsg-json +libmbedtls
endef

define Package/ecchatd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ecchatd $(1)/usr/bin/
	#$(INSTALL_BIN) ./files/ecchatd.init $(1)/etc/init.d/ecchatd
endef

$(eval $(call BuildPackage,ecchatd))

