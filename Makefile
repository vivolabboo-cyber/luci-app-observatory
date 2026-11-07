include $(TOPDIR)/rules.mk
PKG_NAME:=luci-app-observatory
PKG_VERSION:=0.4.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKGARCH:=all
include $(INCLUDE_DIR)/package.mk
define Package/luci-app-observatory
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=luci-app-observatory
  DEPENDS:=+luci-base +python3-light +python3-sqlite3 +python3-urllib +ip-full +nftables +rpcd
endef
define Build/Compile
endef
define Package/luci-app-observatory/install
	$(CP) ./root/* $(1)/
endef
$(eval $(call BuildPackage,luci-app-observatory))
