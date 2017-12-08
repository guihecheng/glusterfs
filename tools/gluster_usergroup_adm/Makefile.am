SUBDIRS = src

bin_SCRIPTS = gluster_usergroup_adm

CLEANFILES = $(bin_SCRIPTS)

uninstall-local:
	rm -rf $(DESTDIR)$(GLUSTERD_WORKDIR)/gluster_usergroup_adm/.keys

install-data-local:
	$(mkdir_p) $(DESTDIR)$(GLUSTERD_WORKDIR)/gluster_usergroup_adm/.keys
