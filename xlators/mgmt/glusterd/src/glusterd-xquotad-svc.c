#include "globals.h"
#include "run.h"
#include "glusterd.h"
#include "glusterd-utils.h"
#include "glusterd-volgen.h"
#include "glusterd-xquotad-svc.h"
#include "glusterd-messages.h"
#include "glusterd-svc-helper.h"

char *xquotad_svc_name = "xquotad";

void
glusterd_xquotadsvc_build (glusterd_svc_t *svc)
{
        svc->manager = glusterd_xquotadsvc_manager;
        svc->start = glusterd_xquotadsvc_start;
        svc->stop = glusterd_svc_stop;
}

int glusterd_xquotadsvc_init (glusterd_svc_t *svc)
{
        int              ret                = -1;

        ret = glusterd_svc_init (svc, xquotad_svc_name);
        if (ret)
                goto out;

out:
        return ret;
}

static int
glusterd_xquotadsvc_create_volfile ()
{
        char             filepath[PATH_MAX] = {0,};
        glusterd_conf_t *conf               = THIS->private;

        glusterd_svc_build_volfile_path (xquotad_svc_name, conf->workdir,
                                         filepath, sizeof (filepath));
        return glusterd_create_global_volfile (build_xquotad_graph,
                                               filepath, NULL);
}

int
glusterd_xquotadsvc_manager (glusterd_svc_t *svc, void *data, int flags)
{
        int                 ret     = 0;
        glusterd_volinfo_t *volinfo = NULL;

        if (!svc->inited) {
                ret = glusterd_xquotadsvc_init (svc);
                if (ret) {
                        gf_msg (THIS->name, GF_LOG_ERROR, 0,
                                GD_MSG_FAILED_INIT_XQUOTASVC, "Failed to init "
                                "xquotad service");
                        goto out;
                } else {
                        svc->inited = _gf_true;
                        gf_msg_debug (THIS->name, 0, "xquotad service "
                                      "initialized");
                }
        }

        volinfo = data;

        /* If all the volumes are stopped or all shd compatible volumes
         * are stopped then stop the service if:
         * - volinfo is NULL or
         * - volinfo is present and volume is shd compatible
         * Otherwise create volfile and restart service if:
         * - volinfo is NULL or
         * - volinfo is present and volume is shd compatible
         */
        if (glusterd_are_all_volumes_stopped () ||
            glusterd_all_volumes_with_xquota_stopped ()) {
                if (!(volinfo && !glusterd_is_volume_xquota_enabled (volinfo))) {
                        ret = svc->stop (svc, SIGTERM);
                }
        } else {
                if (!(volinfo && !glusterd_is_volume_xquota_enabled (volinfo))) {
                        ret = glusterd_xquotadsvc_create_volfile ();
                        if (ret)
                                goto out;

                        ret = svc->stop (svc, SIGTERM);
                        if (ret)
                                goto out;

                        ret = svc->start (svc, flags);
                        if (ret)
                                goto out;

                        ret = glusterd_conn_connect (&(svc->conn));
                        if (ret)
                                goto out;
                }
        }
out:
        if (ret)
                gf_event (EVENT_SVC_MANAGER_FAILED, "svc_name=%s", svc->name);

        gf_msg_debug (THIS->name, 0, "Returning %d", ret);

        return ret;
}

int
glusterd_xquotadsvc_start (glusterd_svc_t *svc, int flags)
{
        int              i         = 0;
        int              ret       = -1;
        dict_t          *cmdline   = NULL;
        char             key[16]   = {0};
        char            *options[] = {
                                      "*replicate*.entry-self-heal=off",
                                      "--xlator-option",
                                      "*replicate*.metadata-self-heal=off",
                                      "--xlator-option",
                                      "*replicate*.data-self-heal=off",
                                      "--xlator-option",
                                      NULL
                                      };

        cmdline = dict_new ();
        if (!cmdline)
                goto out;

        for (i = 0; options[i]; i++) {
                memset (key, 0, sizeof (key));
                snprintf (key, sizeof (key), "arg%d", i);
                ret = dict_set_str (cmdline, key, options[i]);
                if (ret)
                        goto out;
        }

        ret = glusterd_svc_start (svc, flags, cmdline);

out:
        if (cmdline)
                dict_unref (cmdline);

        gf_msg_debug (THIS->name, 0, "Returning %d", ret);

        return ret;
}

int
glusterd_xquotadsvc_reconfigure ()
{
        int              ret             = -1;
        xlator_t        *this            = NULL;
        glusterd_conf_t *priv            = NULL;
        gf_boolean_t     identical       = _gf_false;

        this = THIS;
        GF_VALIDATE_OR_GOTO (this->name, this, out);

        priv = this->private;
        GF_VALIDATE_OR_GOTO (this->name, priv, out);

        if (glusterd_all_volumes_with_xquota_stopped ())
                goto manager;

        /*
         * Check both OLD and NEW volfiles, if they are SAME by size
         * and cksum i.e. "character-by-character". If YES, then
         * NOTHING has been changed, just return.
         */
        ret = glusterd_svc_check_volfile_identical (priv->xquotad_svc.name,
                                                    build_xquotad_graph,
                                                    &identical);
        if (ret)
                goto out;

        if (identical) {
                ret = 0;
                goto out;
        }

        /*
         * They are not identical. Find out if the topology is changed
         * OR just the volume options. If just the options which got
         * changed, then inform the xlator to reconfigure the options.
         */
        identical = _gf_false; /* RESET the FLAG */
        ret = glusterd_svc_check_topology_identical (priv->xquotad_svc.name,
                                                     build_xquotad_graph,
                                                     &identical);
        if (ret)
                goto out;

        /* Topology is not changed, but just the options. But write the
         * options to xquotad volfile, so that xquotad will be reconfigured.
         */
        if (identical) {
                ret = glusterd_xquotadsvc_create_volfile ();
                if (ret == 0) {/* Only if above PASSES */
                        ret = glusterd_fetchspec_notify (THIS);
                }
                goto out;
        }
manager:
        /*
         * xquotad volfile's topology has been changed. xquotad server needs
         * to be RESTARTED to ACT on the changed volfile.
         */
        ret = priv->xquotad_svc.manager (&(priv->xquotad_svc), NULL,
                                        PROC_START_NO_WAIT);

out:
        gf_msg_debug (this->name, 0, "Returning %d", ret);
        return ret;
}
