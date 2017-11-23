#include <sys/wait.h>
#include <unistd.h>
#include <uci.h>
#include <sys/stat.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/plugins.h>

#include "common.h"
#include "sip.h"
#include "parse.h"

/* name of the uci config file. */
static const char *config_file = "voice_client";
static const char *yang_model = "terastream-sip";

static int parse_change(sr_session_ctx_t *session, const char *module_name, ctx_t *ctx, sr_notif_event_t event)
{
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char xpath[XPATH_MAX_LEN] = {
        0,
    };

    snprintf(xpath, XPATH_MAX_LEN, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, xpath, &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", xpath);
        goto error;
    }

    while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
        rc = sysrepo_to_uci(ctx, oper, old_value, new_value, event);
        sr_free_val(old_value);
        sr_free_val(new_value);
        CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
    }

    DBG_MSG("restart voice_client");
    pid_t pid = fork();
    if (0 == pid) {
        struct blob_buf buf = {0};
        struct json_object *p;
        uint32_t id = 0;
        int u_rc = 0;

        struct ubus_context *u_ctx = ubus_connect(NULL);
        if (u_ctx == NULL) {
            ERR_MSG("Could not connect to ubus");
            goto cleanup;
        }

        blob_buf_init(&buf, 0);
        u_rc = ubus_lookup_id(u_ctx, "uci", &id);
        if (UBUS_STATUS_OK != u_rc) {
            ERR("ubus [%d]: no object network\n", u_rc);
            goto cleanup;
        }

        p = json_object_new_object();
        json_object_object_add(p, "config", json_object_new_string("voice_client"));

        const char *json_data = json_object_get_string(p);
        blobmsg_add_json_from_string(&buf, json_data);
        json_object_put(p);

        u_rc = ubus_invoke(u_ctx, id, "commit", buf.head, NULL, NULL, 1000);
        if (UBUS_STATUS_OK != u_rc) {
            ERR("ubus [%d]: no object restart\n", u_rc);
            goto cleanup;
        }

    cleanup:
        if (NULL != u_ctx) {
            ubus_free(u_ctx);
            blob_buf_free(&buf);
        }

        if (-1 == system("/etc/init.d/voice_client reload > /dev/null")) {
            ERR_MSG("failed to reload voice_client");
        };

        sr_val_t *value = NULL;
        rc = sr_get_item(session, "/terastream-sip:asterisk/enabled", &value);
        if (SR_ERR_OK != rc) {
            ERR("Could nog get /terastream-sip:asterisk/enabled, error: %s", sr_strerror(rc));
            exit(127);
        }

        if (true == value->data.bool_val) {
            // TODO get asterisk state
            if (-1 == system("/etc/init.d/asterisk restart > /dev/null")) {
                ERR_MSG("failed to restart voice_client");
            };
            sleep(1);
            // TODO asterisk works only after second restart
            if (-1 == system("/etc/init.d/asterisk restart > /dev/null")) {
                ERR_MSG("failed to restart voice_client");
            };
        }
        if (NULL != value) {
            sr_free_val(value);
        }
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

error:
    if (NULL != it) {
        sr_free_change_iter(it);
    }
    return rc;
}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	ctx_t *ctx = private_ctx;
	INF("%s configuration has changed.", yang_model);

	ctx->sess = session;

	if (SR_EV_APPLY == event) {
		/* copy running datastore to startup */

		rc = sr_copy_config(ctx->startup_sess, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
		if (SR_ERR_OK != rc) {
			WRN_MSG("Failed to copy running datastore to startup");
			/* TODO handle this error */
			return rc;
		}
		return SR_ERR_OK;
	}

	rc = parse_change(session, module_name, ctx, event);
	CHECK_RET(rc, error, "failed to apply sysrepo changes to snabb: %s", sr_strerror(rc));

error:
	return rc;
}

static int state_data_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
	ctx_t *ctx = private_ctx;

	rc = fill_state_data(ctx, (char *) xpath, values, values_cnt);
	if (SR_ERR_OK != rc) {
		DBG("failed to load state data: %s", sr_strerror(rc));
		rc = SR_ERR_OK;
	}
	CHECK_RET(rc, error, "failed to load state data: %s", sr_strerror(rc));

error:
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
	int rc = SR_ERR_OK;

	/* INF("sr_plugin_init_cb for sysrepo-plugin-dt-network"); */

	ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->sub = NULL;
	ctx->sess = session;
	ctx->startup_conn = NULL;
	ctx->startup_sess = NULL;
	ctx->yang_model = yang_model;
	ctx->config_file = config_file;
	*private_ctx = ctx;

	/* Allocate UCI context for uci files. */
	ctx->uctx = uci_alloc_context();
	if (NULL == ctx->uctx) {
		rc = SR_ERR_NOMEM;
	}
	CHECK_RET(rc, error, "Can't allocate uci context: %s", sr_strerror(rc));

	/* load the startup datastore */
	INF_MSG("load sysrepo startup datastore");
	rc = load_startup_datastore(ctx);
	CHECK_RET(rc, error, "failed to load startup datastore: %s", sr_strerror(rc));

	/* sync sysrepo datastore and uci configuration file */
	rc = sync_datastores(ctx);
	CHECK_RET(rc, error, "failed to sync sysrepo datastore and cui configuration file: %s", sr_strerror(rc));

	rc = sr_module_change_subscribe(ctx->sess, yang_model, module_change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &ctx->sub);
	CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

	rc = sr_dp_get_items_subscribe(ctx->sess, "/terastream-sip:sip-state", state_data_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
	CHECK_RET(rc, error, "failed sr_dp_get_items_subscribe: %s", sr_strerror(rc));

	INF_MSG("Plugin initialized successfully");

	return SR_ERR_OK;

error:
	ERR("Plugin initialization failed: %s", sr_strerror(rc));
	if (NULL != ctx->sub) {
		sr_unsubscribe(ctx->sess, ctx->sub);
		ctx->sub = NULL;
	}
	return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
	INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
	if (!private_ctx)
		return;

	ctx_t *ctx = private_ctx;
	if (NULL == ctx) {
		return;
	}
	/* clean startup datastore */
	if (NULL != ctx->startup_sess) {
		sr_session_stop(ctx->startup_sess);
	}
	if (NULL != ctx->startup_conn) {
		sr_disconnect(ctx->startup_conn);
	}
	if (NULL != ctx->sub) {
		sr_unsubscribe(session, ctx->sub);
	}
	if (ctx->uctx) {
		uci_free_context(ctx->uctx);
	}
	free(ctx);

	DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum)
{
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

int main()
{
	INF_MSG("Plugin application mode initialized");
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_ctx = NULL;
	int rc = SR_ERR_OK;

	/* connect to sysrepo */
	rc = sr_connect(yang_model, SR_CONN_DEFAULT, &connection);
	CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	/* start session */
	rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
	CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	rc = sr_plugin_init_cb(session, &private_ctx);
	CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1); /* or do some more useful work... */
	}

cleanup:
	sr_plugin_cleanup_cb(session, private_ctx);
	if (NULL != session) {
		sr_session_stop(session);
	}
	if (NULL != connection) {
		sr_disconnect(connection);
	}
}
#endif
