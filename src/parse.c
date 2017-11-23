#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uci.h>
#include <sysrepo.h>
#include <sysrepo/plugins.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "common.h"
#include "parse.h"
#include "uci.h"

typedef int (*sr_callback)(ctx_t *, sr_change_oper_t, char *, char *, char *, sr_val_t *);

int sysrepo_option_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
	int rc = SR_ERR_OK;

	/* add/change leafs */
	if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
		char *mem = NULL;
		mem = sr_val_to_str(val);
		CHECK_NULL(mem, &rc, error, "sr_print_val %s", sr_strerror(rc));
		rc = set_uci_item(ctx->uctx, ucipath, mem);
		if (mem) {
			free(mem);
		}
		UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
	} else if (SR_OP_DELETED == op) {
		rc = uci_del(ctx, ucipath);
		UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
	}

error:
	return rc;
uci_error:
	return SR_ERR_INTERNAL;
}

int sysrepo_boolean_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
	int rc = SR_ERR_OK;

	/* add/change leafs */
	if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
		if (val->data.bool_val) {
			rc = set_uci_item(ctx->uctx, ucipath, "1");
		} else {
			rc = set_uci_item(ctx->uctx, ucipath, "0");
		}
		UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
	} else if (SR_OP_DELETED == op) {
		rc = uci_del(ctx, ucipath);
		UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
	}

	if (val->data.bool_val) {
		/* voice_client init.d script will delete the password when the leaf is set
		 * to disabled, so after it's enabled the password needs to be written, if
		 * it exists, to UCI again */
		sr_val_t *value = NULL;
		char password_xpath[XPATH_MAX_LEN] = {0};
		char password_ucipath[XPATH_MAX_LEN] = {0};

		snprintf(password_xpath, XPATH_MAX_LEN, "/terastream-sip:sip/sip-account[account='%s']/password", key);
		snprintf(password_ucipath, XPATH_MAX_LEN, "voice_client.%s.secret", key);

		rc = sr_get_item(ctx->sess, password_xpath, &value);
		if (SR_ERR_NOT_FOUND == rc) {
			return SR_ERR_OK;
		} else if (SR_ERR_OK != rc) {
			return rc;
		}
		rc = set_uci_item(ctx->uctx, password_ucipath, value->data.string_val);
		sr_free_val(value);
		UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
	}

	return rc;
uci_error:
	return SR_ERR_INTERNAL;
}

int sysrepo_section_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
	int rc = SR_ERR_OK;

	/* for now there is only one */
	char *element = "sip_service_provider";

	/* add/change leafs */
	if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
		sprintf(ucipath, "%s.%s=%s", ctx->config_file, key, element);
		rc = set_uci_section(ctx, ucipath);
		UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
	} else if (SR_OP_DELETED == op) {
		rc = uci_del(ctx, ucipath);
		UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
	}

	return rc;
uci_error:
	return SR_ERR_INTERNAL;
}

int sysrepo_list_callback(ctx_t *ctx, sr_change_oper_t op, char *orig_xpath, char *orig_ucipath, char *key, sr_val_t *val) {
	int rc = SR_ERR_OK;
	size_t count = 0;
	bool enabled = true;
	sr_val_t *values = NULL;
	struct uci_ptr ptr = {};
	char set_path[XPATH_MAX_LEN] = {0};
	char ucipath[] = "voice_client.direct_dial.direct_dial";
	char xpath[] = "/terastream-sip:sip/digitmap/dials";

	/* check if digitmap is enabled */
	rc = sr_get_item(ctx->sess, "/terastream-sip:sip/digitmap/enabled", &values);
	CHECK_RET(rc, cleanup, "failed sr_get_item: %s", sr_strerror(rc));
	enabled = values->data.bool_val;
	sr_free_val(values);
	values = NULL;
	if (false == enabled) {
		return rc;
	}

	rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
	UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);
	if (NULL != ptr.o) {
		/* remove the UCI list first */
		rc = uci_delete(ctx->uctx, &ptr);
		UCI_CHECK_RET(rc, uci_error, "uci_delete %d, path %s", rc, ucipath);
	}

	/* get all list instances */
	rc = sr_get_items(ctx->sess, xpath, &values, &count);
	CHECK_RET(rc, cleanup, "failed sr_get_items: %s", sr_strerror(rc));

	for (size_t i = 0; i<count; i++){
		sprintf(set_path, "%s%s%s", orig_ucipath, "=", values[i].data.string_val);

		rc = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
		UCI_CHECK_RET(rc, uci_error, "lookup_pointer %d %s", rc, set_path);

		rc = uci_add_list(ctx->uctx, &ptr);
		UCI_CHECK_RET(rc, uci_error, "uci_set %d %s", rc, set_path);

		rc = uci_save(ctx->uctx, ptr.p);
		UCI_CHECK_RET(rc, uci_error, "uci_save %d %s", rc, set_path);

		rc = uci_commit(ctx->uctx, &(ptr.p), false);
		UCI_CHECK_RET(rc, uci_error, "uci_commit %d %s", rc, set_path);
	}

cleanup:
	if (NULL != values && 0 != count) {
		sr_free_values(values, count);
	}
	return rc;
uci_error:
	if (NULL != values && 0 != count) {
		sr_free_values(values, count);
	}
	return SR_ERR_INTERNAL;
}

int sysrepo_list_callback_enable(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *orig_ucipath, char *key, sr_val_t *val) {
	int rc = SR_ERR_OK;
	struct uci_ptr ptr = {};
	char ucipath[] = "voice_client.direct_dial.direct_dial";

	if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
		if (false == val->data.bool_val) {
			rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
			UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);
			if (NULL != ptr.o) {
				/* remove the UCI list first */
				rc = uci_delete(ctx->uctx, &ptr);
				UCI_CHECK_RET(rc, uci_error, "uci_delete %d, path %s", rc, ucipath);

				rc = uci_save(ctx->uctx, ptr.p);
				UCI_CHECK_RET(rc, uci_error, "uci_save %d %s", rc, ucipath);

				rc = uci_commit(ctx->uctx, &(ptr.p), false);
				UCI_CHECK_RET(rc, uci_error, "uci_commit %d %s", rc, ucipath);
			}
		} else {
			return sysrepo_list_callback(ctx, op, xpath, "voice_client.direct_dial.direct_dial", key, val); 
		}
	} else if (SR_OP_DELETED == op) {
		//TODO
	}

	return rc;
uci_error:
	return SR_ERR_INTERNAL;
}

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
	sr_callback callback;
	bool boolean;
	char *ucipath;
	char *xpath;
} sr_uci_link;

static sr_uci_link table_sr_uci[] = {
	{sysrepo_section_callback,        false, "voice_client.%s",                      "/terastream-sip:sip/sip-account[account='%s']"},
	{sysrepo_option_callback,         false, "voice_client.%s.name",                 "/terastream-sip:sip/sip-account[account='%s']/account_name"},
	{sysrepo_option_callback,         false, "voice_client.%s.displayname",          "/terastream-sip:sip/sip-account[account='%s']/display_name"},
	{sysrepo_boolean_callback,        true,  "voice_client.%s.enabled",              "/terastream-sip:sip/sip-account[account='%s']/enabled"},
	{sysrepo_option_callback,         false, "voice_client.%s.domain",               "/terastream-sip:sip/sip-account[account='%s']/domain"},
	{sysrepo_option_callback,         false, "voice_client.%s.user",                 "/terastream-sip:sip/sip-account[account='%s']/username"},
	{sysrepo_option_callback,         false, "voice_client.%s.secret",               "/terastream-sip:sip/sip-account[account='%s']/password"},
	{sysrepo_option_callback,         false, "voice_client.%s.authuser",             "/terastream-sip:sip/sip-account[account='%s']/authentication_name"},
	{sysrepo_option_callback,         false, "voice_client.%s.host",                 "/terastream-sip:sip/sip-account[account='%s']/host"},
	{sysrepo_option_callback,         false, "voice_client.%s.port",                 "/terastream-sip:sip/sip-account[account='%s']/port"},
	{sysrepo_option_callback,         false, "voice_client.%s.outboundproxy",        "/terastream-sip:sip/sip-account[account='%s']/outbound/proxy"},
	{sysrepo_option_callback,         false, "voice_client.%s.outboundproxyport",    "/terastream-sip:sip/sip-account[account='%s']/outbound/port"},
	{sysrepo_option_callback,         false, "voice_client.SIP.rtpstart",            "/terastream-sip:sip/advanced/rtpstart"},
	{sysrepo_option_callback,         false, "voice_client.SIP.rtpend",              "/terastream-sip:sip/advanced/rtpend"},
	{sysrepo_option_callback,         false, "voice_client.SIP.dtmfmode",            "/terastream-sip:sip/advanced/dtmfmode"},
	{sysrepo_list_callback,           false, "voice_client.direct_dial.direct_dial", "/terastream-sip:sip/digitmap/dials"},
	{sysrepo_list_callback_enable,    false, "voice_client.direct_dial.XXXX",        "/terastream-sip:sip/digitmap/enabled"},
};

bool string_eq(char *first, char *second)
{
	if (0 == strcmp(first, second)) {
		if (strlen(first) == strlen(second)) {
			return true;
		}
	}
	return false;
}

int get_secret(char *key, char **value)
{
	int rc = SR_ERR_OK;
	FILE *fp;
	char buf[XPATH_MAX_LEN] = {0};
	char cmd[XPATH_MAX_LEN] = {0};
	char *cmd_fmt = "/etc/sysrepo/scripts/sip/secret.sh %s";

	sprintf(cmd, cmd_fmt, key);

	if ((fp = popen(cmd, "r")) == NULL) {
		fprintf(stderr, "Error opening pipe!\n");
		return SR_ERR_INTERNAL;
	}

	if (fgets(buf, XPATH_MAX_LEN, fp) != NULL) {
		*value = strdup(buf);
	} else {
		fprintf(stderr, "Error running %s command.\n", cmd);
		return SR_ERR_INTERNAL;
	}

	rc = pclose(fp);

	return rc;
}

static int parse_uci_config(ctx_t *ctx, char *key)
{
	char xpath[XPATH_MAX_LEN] = {0};
	char ucipath[XPATH_MAX_LEN] = {0};
	char *uci_val = calloc(1, 100);
	int rc = SR_ERR_OK;

	const int n_mappings = ARR_SIZE(table_sr_uci);
	for (int i = 0; i < n_mappings; i++) {
		snprintf(xpath, XPATH_MAX_LEN, table_sr_uci[i].xpath, key);
		snprintf(ucipath, XPATH_MAX_LEN, table_sr_uci[i].ucipath, key);
		//TODO remove edge case or make more general solution
		if (0 == strncmp("voice_client.direct_dial.", ucipath, strlen("voice_client.direct_dial."))) {
			rc = UCI_ERR_NOTFOUND;
		} else {
			rc = get_uci_item(ctx->uctx, ucipath, &uci_val);
		}
		if (UCI_OK == rc) {
			UCI_CHECK_RET(rc, cleanup, "get_uci_item %d", rc);
			INF("%s : %s", xpath, uci_val);
			/* check if boolean value */
			if (table_sr_uci[i].boolean) {
				if (string_eq(uci_val, "1") || string_eq(uci_val, "true") || string_eq(uci_val, "on")) {
					rc = sr_set_item_str(ctx->startup_sess, xpath, "true", SR_EDIT_DEFAULT);
				} else {
					rc = sr_set_item_str(ctx->startup_sess, xpath, "false", SR_EDIT_DEFAULT);
				}
			} else {
				rc = sr_set_item_str(ctx->startup_sess, xpath, uci_val, SR_EDIT_DEFAULT);
			}
			CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
		}
	}

	/* get asterisk secret */
	char *secret = NULL;
	rc = get_secret(key, &secret);
	if (SR_ERR_OK == rc && NULL != secret) {
		CHECK_RET(rc, cleanup, "failed to get asterisk secret: %s", sr_strerror(rc));
		snprintf(xpath, XPATH_MAX_LEN, "/terastream-sip:sip/sip-account[account='%s']/password", key);
		rc = sr_set_item_str(ctx->startup_sess, xpath, secret, SR_EDIT_DEFAULT);
		CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
		free(secret);
	} else {
		rc = SR_ERR_OK;
	}

	rc = SR_ERR_OK;
cleanup:
	if (SR_ERR_NOT_FOUND == rc) {
		rc = SR_ERR_OK;
	}
	if (NULL != uci_val) {
		free(uci_val);
	}

	return rc;
}

/* parse UCI list "voice_client.direct_dial.direct_dial" */
static int parse_uci_config_list(ctx_t *ctx)
{
	int rc = SR_ERR_OK;
	struct uci_option *o;
	struct uci_element *el;
	struct uci_ptr ptr = {};
	char ucipath[] = "voice_client.direct_dial.direct_dial";
	char xpath_dials[] = "/terastream-sip:sip/digitmap/dials";
	char xpath_enabled[] = "/terastream-sip:sip/digitmap/enabled";
	bool digitmap_has_data = false;

	rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
	UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);

	if (NULL == ptr.o) {
		goto uci_error;
	}

	uci_foreach_element(&ptr.o->v.list, el) {
		o = uci_to_option(el);
		if (NULL == o && NULL == o->e.name) {
			goto uci_error;
		}
		digitmap_has_data = true;
		rc = sr_set_item_str(ctx->startup_sess, xpath_dials, o->e.name, SR_EDIT_DEFAULT);
		CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
	}

	char *enabled = digitmap_has_data ? "true" : "false";
	rc = sr_set_item_str(ctx->startup_sess, xpath_enabled, enabled, SR_EDIT_DEFAULT);
	CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));

cleanup:
	return rc;
uci_error:
	return SR_ERR_INTERNAL;
}

char *get_key_value(char *orig_xpath)
{
	char *key = NULL, *node = NULL;
	sr_xpath_ctx_t state = {0, 0, 0, 0};

	node = sr_xpath_next_node(orig_xpath, &state);
	if (NULL == node) {
		goto error;
	}
	while (true) {
		key = sr_xpath_next_key_name(NULL, &state);
		if (NULL != key) {
			key = strdup(sr_xpath_next_key_value(NULL, &state));
			break;
		}
		node = sr_xpath_next_node(NULL, &state);
		if (NULL == node) {
			break;
		}
	}

error:
	sr_xpath_recover(&state);
	return key;
}

int toggle_asterisk(sr_val_t *val)
{
	int rc = SR_ERR_OK;
	pid_t pid = fork();

	INF_MSG("change asterisk state");

	if (pid == 0) {
		if (val->data.bool_val) {
			execl("/etc/init.d/asterisk", "asterisk", "start", (char *) NULL);
		} else {
			execl("/etc/init.d/asterisk", "asterisk", "stop", (char *) NULL);
		}
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}
	return rc;
}

int sysrepo_to_uci(ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, sr_notif_event_t event)
{
	char xpath[XPATH_MAX_LEN] = {0};
	char ucipath[XPATH_MAX_LEN] = {0};
	char *orig_xpath = NULL;
	char *key = NULL;
	int rc = SR_ERR_OK;

	if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
		orig_xpath = new_val->xpath;
	} else if (SR_OP_DELETED == op) {
		orig_xpath = old_val->xpath;
	} else {
		return rc;
	}

	if (string_eq(orig_xpath, "/terastream-sip:asterisk/enabled")) {
		return toggle_asterisk(new_val);
	}

	key = get_key_value(orig_xpath);

	/* add/change leafs */
	const int n_mappings = ARR_SIZE(table_sr_uci);
	for (int i = 0; i < n_mappings; i++) {
		snprintf(xpath, XPATH_MAX_LEN, table_sr_uci[i].xpath, key);
		snprintf(ucipath, XPATH_MAX_LEN, table_sr_uci[i].ucipath, key);
		if (string_eq(xpath, orig_xpath)) {
			rc = table_sr_uci[i].callback(ctx, op, xpath, ucipath, key, new_val);
			CHECK_RET(rc, error, "failed sysrepo operation %s", sr_strerror(rc));
		}
	}

error:
	if (NULL != key) {
		free(key);
	}
	return rc;
}

static int init_sysrepo_data(ctx_t *ctx)
{
	struct uci_element *e;
	struct uci_section *s;
	int rc;

	rc = uci_load(ctx->uctx, ctx->config_file, &ctx->package);
	if (rc != UCI_OK) {
		fprintf(stderr, "No configuration (package): %s\n", ctx->config_file);
		goto cleanup;
	}

	uci_foreach_element(&ctx->package->sections, e)
	{
		s = uci_to_section(e);
		if (string_eq(s->type, "sip_service_provider")) {
			INF("key value is: %s", s->e.name)
			rc = parse_uci_config(ctx, s->e.name);
			CHECK_RET(rc, cleanup, "failed to add sysrepo data: %s", sr_strerror(rc));
		} else if (string_eq(s->type, "sip_advanced")) {
			INF("key value is: %s", s->e.name)
			rc = parse_uci_config(ctx, s->e.name);
			CHECK_RET(rc, cleanup, "failed to add sysrepo data: %s", sr_strerror(rc));
		} else if (string_eq(s->type, "direct_dial")) {
			rc = parse_uci_config_list(ctx);
			CHECK_RET(rc, cleanup, "failed to add sysrepo data: %s", sr_strerror(rc));
		}
	}

	/* add asterisk boolean value */
	rc = sr_set_item_str(ctx->startup_sess, "/terastream-sip:asterisk/enabled", "true", SR_EDIT_DEFAULT);
	CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));

	/* commit the changes to startup datastore */
	rc = sr_commit(ctx->startup_sess);
	CHECK_RET(rc, cleanup, "failed sr_commit: %s", sr_strerror(rc));

	return SR_ERR_OK;

cleanup:
	if (ctx->uctx) {
		uci_free_context(ctx->uctx);
		ctx->uctx = NULL;
	}
	return rc;
}

int sync_datastores(ctx_t *ctx)
{
	char startup_file[XPATH_MAX_LEN] = {0};
	int rc = SR_ERR_OK;
	struct stat st;

	/* check if the startup datastore is empty
	 * by checking the content of the file */
	snprintf(startup_file, XPATH_MAX_LEN, "/etc/sysrepo/data/%s.startup", ctx->yang_model);

	if (stat(startup_file, &st) != 0) {
		ERR("Could not open sysrepo file %s", startup_file);
		return SR_ERR_INTERNAL;
	}

	if (0 == st.st_size) {
		/* parse uci config */
		rc = init_sysrepo_data(ctx);
		INF_MSG("copy uci data to sysrepo");
		CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
	} else {
		/* copy the sysrepo startup datastore to uci */
		INF_MSG("copy sysrepo data to uci");
		CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
	}

error:
	return rc;
}

int load_startup_datastore(ctx_t *ctx)
{
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	int rc = SR_ERR_OK;

	/* connect to sysrepo */
	rc = sr_connect(ctx->yang_model, SR_CONN_DEFAULT, &connection);
	CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	/* start session */
	rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_CONFIG_ONLY, &session);
	CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	ctx->startup_sess = session;
	ctx->startup_conn = connection;

	return rc;
cleanup:
	if (NULL != session) {
		sr_session_stop(session);
	}
	if (NULL != connection) {
		sr_disconnect(connection);
	}

	return rc;
}

void ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char xpath[XPATH_MAX_LEN] = {0};
	ubus_ctx_t *ubus_ctx = req->priv;
	struct json_object *r = NULL, *o = NULL, *v = NULL;
	char *json_result = NULL;
	int counter = 0;
	int rc = SR_ERR_OK;
	sr_val_t *sr_val = NULL;

	if (msg) {
		json_result = blobmsg_format_json(msg, true);
		r = json_tokener_parse(json_result);
	} else {
		goto cleanup;
	}

	json_object_object_get_ex(r, "sip", &o);

	/* get array size */
	json_object_object_foreach(o, key_tmp, val_tmp) {
		if (NULL != key_tmp && NULL != val_tmp) {
			counter++;
		}
	}

	rc = sr_new_values(counter * 3, &sr_val);
	CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));

	counter = 0;
	json_object_object_foreach(o, key, val)
	{
		snprintf(xpath, XPATH_MAX_LEN, "/terastream-sip:sip-state[account='%s']/account", key);
		rc = sr_val_set_xpath(&sr_val[counter], xpath);
		CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
		rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, key);
		CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
		counter++;

		json_object_object_get_ex(val, "registered", &v);
		snprintf(xpath, XPATH_MAX_LEN, "/terastream-sip:sip-state[account='%s']/registered", key);
		rc = sr_val_set_xpath(&sr_val[counter], xpath);
		CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
		(&sr_val[counter])->data.bool_val = json_object_get_boolean(v);
		(&sr_val[counter])->type = SR_BOOL_T;
		counter++;

		json_object_object_get_ex(val, "state", &v);
		snprintf(xpath, XPATH_MAX_LEN, "/terastream-sip:sip-state[account='%s']/state", key);
		rc = sr_val_set_xpath(&sr_val[counter], xpath);
		CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
		rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
		CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
		counter++;
	}

	*ubus_ctx->values_cnt = counter;
	*ubus_ctx->values = sr_val;

cleanup:
	if (NULL != r) {
		json_object_put(r);
	}
	if (NULL != json_result) {
		free(json_result);
	}
	return;
}

int fill_state_data(ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt)
{
	int rc = SR_ERR_OK;
	uint32_t id = 0;
	struct blob_buf buf = {0};
	ubus_ctx_t ubus_ctx = {0, 0, 0};
	int u_rc = UBUS_STATUS_OK;

	struct ubus_context *u_ctx = ubus_connect(NULL);
	if (u_ctx == NULL) {
		ERR_MSG("Could not connect to ubus");
		rc = SR_ERR_INTERNAL;
		goto cleanup;
	}

	blob_buf_init(&buf, 0);
	u_rc = ubus_lookup_id(u_ctx, "asterisk", &id);
	if (UBUS_STATUS_OK != u_rc) {
		ERR("ubus [%d]: no object asterisk\n", u_rc);
		rc = SR_ERR_INTERNAL;
		goto cleanup;
	}

	ubus_ctx.ctx = ctx;
	ubus_ctx.values = values;
	ubus_ctx.values_cnt = values_cnt;
	u_rc = ubus_invoke(u_ctx, id, "status", buf.head, ubus_cb, &ubus_ctx, 0);
	if (UBUS_STATUS_OK != u_rc) {
		ERR("ubus [%d]: no object asterisk\n", u_rc);
		rc = SR_ERR_INTERNAL;
		goto cleanup;
	}

cleanup:
	if (NULL != u_ctx) {
		ubus_free(u_ctx);
		blob_buf_free(&buf);
	}
	return rc;
}
