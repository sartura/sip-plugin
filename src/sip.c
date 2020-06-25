#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include <srpo_uci.h>
#include <srpo_ubus.h>

#include "transform_data.h"
#include "utils/memory.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define SIP_YANG_MODEL "terastream-sip"
#define SYSREPOCFG_EMPTY_CHECK_COMMAND "sysrepocfg -X -d running -m " SIP_YANG_MODEL
#define SIP_ACCOUNT_XPATH_TEMPLATE "/" SIP_YANG_MODEL ":sip/sip-account[account='%s']"
#define SIP_ADVANCED_XPATH_TEMPLATE "/" SIP_YANG_MODEL ":sip/advanced"
#define SIP_DIGITMAP_XPATH_TEMPLATE "/" SIP_YANG_MODEL ":sip/digitmap"
#define SIP_STATE_DATA_XPATH_TEMPLATE "/" SIP_YANG_MODEL ":sip-state"

typedef char *(*transform_data_cb)(const char *);

typedef struct {
	const char *value_name;
	const char *xpath_template;
	transform_data_cb transform_data;
} sip_ubus_json_transform_table_t;

int sip_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void sip_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int sip_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int sip_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

static bool sip_running_datastore_is_empty_check(void);
static int sip_uci_data_load(sr_session_ctx_t *session);
static char *sip_xpath_get(const struct lyd_node *node);

static void sip_ubus(const char *ubus_json, srpo_ubus_result_values_t *values);
static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent);

srpo_uci_xpath_uci_template_map_t sip_xpath_uci_path_template_map[] = {
	{SIP_ACCOUNT_XPATH_TEMPLATE "voice_client.%s", "interface", NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/account_name", "voice_client.%s.name", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/display_name", "voice_client.%s.displayname", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/enabled", "voice_client.%s.enabled", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/domain", "voice_client.%s.domain", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/username", "voice_client.%s.user", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/password", "voice_client.%s.secret", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/authentication_name", "voice_client.%s.authuser", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/host", "voice_client.%s.host", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/port", "voice_client.%s.port", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/outbound/proxy", "voice_client.%s.outboundproxy", NULL, NULL, NULL, false, false},
	{SIP_ACCOUNT_XPATH_TEMPLATE "/outbound/port", "voice_client.%s.outboundproxyport", NULL, NULL, NULL, false, false},
	{SIP_ADVANCED_XPATH_TEMPLATE "/rtpstart", "voice_client.SIP.rtpstart", NULL, NULL, NULL, false, false},
	{SIP_ADVANCED_XPATH_TEMPLATE "/rtpend", "voice_client.SIP.rtpend", NULL, NULL, NULL, false, false},
	{SIP_ADVANCED_XPATH_TEMPLATE "/dtmfmode", "voice_client.SIP.dtmfmode", NULL, NULL, NULL, false, false},
	{SIP_DIGITMAP_XPATH_TEMPLATE "/dials", "voice_client.direct_dial.direct_dial", NULL, NULL, NULL, false, false},
	{SIP_DIGITMAP_XPATH_TEMPLATE "/enabled", "voice_client.direct_dial.XXXX", NULL, NULL, NULL, false, false},
};


static sip_ubus_json_transform_table_t sip_transform_table[] = {
	{.value_name = "account", .xpath_template = SIP_STATE_DATA_XPATH_TEMPLATE "/account"},
	{.value_name = "registered", .xpath_template = SIP_STATE_DATA_XPATH_TEMPLATE "/registered"},
	{.value_name = "state", .xpath_template = SIP_STATE_DATA_XPATH_TEMPLATE "/state"},
	{.value_name = "username", .xpath_template = SIP_STATE_DATA_XPATH_TEMPLATE "/username"},
	{.value_name = "refresh", .xpath_template = SIP_STATE_DATA_XPATH_TEMPLATE "/refresh"},
};


static const char *sip_uci_sections[] = {"brcm_line", "dialplan", "sip_advanced", "brcm_advanced", "features", "log", "call_filter", "cdr_log", "sip_service_provider"};

static struct {
	const char *uci_file;
	const char **uci_section_list;
	size_t uci_section_list_size;
	bool convert_unnamed_sections;
} sip_config_files[] = {
	{"voice_client", sip_uci_sections, ARRAY_SIZE(sip_uci_sections), true},
};





int sip_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	*private_data = NULL;

	error = srpo_uci_init();
	if (error) {
		SRP_LOG_ERR("srpo_uci_init error (%d): %s", error, srpo_uci_error_description_get(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	*private_data = startup_session;

	if (sip_running_datastore_is_empty_check() == true) {
		SRP_LOG_INFMSG("running DS is empty, loading data from UCI");

		error = sip_uci_data_load(session);
		if (error) {
			SRP_LOG_ERRMSG("sip_uci_data_load error");
			goto error_out;
		}

		error = sr_copy_config(startup_session, SIP_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	SRP_LOG_INFMSG("subscribing to module change");

	error = sr_module_change_subscribe(session, SIP_YANG_MODEL, "/" SIP_YANG_MODEL ":*//*", sip_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

  SRP_LOG_INFMSG("subscribing to get oper items");

	error = sr_oper_get_items_subscribe(session, SIP_YANG_MODEL, "/terastream-sip:sip-state", sip_state_data_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}


	SRP_LOG_INFMSG("plugin init done");

	goto out;

error_out:
	sr_unsubscribe(subscription);

out:

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static bool sip_running_datastore_is_empty_check(void)
{
	FILE *sysrepocfg_DS_empty_check = NULL;
	bool is_empty = false;

	sysrepocfg_DS_empty_check = popen(SYSREPOCFG_EMPTY_CHECK_COMMAND, "r");
	if (sysrepocfg_DS_empty_check == NULL) {
		SRP_LOG_WRN("could not execute %s", SYSREPOCFG_EMPTY_CHECK_COMMAND);
		is_empty = true;
		goto out;
	}

	if (fgetc(sysrepocfg_DS_empty_check) == EOF) {
		is_empty = true;
	}

out:
	if (sysrepocfg_DS_empty_check) {
		pclose(sysrepocfg_DS_empty_check);
	}

	return is_empty;
}

static int sip_uci_data_load(sr_session_ctx_t *session)
{
	int error = 0;
	char **uci_path_list = NULL;
	size_t uci_path_list_size = 0;
	char *xpath = NULL;
	srpo_uci_transform_data_cb transform_uci_data_cb = NULL;
	bool has_transform_uci_data_private = false;
	char *uci_section_name = NULL;
	char **uci_value_list = NULL;
	size_t uci_value_list_size = 0;

	for (size_t i = 0; i < ARRAY_SIZE(sip_config_files); i++) {
		error = srpo_uci_ucipath_list_get(sip_config_files[i].uci_file, sip_config_files[i].uci_section_list, sip_config_files[i].uci_section_list_size, &uci_path_list, &uci_path_list_size, true);
		if (error) {
			SRP_LOG_ERR("srpo_uci_path_list_get error (%d): %s", error, srpo_uci_error_description_get(error));
			goto error_out;
		}

		for (size_t j = 0; j < uci_path_list_size; j++) {
			error = srpo_uci_ucipath_to_xpath_convert(uci_path_list[j], sip_xpath_uci_path_template_map, ARRAY_SIZE(sip_xpath_uci_path_template_map), &xpath);
			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_to_xpath_path_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				error = 0;
				FREE_SAFE(uci_path_list[j]);
				continue;
			}

			error = srpo_uci_transform_uci_data_cb_get(uci_path_list[j], sip_xpath_uci_path_template_map, ARRAY_SIZE(sip_xpath_uci_path_template_map), &transform_uci_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_uci_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_uci_data_private_get(uci_path_list[j], sip_xpath_uci_path_template_map, ARRAY_SIZE(sip_xpath_uci_path_template_map), &has_transform_uci_data_private);
			if (error) {
				SRP_LOG_ERR("srpo_uci_has_transform_uci_data_private_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			uci_section_name = srpo_uci_section_name_get(uci_path_list[j]);

			error = srpo_uci_element_value_get(uci_path_list[j], transform_uci_data_cb, has_transform_uci_data_private ? uci_section_name : NULL, &uci_value_list, &uci_value_list_size);
			if (error) {
				SRP_LOG_ERR("srpo_uci_element_value_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			for (size_t k = 0; k < uci_value_list_size; k++) {
				error = sr_set_item_str(session, xpath, uci_value_list[k], NULL, SR_EDIT_DEFAULT);
				if (error) {
					SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
					goto error_out;
				}

				FREE_SAFE(uci_value_list[k]);
			}

			FREE_SAFE(uci_section_name);
			FREE_SAFE(uci_path_list[j]);
			FREE_SAFE(xpath);
			FREE_SAFE(uci_value_list);
		}

		FREE_SAFE(uci_path_list);
	}

	error = sr_apply_changes(session, 0, 0);
	if (error) {
		SRP_LOG_ERR("sr_apply_changes error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	goto out;

error_out:
	FREE_SAFE(xpath);
	FREE_SAFE(uci_section_name);

	for (size_t i = 0; i < uci_path_list_size; i++) {
		FREE_SAFE(uci_path_list[i]);
	}

	FREE_SAFE(uci_path_list);

	for (size_t i = 0; i < uci_value_list_size; i++) {
		FREE_SAFE(uci_value_list[i]);
	}

	FREE_SAFE(uci_value_list);

out:
	return error ? -1 : 0;
}

void sip_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	srpo_uci_cleanup();

	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;

	if (startup_session) {
		sr_session_stop(startup_session);
	}

	SRP_LOG_INFMSG("plugin cleanup finished");
}


static int sip_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = 0;
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;
	sr_change_iter_t *sip_server_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const struct lyd_node *node = NULL;
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	bool prev_default = false;
	char *node_xpath = NULL;
	const char *node_value = NULL;
	char *uci_path = NULL;
	struct lyd_node_leaf_list *node_leaf_list;
	struct lys_node_leaf *schema_node_leaf;
	srpo_uci_transform_data_cb transform_sysrepo_data_cb = NULL;
	bool has_transform_sysrepo_data_private = false;
	const char *uci_section_type = NULL;
	char *uci_section_name = NULL;
	void *transform_cb_data = NULL;

	SRP_LOG_INF("module_name: %s, xpath: %s, event: %d, request_id: %" PRIu32, module_name, xpath, event, request_id);

	if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto error_out;
	}

	if (event == SR_EV_DONE) {
		error = sr_copy_config(startup_session, SIP_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &sip_server_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}

		while (sr_get_change_tree_next(session, sip_server_change_iter, &operation, &node, &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = sip_xpath_get(node);

			error = srpo_uci_xpath_to_ucipath_convert(node_xpath, sip_xpath_uci_path_template_map, ARRAY_SIZE(sip_xpath_uci_path_template_map), &uci_path);
			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_xpath_to_ucipath_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				error = 0;
				SRP_LOG_DBG("xpath %s not found in table", node_xpath);
				FREE_SAFE(node_xpath);
				continue;
			}

			error = srpo_uci_transform_sysrepo_data_cb_get(node_xpath, sip_xpath_uci_path_template_map, ARRAY_SIZE(sip_xpath_uci_path_template_map), &transform_sysrepo_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_sysrepo_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_sysrepo_data_private_get(node_xpath, sip_xpath_uci_path_template_map, ARRAY_SIZE(sip_xpath_uci_path_template_map), &has_transform_sysrepo_data_private);
			if (error) {
				SRP_LOG_ERR("srpo_uci_has_transform_sysrepo_data_private_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_section_type_get(uci_path, sip_xpath_uci_path_template_map, ARRAY_SIZE(sip_xpath_uci_path_template_map), &uci_section_type);
			if (error) {
				SRP_LOG_ERR("srpo_uci_section_type_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			uci_section_name = srpo_uci_section_name_get(uci_path);

			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				node_leaf_list = (struct lyd_node_leaf_list *) node;
				node_value = node_leaf_list->value_str;
				if (node_value == NULL) {
					schema_node_leaf = (struct lys_node_leaf *) node_leaf_list->schema;
					node_value = schema_node_leaf->dflt ? schema_node_leaf->dflt : "";
				}
			}

			SRP_LOG_DBG("uci_path: %s; prev_val: %s; node_val: %s; operation: %d", uci_path, prev_value, node_value, operation);

			if (node->schema->nodetype == LYS_LIST) {
				if (operation == SR_OP_CREATED) {
					error = srpo_uci_section_create(uci_path, uci_section_type);
					if (error) {
						SRP_LOG_ERR("srpo_uci_section_create error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_section_delete(uci_path);
					if (error) {
						SRP_LOG_ERR("srpo_uci_section_delete error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAF) {
				if (operation == SR_OP_CREATED || operation == SR_OP_MODIFIED) {
					if (has_transform_sysrepo_data_private && strstr(node_xpath, "stop")) {
						transform_cb_data = (void *) &(leasetime_data_t){.uci_section_name = uci_section_name, .sr_session = session};
					} else if (has_transform_sysrepo_data_private) {
						transform_cb_data = uci_section_name;
					} else {
						transform_cb_data = NULL;
					}

					error = srpo_uci_option_set(uci_path, node_value, transform_sysrepo_data_cb, transform_cb_data);
					if (error) {
						SRP_LOG_ERR("srpo_uci_option_set error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_option_remove(uci_path);
					if (error) {
						SRP_LOG_ERR("srpo_uci_option_remove error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAFLIST) {
				if (has_transform_sysrepo_data_private) {
					transform_cb_data = uci_section_name;
				} else {
					transform_cb_data = NULL;
				}

				if (operation == SR_OP_CREATED) {
					error = srpo_uci_list_set(uci_path, node_value, transform_sysrepo_data_cb, transform_cb_data);
					if (error) {
						SRP_LOG_ERR("srpo_uci_list_set error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_list_remove(uci_path, node_value);
					if (error) {
						SRP_LOG_ERR("srpo_uci_list_remove error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			}
			FREE_SAFE(uci_section_name);
			FREE_SAFE(uci_path);
			FREE_SAFE(node_xpath);
			node_value = NULL;
		}

		srpo_uci_commit("voice_client");
	}

	goto out;

error_out:
	srpo_uci_revert("voice_client");

out:
	FREE_SAFE(uci_section_name);
	FREE_SAFE(node_xpath);
	FREE_SAFE(uci_path);
	sr_free_change_iter(sip_server_change_iter);

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static char *sip_xpath_get(const struct lyd_node *node)
{
	char *xpath_node = NULL;
	char *xpath_leaflist_open_bracket = NULL;
	size_t xpath_trimed_size = 0;
	char *xpath_trimed = NULL;

	if (node->schema->nodetype == LYS_LEAFLIST) {
		xpath_node = lyd_path(node);
		xpath_leaflist_open_bracket = strrchr(xpath_node, '[');
		if (xpath_leaflist_open_bracket == NULL) {
			return xpath_node;
		}

		xpath_trimed_size = (size_t) xpath_leaflist_open_bracket - (size_t) xpath_node + 1;
		xpath_trimed = xcalloc(1, xpath_trimed_size);
		strncpy(xpath_trimed, xpath_node, xpath_trimed_size - 1);
		xpath_trimed[xpath_trimed_size - 1] = '\0';

		FREE_SAFE(xpath_node);

		return xpath_trimed;
	} else {
		return lyd_path(node);
	}
}

static int sip_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	srpo_ubus_result_values_t *values = NULL;
	srpo_ubus_call_data_t ubus_call_data = {.lookup_path = "asterisk.sip", .method = "registry_status", .transform_data_cb = sip_ubus, .timeout = 0, .json_call_arguments = NULL};
	int error = SRPO_UBUS_ERR_OK;

	error = srpo_ubus_call(values, &ubus_call_data);
	if (error != SRPO_UBUS_ERR_OK) {
		SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
		goto out;
	}

	error = store_ubus_values_to_datastore(session, request_xpath, values, parent);
		if (error != SRPO_UBUS_ERR_OK) {
		SRP_LOG_ERR("store_ubus_values_to_datastore error (%d)", error);
		goto out;
	}

	srpo_ubus_free_result_values(values);
	values = NULL;

out:
	if (values) {
		srpo_ubus_free_result_values(values);
	}

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static void sip_ubus(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	json_object *result = NULL;
	json_object *child_value = NULL;
	const char *value_string = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);

	json_object_object_foreach(result, key, value)
	{
		for (size_t i = 0; i < ARRAY_SIZE(sip_transform_table); i++) {
			json_object_object_get_ex(value, sip_transform_table[i].value_name, &child_value);
			if (child_value == NULL) {
				goto cleanup;
			}

			value_string = json_object_get_string(child_value);

			error = srpo_ubus_result_values_add(values, value_string, strlen(value_string),sip_transform_table[i].xpath_template,strlen(sip_transform_table[i].xpath_template),key, strlen(key));
			if (error != SRPO_UBUS_ERR_OK) {
				goto cleanup;
			}
		}
	}

cleanup:
	json_object_put(result);
	return ;
}

static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent)
{
	const struct ly_ctx *ly_ctx = NULL;
	if (*parent == NULL) {
		ly_ctx = sr_get_context(sr_session_get_connection(session));
		if (ly_ctx == NULL) {
			return -1;
		}
		*parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
	}

	for (size_t i = 0; i < values->num_values; i++) {
		lyd_new_path(*parent, NULL, values->values[i].xpath, values->values[i].value, 0, 0);
	}

	return 0;
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

int main()
{
	int error = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_data = NULL;

	sr_log_stderr(SR_LL_DBG);

	/* connect to sysrepo */
	error = sr_connect(SR_CONN_DEFAULT, &connection);
	if (error) {
		SRP_LOG_ERR("sr_connect error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sip_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("sip_plugin_init_cb error");
		goto out;
	}

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1); /* or do some more useful work... */
	}

out:
	sip_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
