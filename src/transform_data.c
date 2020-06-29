#include <inttypes.h>
#include <string.h>

#include <uci.h>
#include <srpo_uci.h>

#include "transform_data.h"
#include "utils/memory.h"
static struct uci_context *uci_context;

int uci_del(char *uci_data);
int set_uci_section(char *uci_data);
int get_uci_item(char *uci_data, char **value);
int set_uci_item(char *uci_data, char *value);

int uci_del(char *uci_data)
{
	int error = 0;
	struct uci_ptr uci_ptr = {0};

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_data, true);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		goto error_out;
	}

	uci_delete(uci_context, &uci_ptr);
	uci_save(uci_context, uci_ptr.p);

	error = uci_commit(uci_context, &uci_ptr.p, false);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		goto error_out;
	}

error_out:
	return error;
}

int set_uci_section(char *uci_data)
{
	int error = 0;
	struct uci_ptr uci_ptr = {0};

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_data, true);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		goto error_out;
	}

	uci_set(uci_context, &uci_ptr);
	uci_save(uci_context, uci_ptr.p);

	error = uci_commit(uci_context, &uci_ptr.p, false);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		goto error_out;
	}

error_out:
	return error;
}

int get_uci_item(char *uci_data, char **value)
{
	int error = SRPO_UCI_ERR_OK;
	struct uci_ptr uci_ptr = {0};

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_data, true);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		goto error_out;
	}

	if (NULL == uci_ptr.o) {
		error = UCI_ERR_NOTFOUND;
		goto error_out;
	}

	strcpy(*value, uci_ptr.o->v.string);

error_out:
	return error;
}

int set_uci_item(char *uci_data, char *value)
{
	int error = 0;
	struct uci_ptr uci_ptr = {0};

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_data, true);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		goto error_out;
	}

	uci_set(uci_context, &uci_ptr);
	uci_save(uci_context, uci_ptr.p);

	error = uci_commit(uci_context, &uci_ptr.p, false);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		return -1;
	}

error_out:
	return error;
}

char *transform_data_sysrepo_option_callback(const char *value, void *private_data)
{
	char *uci_data = (char *) private_data;
	int error = 0;
	sr_change_oper_t operation;
	struct uci_ptr uci_ptr = {0};

	if (SR_OP_CREATED == operation || SR_OP_MODIFIED == operation) {
		error = set_uci_item(uci_data, value);
		if (error) {
			error = SRPO_UCI_ERR_UCI;
			goto error_out;
		}
	} else if (SR_OP_DELETED == operation) {
		error = uci_del(uci_data);
		if (error) {
			error = SRPO_UCI_ERR_UCI;
			goto error_out;
		}
	}

error_out:
	FREE_SAFE(uci_data);

	return error;
}

char *transform_data_sysrepo_boolean_callback(const char *value, void *private_data)
{
	char *uci_data = (char *) private_data;
	int error = 0;
	sr_change_oper_t operation;
	sr_val_t *val;
	struct uci_ptr uci_ptr = {0};
	char *key;

	if (SR_OP_CREATED == operation || SR_OP_MODIFIED == operation) {
		if (val->data.bool_val) {
			error = set_uci_item(uci_data, value);
			if (error) {
				goto error_out;
			}
		} else {
			error = set_uci_item(uci_data, value);
			if (error) {
				goto error_out;
			}
		}
	} else if (SR_OP_DELETED == operation) {
		error = uci_del(uci_data);
		if (error) {
			error = SRPO_UCI_ERR_UCI;
			goto error_out;
		}
	}

	/*if (val->data.bool_val) {
		sr_val_t *value = NULL;
		char password_xpath[XPATH_MAX_LEN] = {0};
		char password_ucipath[XPATH_MAX_LEN] = {0};
   		snprintf(password_xpath, XPATH_MAX_LEN, "/terastream-sip:sip/sip-account[account='%s']/password", key);
		snprintf(password_ucipath, XPATH_MAX_LEN, "voice_client.%s.secret", key);


	}*/

error_out:
	FREE_SAFE(uci_data);

	return error;
}

char *transform_data_sysrepo_section_callback(const char *value, void *private_data)
{
	char *uci_data = (char *) private_data;
	int error = SRPO_UCI_ERR_OK;
	char *element = "sip_service_provider";
	sr_change_oper_t operation;
	struct uci_ptr uci_ptr = {0};
	const char *uci_section_type = NULL;

	if (SR_OP_CREATED == operation || SR_OP_MODIFIED == operation) {
		error = set_uci_section(uci_data);
		if (error) {
			return -1;
		} else if (SR_OP_DELETED == operation) {
			error = uci_del(uci_data);
			if (error) {
				goto error_out;
			}
		}
	}

error_out:
	FREE_SAFE(uci_data);

	return error;
}

char *transform_data_sysrepo_list_callback(const char *value, void *private_data)
{
	char *uci_data = (char *) private_data;
	int error = SRPO_UCI_ERR_OK;
	struct uci_ptr uci_ptr = {0};
	char *uci_config_tmp = NULL;
	sr_val_t *val;
	sr_change_oper_t operation;
	char ucipath[] = "voice_client.direct_dial.direct_dial";
	char xpath[] = "/terastream-sip:sip/digitmap/dials";

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_config_tmp, true);
	if (error) {
		error = SRPO_UCI_ERR_UCI;
		goto error_out;
	}

	if (NULL != uci_ptr.o) {
		uci_delete(uci_context, &uci_ptr);
		uci_save(uci_context, uci_ptr.p);
		error = uci_commit(uci_context, &uci_ptr.p, false);
		if (error) {
			error = SRPO_UCI_ERR_UCI;
			goto error_out;
		}
	}

error_out:
	FREE_SAFE(uci_config_tmp);

	return error;
}

char *transform_data_sysrepo_list_callback_enable(const char *value, void *private_data)
{
	char *uci_data = (char *) private_data;
	int error = SRPO_UCI_ERR_OK;
	char *uci_config_tmp = NULL;
	struct uci_ptr uci_ptr = {0};
	size_t count = 0;
	char ucipath[] = "voice_client.direct_dial.direct_dial";
	sr_change_oper_t operation;
	sr_val_t *val;

	if (SR_OP_CREATED == operation || SR_OP_MODIFIED == operation) {
		if (false == val->data.bool_val) {
			error = uci_lookup_ptr(uci_context, &uci_ptr, uci_config_tmp, true);
			if (error) {
				error = SRPO_UCI_ERR_UCI;
				goto error_out;
			}

			if (NULL != uci_ptr.o) {
				uci_delete(uci_context, &uci_ptr);
				uci_save(uci_context, uci_ptr.p);
				error = uci_commit(uci_context, &uci_ptr.p, false);
				if (error) {
					error = SRPO_UCI_ERR_UCI;
					goto error_out;
				}
			}

		} else {
			return transform_data_sysrepo_list_callback((char *) value, ucipath);
		}
	} else if (SR_OP_DELETED == operation) {
		return NULL;
	}

error_out:
	FREE_SAFE(uci_config_tmp);

	return error;
}
