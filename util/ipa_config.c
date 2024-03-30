#include <errno.h>
#include "ipa_config.h"

int ipa_config_from_file(const char *config_file, struct ini_cfgobj *cfgctx)
{
    struct ini_cfgfile *fctx = NULL;
    char **errors = NULL;
    int ret;

    ret = ini_config_file_open(config_file, 0, &fctx);
    if (ret) {
        fprintf(stderr, "Failed to open config file %s\n", config_file);
        return ret;
    }

    ret = ini_config_parse(fctx,
                           INI_STOP_ON_ANY,
                           INI_MS_MERGE | INI_MV1S_ALLOW | INI_MV2S_ALLOW,
                           INI_PARSE_NOWRAP,
                           cfgctx);
    if (ret) {
        fprintf(stderr, "Failed to parse config file %s\n", config_file);
        if (ini_config_error_count(cfgctx)) {
            ini_config_get_errors(cfgctx, &errors);
            if (errors) {
                ini_config_print_errors(stderr, errors);
                ini_config_free_errors(errors);
            }
        }
        ini_config_file_destroy(fctx);
        return ret;
    }

    ini_config_file_destroy(fctx);
    return 0;
}

int ipa_read_config(const char *config_file, struct ipa_config **ipacfg)
{
    struct ini_cfgobj *cfgctx = NULL;
    struct value_obj *obj = NULL;
    int ret;

    *ipacfg = calloc(1, sizeof(struct ipa_config));
    if (!*ipacfg) {
        return ENOMEM;
    }

    ret = ini_config_create(&cfgctx);
    if (ret) {
        return ENOENT;
    }

    ret = ipa_config_from_file(config_file, cfgctx);
    if (ret) {
        ini_config_destroy(cfgctx);
        return EINVAL;
    }

    ret = ini_get_config_valueobj("global", "server", cfgctx,
                                  INI_GET_LAST_VALUE, &obj);
    if (ret != 0 || obj == NULL) {
        /* if called on an IPA server we need to look for 'host' instead */
        ret = ini_get_config_valueobj("global", "host", cfgctx,
                                      INI_GET_LAST_VALUE, &obj);
    }

    if (ret == 0 && obj != NULL) {
        (*ipacfg)->server_name = ini_get_string_config_value(obj, &ret);
    }
    ret = ini_get_config_valueobj("global", "domain", cfgctx,
                                  INI_GET_LAST_VALUE, &obj);
    if (ret == 0 && obj != NULL) {
        (*ipacfg)->domain = ini_get_string_config_value(obj, &ret);
    }

    return 0;
}

