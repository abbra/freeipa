#include <ini_configobj.h>

int ipa_config_from_file(const char *config_file, struct ini_cfgobj *cfgctx);

struct ipa_config {
    const char *server_name;
    const char *domain;
};

int ipa_read_config(const char *config_file, struct ipa_config **ipacfg);

