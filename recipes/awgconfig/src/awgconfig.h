#ifndef AWGCONFIG_H
#define AWGCONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

int awg_apply_config(const char *conf, const char *name, const char **err);

#ifdef __cplusplus
}
#endif

#endif // AWGCONFIG_H
