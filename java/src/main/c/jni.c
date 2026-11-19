#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "xtun.h"

#define LIBXTUN_ERR_JNI_NOMEM       LIBXTUN_ERR_RESERVED_0
#define LIBXTUN_ERR_JNI_WRONG_PARAM LIBXTUN_ERR_RESERVED_1
#define LIBXTUN_ERR_JNI_CLOSED      LIBXTUN_ERR_RESERVED_2

static JavaVM *g_vm;

static jclass    g_XtunException;
static jclass    g_String;

static jmethodID g_XtunException_init;
static jmethodID g_XtunProxy_onSocketCreated;
static jmethodID g_XtunProxy_onLog;
static jmethodID g_XtunProxy_onStatus;
static jmethodID g_XtunTunnel_createTun;

static jfieldID g_XtunProxy_handle;

static void throwException(JNIEnv *env, int code) {
    jobject obj;

    obj = (*env)->NewObject(env, g_XtunException, g_XtunException_init, code);
    if (obj == NULL)
        return;

    (*env)->Throw(env, (jthrowable)obj);
    (*env)->DeleteLocalRef(env, obj);
}

static jobjectArray toStringArray(JNIEnv *env, const char *const *list) {
    jobjectArray out;
    jstring str;
    jsize len = 0;
    jsize i;

    if (list != NULL) {
        while(list[len] != NULL)
            len++;
    }

    out = (*env)->NewObjectArray(env, len, g_String, NULL);
    if (out == NULL)
        return NULL;

    for (i = 0; i < len; i++) {
        str = (*env)->NewStringUTF(env, list[i]);
        if (str == NULL)
            goto free_out;

        (*env)->SetObjectArrayElement(env, out, i, str);
        (*env)->DeleteLocalRef(env, str);
    }
    return out;

free_out:
    (*env)->DeleteLocalRef(env, out);
    return NULL;
}

static void freeCStringList(const char **list) {
    size_t i;

    if (list == NULL)
        return;

    for (i = 0; list[i] != NULL; i++) {
        free((char*)list[i]);
    }
    free(list);
}

static const char **toCStringList(JNIEnv *env, jobjectArray jlist) {
    jsize count, i;
    jstring jstr;
    const char *str;
    const char **list;

    count = (*env)->GetArrayLength(env, jlist);
    list = calloc(count + 1, sizeof(char*));
    if (list == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        return NULL;
    }

    for (i = 0; i < count; i++) {
        jstr = (jstring)(*env)->GetObjectArrayElement(env, jlist, i);
        if (jstr == NULL) {
            throwException(env, LIBXTUN_ERR_JNI_WRONG_PARAM);
            goto fail;
        }

        str = (*env)->GetStringUTFChars(env, jstr, NULL);
        if (str == NULL) {
            (*env)->DeleteLocalRef(env, jstr);
            goto fail;
        }

        list[i] = strdup(str);
        (*env)->ReleaseStringUTFChars(env, jstr, str);
        (*env)->DeleteLocalRef(env, jstr);

        if (list[i] == NULL) {
            throwException(env, LIBXTUN_ERR_JNI_NOMEM);
            goto fail;
        }
    }

    return list;

fail:
    freeCStringList(list);
    return NULL;
}

static void loghandler(const char *cstr, void *priv) {
    jobject obj = priv;
    JNIEnv *env;
    jstring str;
    int res;
    int detached = 0;

    if (obj == NULL)
        return;

    res = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
    switch (res) {
        case JNI_EDETACHED:
            if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK)
                return;
            detached = 1;
            break;
        case JNI_OK:
            break;
        default:
            return;
    }

    str = (*env)->NewStringUTF(env, cstr);
    if (str == NULL)
        goto free_env;

    (*env)->CallVoidMethod(env, obj, g_XtunProxy_onLog, str);
    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    (*env)->DeleteLocalRef(env, str);
free_env:
    if (detached)
        (*g_vm)->DetachCurrentThread(g_vm);
}

static void onsockspawn(int socket, void *priv) {
    jobject obj = priv;
    JNIEnv *env;
    int res;
    int detached = 0;

    if (obj == NULL)
        return;

    res = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
    switch (res) {
        case JNI_EDETACHED:
            if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK)
                return;
            detached = 1;
            break;
        case JNI_OK:
            break;
        default:
            return;
    }

    (*env)->CallVoidMethod(env, obj, g_XtunProxy_onSocketCreated, (jint)socket);
    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    if (detached)
        (*g_vm)->DetachCurrentThread(g_vm);
}

static void statushandler(int status, void *priv) {
    jobject obj = priv;
    JNIEnv *env;
    int res;
    int detached = 0;

    if (obj == NULL)
        return;

    res = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
    switch (res) {
        case JNI_EDETACHED:
            if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK)
                return;
            detached = 1;
            break;
        case JNI_OK:
            break;
        default:
            return;
    }

    (*env)->CallVoidMethod(env, obj, g_XtunProxy_onStatus, (jint)status);
    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    if (detached)
        (*g_vm)->DetachCurrentThread(g_vm);
}

static int tunfactory(const char *const *dns, const char *const *includeRoutes, const char *const *excludeRoutes, int mtu, void *priv) {
    jobject obj = priv;
    JNIEnv *env;
    int res;
    int detached = 0;
    jint out = -1;
    jobjectArray jdns, jincludeRoutes, jexcludeRoutes;

    if (obj == NULL)
        return -1;

    res = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
    switch (res) {
        case JNI_EDETACHED:
            if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK)
                return -1;
            detached = 1;
            break;
        case JNI_OK:
            break;
        default:
            return -1;
    }

    jdns = toStringArray(env, dns);
    jincludeRoutes = jdns != NULL ? toStringArray(env, includeRoutes) : NULL;
    jexcludeRoutes = jincludeRoutes != NULL ? toStringArray(env, excludeRoutes) : NULL;
    if (jdns != NULL && jincludeRoutes != NULL && jexcludeRoutes != NULL)
        out = (*env)->CallIntMethod(env, obj, g_XtunTunnel_createTun, jdns, jincludeRoutes, jexcludeRoutes, (jint)mtu);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        out = -1;
    }

    if (jdns != NULL)
        (*env)->DeleteLocalRef(env, jdns);
    if (jincludeRoutes != NULL)
        (*env)->DeleteLocalRef(env, jincludeRoutes);
    if (jexcludeRoutes != NULL)
        (*env)->DeleteLocalRef(env, jexcludeRoutes);

    if (detached)
        (*g_vm)->DetachCurrentThread(g_vm);

    return out;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    jclass clazz, gclazz;
    jmethodID method;
    jfieldID field;

    g_vm = vm;

    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    clazz = (*env)->FindClass(env, "java/lang/String");
    if (clazz == NULL)
        return JNI_ERR;
    gclazz = (*env)->NewGlobalRef(env, clazz);
    if (gclazz == NULL)
        return JNI_ERR;

    g_String = gclazz;

    clazz = (*env)->FindClass(env, "org/amnezia/xtun/XtunException");
    if (clazz == NULL)
        return JNI_ERR;
    method = (*env)->GetMethodID(env, clazz, "<init>", "(I)V");
    if (method == NULL)
        return JNI_ERR;
    gclazz = (*env)->NewGlobalRef(env, clazz);
    if (gclazz == NULL)
        return JNI_ERR;

    g_XtunException = gclazz;
    g_XtunException_init = method;

    clazz = (*env)->FindClass(env, "org/amnezia/xtun/XtunProxy$SocketHandler");
    if (clazz == NULL)
        return JNI_ERR;
    method = (*env)->GetMethodID(env, clazz, "onSocketCreated", "(I)V");
    if (method == NULL)
        return JNI_ERR;

    g_XtunProxy_onSocketCreated = method;

    clazz = (*env)->FindClass(env, "org/amnezia/xtun/XtunProxy$LogHandler");
    if (clazz == NULL)
        return JNI_ERR;
    method = (*env)->GetMethodID(env, clazz, "onLog", "(Ljava/lang/String;)V");
    if (method == NULL)
        return JNI_ERR;

    g_XtunProxy_onLog = method;

    clazz = (*env)->FindClass(env, "org/amnezia/xtun/XtunProxy$StatusHandler");
    if (clazz == NULL)
        return JNI_ERR;
    method = (*env)->GetMethodID(env, clazz, "onStatus", "(I)V");
    if (method == NULL)
        return JNI_ERR;

    g_XtunProxy_onStatus = method;

    clazz = (*env)->FindClass(env, "org/amnezia/xtun/XtunProxy");
    if (clazz == NULL)
        return JNI_ERR;
    field = (*env)->GetFieldID(env, clazz, "handle", "J");
    if (field == NULL)
        return JNI_ERR;

    g_XtunProxy_handle = field;

    clazz = (*env)->FindClass(env, "org/amnezia/xtun/XtunTunnel$TunFactory");
    if (clazz == NULL)
        return JNI_ERR;
    method = (*env)->GetMethodID(env, clazz, "createTun", "([Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;I)I");
    if (method == NULL)
        return JNI_ERR;

    g_XtunTunnel_createTun = method;

    return JNI_VERSION_1_6;
}

JNIEXPORT jlong JNICALL Java_org_amnezia_xtun_XtunProxy_nativeInit(JNIEnv *env, jclass c, jint proto, jstring conf, jobjectArray jincludeRoutes, jobjectArray jexcludeRoutes, jobject socketHandler, jobject logHandler, jobject statusHandler)
{
    struct libxtun_proxy* proxy;
    struct libxtun_proxy_opts opts;
    void *onsockspawn_priv, *loghandler_priv, *statushandler_priv;
    int res;
    const char* cstr;
    const char **includeRoutes = NULL, **excludeRoutes = NULL;

    proxy = malloc(sizeof(struct libxtun_proxy));
    if (proxy == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        return 0;
    }

    onsockspawn_priv = (*env)->NewGlobalRef(env, socketHandler);
    if (onsockspawn_priv == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        goto free_proxy;
    }

    loghandler_priv = (*env)->NewGlobalRef(env, logHandler);
    if (loghandler_priv == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        goto free_onsockspawn_priv;
    }

    statushandler_priv = (*env)->NewGlobalRef(env, statusHandler);
    if (statushandler_priv == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        goto free_loghandler_priv;
    }

    proxy->handle = NULL;
    proxy->loghandler = loghandler;
    proxy->loghandler_priv = loghandler_priv;
    proxy->onsockspawn = onsockspawn;
    proxy->onsockspawn_priv = onsockspawn_priv;
    proxy->statushandler = statushandler;
    proxy->statushandler_priv = statushandler_priv;

    if (proto < 0 || proto > LIBXTUN_PROXY_PROTO_LAST) {
        throwException(env, LIBXTUN_ERR_JNI_WRONG_PARAM);
        goto free_statushandler_priv;
    }

    if (jincludeRoutes != NULL) {
        includeRoutes = toCStringList(env, jincludeRoutes);
        if (includeRoutes == NULL)
            goto free_statushandler_priv;
    }

    if (jexcludeRoutes != NULL) {
        excludeRoutes = toCStringList(env, jexcludeRoutes);
        if (excludeRoutes == NULL)
            goto free_includeRoutes;
    }

    cstr = (*env)->GetStringUTFChars(env, conf, NULL);
    if (cstr == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        goto free_excludeRoutes;
    }

    opts.size = sizeof(struct libxtun_proxy_opts);
    opts.includeRoutes = includeRoutes;
    opts.excludeRoutes = excludeRoutes;

    res = libxtun_proxy_new(proxy, proto, cstr, &opts);
    (*env)->ReleaseStringUTFChars(env, conf, cstr);

    if (res) {
        throwException(env, res);
        goto free_excludeRoutes;
    }

    freeCStringList(excludeRoutes);
    freeCStringList(includeRoutes);
    return (jlong)proxy;

free_excludeRoutes:
    freeCStringList(excludeRoutes);
free_includeRoutes:
    freeCStringList(includeRoutes);
free_statushandler_priv:
    (*env)->DeleteGlobalRef(env, statushandler_priv);
free_loghandler_priv:
    (*env)->DeleteGlobalRef(env, loghandler_priv);
free_onsockspawn_priv:
    (*env)->DeleteGlobalRef(env, onsockspawn_priv);
free_proxy:
    free(proxy);
    return 0;
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunProxy_nativeFree(JNIEnv *env, jclass c, jlong handle)
{
    struct libxtun_proxy* proxy = (struct libxtun_proxy*)handle;
    if (proxy == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    libxtun_proxy_free(proxy);
    (*env)->DeleteGlobalRef(env, proxy->onsockspawn_priv);
    (*env)->DeleteGlobalRef(env, proxy->loghandler_priv);
    (*env)->DeleteGlobalRef(env, proxy->statushandler_priv);
    free(proxy);
}

struct libxtun_jtunnel
{
    struct libxtun_tunnel tunnel;
    void *priv;
};

JNIEXPORT jlong JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeInit(JNIEnv *env, jclass c, jobject tunfactoryHandle, jobjectArray jifaddrs) {
    struct libxtun_jtunnel *jtunnel;
    struct libxtun_tunfactory factory;
    int res = -1;
    const char **ifaddrs;

    if (jifaddrs == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_WRONG_PARAM);
        return 0;
    }

    jtunnel = malloc(sizeof(struct libxtun_jtunnel));
    if (jtunnel == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        return 0;
    }

    jtunnel->tunnel.handle = NULL;
    jtunnel->priv = (*env)->NewGlobalRef(env, tunfactoryHandle);
    if (jtunnel->priv == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        goto free_jtunnel;
    }

    ifaddrs = toCStringList(env, jifaddrs);
    if (ifaddrs == NULL) {
        goto free_priv;
    }

    factory.size = sizeof(struct libxtun_tunfactory);
    factory.factory_func = tunfactory;
    factory.factory_priv = jtunnel->priv;
    factory.if_addrs = ifaddrs;

    res = libxtun_tunnel_new_from_tunfactory(&jtunnel->tunnel, &factory);
    if (res) {
        throwException(env, res);
    }

    freeCStringList(ifaddrs);

    if (res == 0) {
        return (jlong)jtunnel;
    }
free_priv:
    (*env)->DeleteGlobalRef(env, jtunnel->priv);
free_jtunnel:
    free(jtunnel);
    return 0;
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeFree(JNIEnv *env, jclass c, jlong handle) {
    struct libxtun_jtunnel *jtunnel = (struct libxtun_jtunnel*)handle;
    if (jtunnel == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    libxtun_tunnel_free(&jtunnel->tunnel);
    (*env)->DeleteGlobalRef(env, jtunnel->priv);
    free(jtunnel);
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeStart(JNIEnv *env, jclass c, jlong handle) {
    struct libxtun_jtunnel *jtunnel = (struct libxtun_jtunnel*)handle;
    int res;

    if (jtunnel == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    res = libxtun_tunnel_start(&jtunnel->tunnel);
    if (res) {
        throwException(env, res);
        return;
    }
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeAttachProxy(JNIEnv *env, jclass c, jlong handle, jobject proxy_obj) {
    struct libxtun_jtunnel *jtunnel = (struct libxtun_jtunnel*)handle;
    struct libxtun_proxy *proxy;
    int res;

    proxy = (struct libxtun_proxy*)(*env)->GetLongField(env, proxy_obj, g_XtunProxy_handle);

    if (jtunnel == NULL || proxy == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    res = libxtun_tunnel_attach_proxy(&jtunnel->tunnel, proxy);
    if (res) {
        throwException(env, res);
        return;
    }
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeDetachProxy(JNIEnv *env, jclass c, jlong handle, jobject proxy_obj) {
    struct libxtun_jtunnel *jtunnel = (struct libxtun_jtunnel*)handle;
    struct libxtun_proxy *proxy;

    proxy = (struct libxtun_proxy*)(*env)->GetLongField(env, proxy_obj, g_XtunProxy_handle);

    if (jtunnel == NULL || proxy == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    libxtun_tunnel_detach_proxy(&jtunnel->tunnel, proxy);
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeNetworkChanged(JNIEnv *env, jclass c, jlong handle) {
    struct libxtun_jtunnel *jtunnel = (struct libxtun_jtunnel*)handle;

    if (jtunnel == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    libxtun_tunnel_network_changed(&jtunnel->tunnel);
}

JNIEXPORT jstring JNICALL Java_org_amnezia_xtun_XtunException_nativeDescribe(JNIEnv *env, jclass c, jint code) {
    return (*env)->NewStringUTF(env, libxtun_strerror(code));
}
