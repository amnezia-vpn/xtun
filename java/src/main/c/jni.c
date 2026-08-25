#include <jni.h>
#include <stdlib.h>

#include "xtun.h"

#define LIBXTUN_ERR_JNI_NOMEM       LIBXTUN_ERR_RESERVED_0
#define LIBXTUN_ERR_JNI_WRONG_PROTO LIBXTUN_ERR_RESERVED_1
#define LIBXTUN_ERR_JNI_CLOSED      LIBXTUN_ERR_RESERVED_2

static JavaVM *g_vm;

static jclass    g_XtunException;
static jmethodID g_XtunException_init;

static jmethodID g_XtunProxy_onSocketCreated;
static jmethodID g_XtunProxy_onLog;
static jmethodID g_XtunProxy_onStatus;

static jfieldID g_XtunProxy_handle;

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
            if ((*g_vm)->AttachCurrentThreadAsDaemon(g_vm, &env, NULL) != JNI_OK)
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

static void throwException(JNIEnv *env, int code) {
    jobject obj;

    obj = (*env)->NewObject(env, g_XtunException, g_XtunException_init, code);
    if (obj == NULL)
        return;

    (*env)->Throw(env, (jthrowable)obj);
    (*env)->DeleteLocalRef(env, obj);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    jclass clazz, gclazz;
    jmethodID method;
    jfieldID field;

    g_vm = vm;

    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

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

    return JNI_VERSION_1_6;
}

JNIEXPORT jlong JNICALL Java_org_amnezia_xtun_XtunProxy_nativeInit(JNIEnv *env, jclass c, jint proto, jstring conf, jobject socketHandler, jobject logHandler, jobject statusHandler)
{
    struct libxtun_proxy* proxy;
    void *onsockspawn_priv, *loghandler_priv, *statushandler_priv;
    int res;
    const char* cstr;

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
        throwException(env, LIBXTUN_ERR_JNI_WRONG_PROTO);
        goto free_statushandler_priv;
    }

    cstr = (*env)->GetStringUTFChars(env, conf, NULL);
    if (cstr == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        goto free_statushandler_priv;
    }

    res = libxtun_proxy_new(proxy, proto, cstr);
    if (res) {
        throwException(env, res);
        goto free_cstr;
    }

    return (jlong)proxy;

free_cstr:
    (*env)->ReleaseStringUTFChars(env, conf, cstr);
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
    if (!proxy) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    (*env)->DeleteGlobalRef(env, proxy->onsockspawn_priv);
    (*env)->DeleteGlobalRef(env, proxy->loghandler_priv);
    (*env)->DeleteGlobalRef(env, proxy->statushandler_priv);
    libxtun_proxy_free(proxy);
    free(proxy);
}

JNIEXPORT jlong JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeInit(JNIEnv *env, jclass c, jint fd) {
    struct libxtun_tunnel *tunnel;
    int res;

    tunnel = malloc(sizeof(struct libxtun_tunnel));
    if (tunnel == NULL) {
        throwException(env, LIBXTUN_ERR_JNI_NOMEM);
        return 0;
    }

    tunnel->handle = NULL;

    res = libxtun_tunnel_new_from_tunfile(tunnel, fd);
    if (res) {
        throwException(env, res);
        goto free_tunnel;
    }

    return (jlong)tunnel;

free_tunnel:
    free(tunnel);
    return 0;
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeFree(JNIEnv *env, jclass c, jlong handle) {
    struct libxtun_tunnel *tunnel = (struct libxtun_tunnel*)handle;
    if (!tunnel) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    libxtun_tunnel_free(tunnel);
    free(tunnel);
}

JNIEXPORT void JNICALL Java_org_amnezia_xtun_XtunTunnel_nativeAttachProxy(JNIEnv *env, jclass c, jlong handle, jobject proxy_obj) {
    struct libxtun_tunnel *tunnel = (struct libxtun_tunnel*)handle;
    struct libxtun_proxy *proxy;
    int res;

    proxy = (struct libxtun_proxy*)(*env)->GetLongField(env, proxy_obj, g_XtunProxy_handle);

    if (!tunnel || !proxy) {
        throwException(env, LIBXTUN_ERR_JNI_CLOSED);
        return;
    }

    res = libxtun_tunnel_attach_proxy(tunnel, proxy);
    if (res) {
        throwException(env, res);
        return;
    }
}
