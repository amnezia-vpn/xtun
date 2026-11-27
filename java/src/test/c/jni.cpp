#include <jni.h>

#include "util/os.h"

extern "C" {

JNIEXPORT jboolean JNICALL Java_org_amnezia_xtun_XtunTestNative_privileged(JNIEnv *, jclass)
{
    return libxtun::test::privileged() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL Java_org_amnezia_xtun_XtunTestNative_createTun(JNIEnv *, jclass)
{
    auto tun = libxtun::test::createTun();
    if (!tun || !libxtun::test::setLinkUp(tun->second)) {
        return -1;
    }
    return tun->first.release();
}

}
