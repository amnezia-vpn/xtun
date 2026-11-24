#include "util/cinterop.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>

namespace
{

    using libxtun::cinterop::readSized;

    struct OptsV1
    {
        size_t size;
        size_t a;
    };

    struct OptsV2
    {
        size_t size;
        size_t a;
        size_t b;
    };

    template<typename L, typename C> L fromClient(const C &client)
    {
        L lib;
        std::memset(&lib, 0xff, sizeof(lib));
        std::memcpy(&lib, &client, std::min(client.size, sizeof(lib)));
        lib.size = client.size;
        return lib;
    }

} // namespace

TEST(CInterop, OptionsStructsArePacked)
{
    EXPECT_EQ(alignof(libxtun_proxy_opts), 1u);
    EXPECT_EQ(alignof(libxtun_tunnel_opts), 1u);
    EXPECT_EQ(alignof(libxtun_tunfactory), 1u);
}

TEST(CInterop, OlderClientGetsZeroForNewerFields)
{
    const OptsV1 client { .size = sizeof(OptsV1), .a = 5 };

    const auto res = readSized(fromClient<OptsV2>(client));
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().a, 5u);
    EXPECT_EQ(res.value().b, 0u);
}

TEST(CInterop, NewerClientIsUnsupported)
{
    const OptsV2 client { .size = sizeof(OptsV2), .a = 5, .b = 7 };

    const auto res = readSized(fromClient<OptsV1>(client));
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), LIBXTUN_ERR_UNSUPPORTED);
}

TEST(CInterop, ZeroSizeReadsAllDefaults)
{
    const OptsV1 client { .size = 0, .a = 5 };

    const auto res = readSized(fromClient<OptsV1>(client));
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().a, 0u);
}
