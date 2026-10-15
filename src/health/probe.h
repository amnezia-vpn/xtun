#ifndef HEALTH_PROBE_H
#define HEALTH_PROBE_H

namespace libxtun::health
{
    class Probe
    {
    public:
        virtual ~Probe() {};
        virtual void sendProbe() = 0;
    };

    class DummyProbe final : public Probe
    {
    public:
        void sendProbe() override {};
    };
}

#endif // HEALTH_PROBE_H
