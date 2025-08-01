#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    reverseclient_lstate_t *uls = lineGetState(l, t);
    if (uls->pair_connected)
    {
        tunnelPrevDownStreamResume(t, uls->d);
    }
}
