#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tundeviceTunnelWritePayload(t, l, buf);
}
