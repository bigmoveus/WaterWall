#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeTunDeviceGet(void)
{
    const char *type_name     = "TunDevice";
    node_t      node_tundevice = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = tundeviceTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
             .required_padding_left = 0,
             .layer_group           = kNodeLayer3,
             .layer_group_next_node = kNodeLayerAnything,
             .layer_group_prev_node = kNodeLayerAnything,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_tundevice;
}
