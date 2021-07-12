#include "sample_app_events.h"
#include "sample_app_version.h"
#include "sample_app.h"
#include "sample_app_table.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size != sizeof(CFE_SB_Buffer_t)){
    return 1;
    }
    SAMPLE_APP_Init();
    CFE_SB_Buffer_t input;
    memcpy(&input, Data, sizeof(CFE_SB_Buffer_t));
    SAMPLE_APP_ProcessCommandPacket(&input);
    return 0;
}
