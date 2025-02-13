#include "sample_app_events.h"
#include "sample_app_version.h"
#include "sample_app.h"
#include "sample_app_table.h"


#include "cfe_es_module_all.h"

void init(void) {
  CFE_ES_ResetData_t* reset = malloc(sizeof(CFE_ES_ResetData_t));
    // init CFE_EVS_GLOBAL
    // memset(&CFE_EVS_Global, 0, sizeof(CFE_EVS_Global));

    // CFE_MSG_Init(&CFE_EVS_Global.EVS_TlmPkt.TlmHeader.Msg, CFE_SB_ValueToMsgId(CFE_EVS_HK_TLM_MID),
    //              sizeof(CFE_EVS_Global.EVS_TlmPkt));

    // CFE_EVS_Global.EVS_TlmPkt.Payload.MessageFormatMode = CFE_PLATFORM_EVS_DEFAULT_MSG_FORMAT_MODE;
    // CFE_EVS_Global.EVS_TlmPkt.Payload.OutputPort        = CFE_PLATFORM_EVS_PORT_DEFAULT;
    // CFE_EVS_Global.EVS_TlmPkt.Payload.LogMode           = CFE_PLATFORM_EVS_DEFAULT_LOG_MODE;

    // CFE_EVS_Global.EVS_LogPtr = &reset->EVS_Log;
    // CFE_EVS_Global.EVS_LogPtr->LogCount = 0;
    // CFE_EVS_Global.EVS_LogPtr->LogFullFlag = 0;
    // CFE_EVS_Global.EVS_LogPtr->LogMode = 0;
    // CFE_EVS_Global.EVS_LogPtr->LogOverflowCounter = 0;

    // OS_MutSemCreate(&CFE_EVS_Global.EVS_SharedDataMutexID, "CFE_EVS_DataMutex", 0);

    // init CFE_ES_GLOBAL
    memset(&CFE_ES_Global, 0, sizeof(CFE_ES_Global));
    OS_MutSemCreate(&(CFE_ES_Global.SharedDataMutex), "ES_DATA_MUTEX", 0);
    CFE_ES_Global.LastAppId              = CFE_ResourceId_FromInteger(0);
    CFE_ES_Global.LastLibId              = CFE_ResourceId_FromInteger(0);
    CFE_ES_Global.LastCounterId          = CFE_ResourceId_FromInteger(0);
    CFE_ES_Global.LastMemPoolId          = CFE_ResourceId_FromInteger(0);
    CFE_ES_Global.CDSVars.LastCDSBlockId = CFE_ResourceId_FromInteger(0);

    CFE_ES_Global.ResetDataPtr = reset;
    CFE_ES_Global.ResetDataPtr->ResetVars.ES_CausedReset = false;
    CFE_ES_Global.ResetDataPtr->ResetVars.ResetSubtype = 2; //CFE_PSP_RST_TYPE_POWERON I'm just lazy and don't want to do the include
    CFE_ES_Global.ResetDataPtr->ResetVars.ResetType    = CFE_PSP_RST_TYPE_POWERON;
    CFE_ES_Global.ResetDataPtr->ResetVars.ProcessorResetCount    = 0;
    CFE_ES_Global.ResetDataPtr->ResetVars.MaxProcessorResetCount = CFE_PLATFORM_ES_MAX_PROCESSOR_RESETS;
    CFE_ES_Global.DebugVars.DebugFlag                            = 0;

    CFE_ES_Global.SystemState = CFE_ES_SystemState_OPERATIONAL;
}

void uninit(void) {
  // free(CFE_EVS_Global.EVS_LogPtr);
  free(CFE_ES_Global.ResetDataPtr);
}



int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size != sizeof(CFE_SB_Buffer_t)){
    return 1;
    }
    init();
    SAMPLE_APP_Init();
    CFE_SB_Buffer_t input;
    memcpy(&input, Data, sizeof(CFE_SB_Buffer_t));
    SAMPLE_APP_ProcessCommandPacket(&input);
    uninit();
    return 0;
}
