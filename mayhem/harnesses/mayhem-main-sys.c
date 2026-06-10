/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * tpm2-tss/mayhem/harnesses/mayhem-main-sys.c
 *
 * Drop-in replacement for test/fuzz/main-sys.c that DIRECTLY instantiates the fuzzing TCTI
 * (Tss2_Tcti_Fuzzing_Init) and the System API context, sets the per-iteration fuzz data on the
 * fuzzing TCTI, and calls the generated test_invoke(). It is linked together with each generated
 * test/fuzz/<Cmd>.fuzz.c (which defines test_invoke()).
 *
 * WHY this exists (additive, no upstream edit): the stock test/fuzz/main-sys.c builds the SYS
 * context via test_sys_setup() -> Tss2_TctiLdr_Initialize(getenv("TPM20TEST_TCTI")). With the
 * OSS-Fuzz configure (--disable-shared, --disable-tcti-{device,mssim,swtpm}) the no-dlopen TCTI
 * loader (tctildr-nodl) has an EMPTY registry and never knows the "fuzzing" TCTI, so every input
 * fails at setup and the (un)marshal code is never reached — the harness builds and "iterates" but
 * fuzzes nothing. Even via the dlopen loader, TctiLdr WRAPS the child TCTI, so main-sys.c's
 * tcti_fuzzing_context_cast() would write the fuzz data into the wrapper, not the fuzzing child.
 *
 * This driver sidesteps the loader entirely: it allocates the fuzzing TCTI in place, so the context
 * main-sys's logic casts IS the fuzzing context, and the bytes flow straight into the unmarshalers.
 */
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_sys.h"
#include "tss2_tcti.h"

#include "tcti/tcti-fuzzing.h"        // TSS2_TCTI_FUZZING_CONTEXT, tcti_fuzzing_context_cast
#include "tcti/tss2_tcti_fuzzing.h"   // Tss2_Tcti_Fuzzing_Init

/* Defined by each generated test/fuzz/<Cmd>.fuzz.c */
extern int test_invoke(TSS2_SYS_CONTEXT *sysContext);

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    TSS2_RC                    rc;
    size_t                     tcti_size = 0;
    size_t                     sys_size  = 0;
    TSS2_TCTI_CONTEXT         *tcti_ctx  = NULL;
    TSS2_SYS_CONTEXT          *sys_ctx   = NULL;
    TSS2_TCTI_FUZZING_CONTEXT *fuzzing   = NULL;
    TSS2_ABI_VERSION           abi = {
        .tssCreator = 1, .tssFamily = 2, .tssLevel = 1, .tssVersion = 108,
    };

    /* Instantiate the fuzzing TCTI in place (no loader, no wrapper). */
    rc = Tss2_Tcti_Fuzzing_Init(NULL, &tcti_size, NULL);
    if (rc != TSS2_RC_SUCCESS || tcti_size == 0) {
        return 0;
    }
    tcti_ctx = calloc(1, tcti_size);
    if (tcti_ctx == NULL) {
        return 0;
    }
    rc = Tss2_Tcti_Fuzzing_Init(tcti_ctx, &tcti_size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        free(tcti_ctx);
        return 0;
    }

    /* Build a SYS context on top of the fuzzing TCTI. */
    sys_size = Tss2_Sys_GetContextSize(0);
    sys_ctx  = calloc(1, sys_size);
    if (sys_ctx == NULL) {
        free(tcti_ctx);
        return 0;
    }
    rc = Tss2_Sys_Initialize(sys_ctx, sys_size, tcti_ctx, &abi);
    if (rc != TSS2_RC_SUCCESS) {
        free(sys_ctx);
        free(tcti_ctx);
        return 0;
    }

    /* Hand the current input to the fuzzing TCTI: the _Complete path reads it back as the raw TPM
     * response buffer (unmarshal surface); fuzz_fill() pulls from it for the _Prepare path. */
    fuzzing = tcti_fuzzing_context_cast(tcti_ctx);
    fuzzing->data = Data;
    fuzzing->size = Size;

    /*
     * Prime the SAPI state machine to CMD_STAGE_RECEIVE_RESPONSE so the generated *_Complete
     * harnesses can run: Tss2_Sys_*_Complete() returns TSS2_SYS_RC_BAD_SEQUENCE unless the previous
     * stage is RECEIVE_RESPONSE (sysapi_util.c:CommonComplete). We drive a full no-argument command
     * cycle — GetTestResult_Prepare -> ExecuteAsync -> ExecuteFinish — which makes the fuzzing TCTI
     * deliver the fuzz bytes into ctx->cmdBuffer as the raw TPM response and advances the stage.
     * The subsequent _Complete (or _Prepare, which is happy from any of INITIALIZE/PREPARE/
     * RECEIVE_RESPONSE) then unmarshals/marshals that attacker-controlled buffer. ExecuteFinish
     * already exercises the response-header unmarshal on the fuzz bytes, so even before test_invoke
     * the unmarshalers see the input.
     */
    if (Tss2_Sys_GetTestResult_Prepare(sys_ctx) == TSS2_RC_SUCCESS) {
        if (Tss2_Sys_ExecuteAsync(sys_ctx) == TSS2_RC_SUCCESS) {
            (void)Tss2_Sys_ExecuteFinish(sys_ctx, TSS2_TCTI_TIMEOUT_BLOCK);
        }
    }

    (void)test_invoke(sys_ctx);

    Tss2_Sys_Finalize(sys_ctx);
    free(sys_ctx);
    free(tcti_ctx);
    return 0;
}
