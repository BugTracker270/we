#pragma once
/*
 * offsets_1352.h — PS4 firmware 13.52 SELF-decrypter offsets
 *
 * Every KNOWN value here is either:
 *   [SDK]      already defined in libPS4/include/fw_defines.h  (K1352_*)
 *   [DERIVED]  recovered by static analysis of the decrypted 13.52 kernel
 *              (czdji0/1352k.elf). Evidence in 1352-OFFSET-DERIVATION.md.
 *
 * All KO values are offsets from kernel_base (0xffffffff82200000) and must be
 * added to the runtime kernel_base obtained from LSTAR / __readmsr(0xC0000082).
 *
 * Provenance legend:
 *   [V] verified against the image (independent cross-check)
 *   [D] derived from disassembly of the calling code
 *   [P] PENDING — signature/layout not yet confirmed; first run must be a probe
 */

#ifndef OFFSETS_1352_H
#define OFFSETS_1352_H

/* ------------------------------------------------------------------ */
/* Kernel image geometry  [V]                                          */
/* ------------------------------------------------------------------ */
#define KO_1352_TEXT_BASE       0x000000000ULL   /* 0xffffffff82200000        */
#define KO_1352_TEXT_END        0x00cfe758ULL    /* end of .text              */
#define KO_1352_DATA_START      0x01520000ULL    /* 0xffffffff83720000        */
#define KO_1352_DATA_FILE_END   0x01b265e8ULL    /* end of file-backed .data  */
                                             /* above here == .bss          */

/* ------------------------------------------------------------------ */
/* AuthMgr — secure module block            [D]                        */
/* ------------------------------------------------------------------ */
#define KO_1352_AUTHMGR_HANDLE      0x0269C0A0ULL  /* SM handle. WRITTEN BY  */
                                                   /* _sceSblAuthMgrSmStart  */
                                                   /* (passed as its arg6).  */
                                                   /* 0 until the SM starts. */
#define KO_1352_SM_FLAG             0x0269C098ULL  /* byte: "SM started". 0 =  */
                                                   /* not started; SmStart is  */
                                                   /* guarded on this, so it   */
                                                   /* is idempotent.           */
#define KO_1352_SM_MTX              0x0269C0C8ULL  /* mtx SmStart locks        */
#define KO_1352_AUTHMGR_BUF_A       0x0269C0B0ULL  /* 0x88 auth-info staging */
#define KO_1352_AUTHMGR_BUF_B       0x0269C0C0ULL  /* 0x88 staging (+0x88)   */
#define KO_1352_AUTHMGR_MTX         0x0269C0C8ULL  /* mtx around mailbox call*/
#define KO_1352_AUTHMGR_LOCK2       0x0269C0E8ULL  /* sibling-fn lock        */

/* AuthMgr context table: 4 entries, stride 0x60            [D]        */
#define KO_1352_AUTHMGR_CTX_TABLE   0x0269C140ULL
#define KO_1352_AUTHMGR_CTX_STRIDE  0x60
#define KO_1352_AUTHMGR_CTX_COUNT   4
#define KO_1352_AUTHMGR_CTX_BUFBASE 0x0269C2C0ULL  /* + idx*0x1000 per ctx   */
#define CTX_OFF_STATE               0x00           /* int  state: 1 or 2 when
                                                        active (IsLoadable
                                                        requires 1 or 2)       */
#define CTX_OFF_INDEX               0x30           /* int  ctx index         */
#define CTX_OFF_BUFFER              0x38           /* ptr  0x1000 buffer     */
#define CTX_OFF_MTX                 0x40           /* mtx  "authmgr_ctx"     */

/* ------------------------------------------------------------------ */
/* SBL service-request cluster (sm_service/req.c)   [D]                 */
/* ------------------------------------------------------------------ */
#define KO_1352_SBLREQ_OBJECT       0x02681B80ULL  /* 0x1C0-byte object      */
#define KO_1352_SBLREQ_CV_A         0x02681C30ULL  /* cv  "req msg cv"       */
#define KO_1352_SBLREQ_CV_B         0x02681CF0ULL  /* cv  "req msg cv"       */
#define KO_1352_SBLREQ_MTX          0x02681D10ULL  /* mtx "req mtx"          */
#define KO_1352_SBLREQ_CV_C         0x02681D30ULL  /* cv  "req cv"           */

/* ------------------------------------------------------------------ */
/* SBL driver lock set (sbl/driver/handler.c)       [D]                 */
/* ------------------------------------------------------------------ */
#define KO_1352_SBLDRV_OBJECT       0x026473C0ULL  /* 0x138-byte object      */
#define KO_1352_SBLDRV_HDLR_SX      0x02647398ULL  /* sx  "SblDrvHdlrSx"     */
#define KO_1352_SBLDRV_INHDLR_MTX   0x026474F8ULL  /* mtx "SblDrvInHdlrMtx"  */
#define KO_1352_SBLDRV_SEND_SX      0x02647518ULL  /* sx  "SblDrvSendSx"     */
#define KO_1352_SBLDRV_NEXT_SX      0x02647538ULL  /* sx  "SblDrvNextSx"     */
#define KO_1352_SBLDRV_NEXT_CV      0x02647558ULL  /* cv  "SblDrvNextCv"     */

/* ------------------------------------------------------------------ */
/* Kernel functions                                 [D]/[V]             */
/* ------------------------------------------------------------------ */
/* sceSblServiceMailbox(service_id, in_ptr, out_ptr)                    */
#define KO_1352_FN_SERVICE_MAILBOX  0x00630230ULL
/* sceSblAuthMgrSmRequest(ctx, arg, _, auth_info_in, auth_info_out)     */
#define KO_1352_FN_SM_REQUEST       0x0063fff0ULL

/* Public AuthMgr API. Function ENTRY points, both prologue-matched and  */
/* confirmed call targets in the image.                     [V]         */
#define KO_1352_FN_AUTHMGR_ISLOADABLE 0x00642880ULL  /* sceSblAuthMgrIsLoadable  */
#define KO_1352_FN_AUTHMGR_AUTHHDR    0x00642c90ULL  /* sceSblAuthMgrAuthHeader  */
#define KO_1352_FN_AUTHMGR_FINALIZE   0x00643370ULL  /* sceSblAuthMgrFinalize    */
#define KO_1352_FN_AUTHMGR_LOAD       0x006434d0ULL  /* LoadSegment/LoadBlock    */
                                                     /* [P] shared boundary —    */
                                                     /* split still unconfirmed  */
#define KO_1352_FN_SM_FINALIZE        0x0063ff00ULL  /* _sceSblAuthMgrSmFinalize */
#define KO_1352_FN_SM_START           0x0063e470ULL  /* _sceSblAuthMgrSmStart    */
#define KO_1352_FN_LOAD_SELF_BLOCK    0x0063d180ULL  /* _sceSblAuthMgrLoadSelfBlock */
#define KO_1352_FN_CHECK_SELF_HEADER  0x0063d7f0ULL  /* _sceSblAuthMgrCheckSelfHeader */
#define KO_1352_FN_SM_LOAD_SELF_BLOCK 0x00640aa0ULL  /* _sceSblAuthMgrSmLoadSelfBlock */

/* ------------------------------------------------------------------ */
/* SELF container constants (from the format, FW-independent)           */
/* ------------------------------------------------------------------ */
/* libPS4's elf.h already defines SELF_MAGIC; guard to avoid a redefinition. */
#ifndef SELF_MAGIC
#define SELF_MAGIC              0x1D3D154FU
#endif
#ifndef SELF_VERSION
#define SELF_VERSION            0x0
#endif
#ifndef SELF_MODE
#define SELF_MODE               0x1
#endif
#ifndef SELF_ENDIANNESS
#define SELF_ENDIANNESS         0x1
#endif
#define SELF_AUTH_INFO_SIZE     0x88
#define SELF_KEY_SIZE           0x10
#define SELF_DIGEST_SIZE        0x20
#define SELF_BLOCK_ALIGNMENT    0x10
#define SELF_SM_PAYLOAD_SIZE    0x80
#define SELF_SM_MSG_TYPE        0x16     /* [D] fixed type in the wrapper */

#endif /* OFFSETS_1352_H */
