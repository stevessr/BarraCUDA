#ifndef BARRACUDA_TENSIX_H
#define BARRACUDA_TENSIX_H

#include "bir.h"

/* Tenstorrent Tensix backend. 32-lane SFPU, 8 writable LRegs, predicated
 * execution, no branches, and a register called L8 that contains 0.8373.
 * ISA from sfpi-binutils + corsix.org reverse engineering. */

#define BC_ERR_TENSIX   -7

/* ---- Tensix Target Constants ---- */

#define TT_SFPU_LANES       32      /* lanes per SFPU vector op */
#define TT_NUM_LREGS        8       /* writable vector registers: L0-L7 */
#define TT_TOTAL_LREGS      16      /* L0-L15, but only L0-L7 are writable */
#define TT_DST_ROWS         1024    /* Dst register file rows (spill target) */

/* ---- Constant Register Assignments ---- */

/* L8-L15 are read-only. Some silicon-fixed, others programmable via SFPCONFIG. */
#define TT_LREG_CONST_0873  8       /* L8  = 0.8373 (don't ask) */
#define TT_LREG_ZERO        9       /* L9  = 0.0 */
#define TT_LREG_ONE         10      /* L10 = 1.0 */
#define TT_LREG_PROG0       11      /* L11 = programmable constant 0 */
#define TT_LREG_PROG1       12      /* L12 = programmable constant 1 */
#define TT_LREG_PROG2       13      /* L13 = programmable constant 2 */
#define TT_LREG_PROG3       14      /* L14 = programmable constant 3 */
#define TT_LREG_LANE_ID     15      /* L15 = lane ID (0,2,4,...,62) */

/* ---- SFPU Instruction Encoding Formats ---- */

/*
 * All SFPU instructions are 32 bits. Opcode in bits [31:24].
 *
 * Format A (3-src):  [op:8][_:4][src_a:4][src_b:4][src_c:4][dst:4][mod1:4]
 * Format B (imm12):  [op:8][imm12:12][src:4][dst:4][mod1:4]
 * Format C (imm16):  [op:8][imm16:16][dst:4][mod1:4]
 * Format D (ld/st):  [op:8][lreg:4][mod0:4][addr_mode:2][dest_addr:14]
 * Format E (loadi):  [op:8][lreg:4][mod0:4][imm16:16]
 */

typedef enum {
    TT_FMT_A,          /* 3-source (MAD/ADD/MUL) */
    TT_FMT_B,          /* imm12 + source */
    TT_FMT_C,          /* imm16, control */
    TT_FMT_D,          /* load/store to Dst */
    TT_FMT_E,          /* load immediate */
    TT_FMT_PSEUDO,     /* eliminated before encoding */
    TT_FMT_COUNT
} tt_fmt_t;

/* ---- SFPU Opcodes ---- */

/* Opcode = bits [31:24]. From sfpi-binutils riscv-opc-sfpu.h. Wormhole B0. */

typedef enum {
    /* ---- Data Movement ---- */
    TT_SFPLOAD          = 0x70,     /* Dst -> LReg */
    TT_SFPLOADI         = 0x71,     /* imm16 -> LReg */
    TT_SFPSTORE         = 0x72,     /* LReg -> Dst */
    TT_SFPLUT           = 0x73,     /* lookup table */
    TT_SFPMOV           = 0x7C,     /* LReg -> LReg */

    /* ---- FP Arithmetic (Format A) ---- */
    TT_SFPMAD           = 0x84,     /* dst = src_a * src_b + src_c */
    TT_SFPADD           = 0x85,     /* dst = src_a + src_c (src_b ignored) */
    TT_SFPMUL           = 0x86,     /* dst = src_a * src_b (src_c ignored) */

    /* ---- Integer / Immediate Arithmetic ---- */
    TT_SFPMULI          = 0x74,     /* dst = src * imm (Format B) */
    TT_SFPADDI          = 0x75,     /* dst = src + imm16 (Format C) */
    TT_SFPIADD          = 0x79,     /* dst = src + imm12 (Format B, integer) */

    /* ---- Bitwise ---- */
    TT_SFPAND           = 0x7E,     /* bitwise AND */
    TT_SFPOR            = 0x7F,     /* bitwise OR */
    TT_SFPNOT           = 0x80,     /* bitwise NOT */
    TT_SFPXOR           = 0x8D,     /* bitwise XOR */
    TT_SFPSHFT          = 0x7A,     /* shift (direction via mod1) */

    /* ---- Comparison / Predication ---- */
    TT_SFPSETCC         = 0x7B,     /* set condition codes per-lane */
    TT_SFPENCC          = 0x8A,     /* enable conditional execution */
    TT_SFPPUSHC         = 0x87,     /* push condition code stack */
    TT_SFPPOPC          = 0x88,     /* pop condition code stack */
    TT_SFPCOMPC         = 0x8B,     /* complement condition mask */

    /* ---- Float Manipulation ---- */
    TT_SFPABS           = 0x7D,     /* absolute value */
    TT_SFPSETSGN        = 0x89,     /* set sign bit */
    TT_SFPDIVP2         = 0x76,     /* divide by power of 2 */
    TT_SFPEXEXP         = 0x77,     /* extract exponent */
    TT_SFPEXMAN         = 0x78,     /* extract mantissa */
    TT_SFPSETEXP        = 0x82,     /* set exponent */
    TT_SFPSETMAN        = 0x83,     /* set mantissa */
    TT_SFPLZ            = 0x81,     /* leading zeros */

    /* ---- Conversion ---- */
    TT_SFPCAST          = 0x90,     /* int <-> float */
    TT_SFPSTOCHRND      = 0x8E,     /* stochastic rounding */

    /* ---- Transpose / Permute ---- */
    TT_SFPTRANSP        = 0x8C,     /* lane transpose */
    TT_SFPSWAP          = 0x92,     /* swap */

    /* ---- Configuration ---- */
    TT_SFPCONFIG        = 0x91,     /* program constant registers etc. */
    TT_SFPLDMACRO       = 0x93,     /* load macro */

    /* ---- Advanced (Blackhole+) ---- */
    TT_SFPSHFT2         = 0x94,     /* advanced shift */
    TT_SFPLUTFP32       = 0x95,     /* FP32 LUT */
    TT_SFPLE            = 0x96,     /* less-than-or-equal compare */
    TT_SFPGT            = 0x97,     /* greater-than compare */
    TT_SFPMUL24         = 0x98,     /* 24-bit multiply */
    TT_SFPARECIP        = 0x99,     /* approximate reciprocal */

    /* ---- Control ---- */
    TT_SFPNOP           = 0x02,     /* do nothing, but do it in 32 bits */
    TT_SFPWNOP          = 0x8F,     /* wide nop (with immediate) */

    /* ---- Pseudo-instructions (eliminated before emit) ---- */
    TT_PSEUDO_PHI,
    TT_PSEUDO_COPY,
    TT_PSEUDO_DEF,

    TT_OP_COUNT
} tt_sfpu_op_t;

/* ---- SFPLOADI mod0 values ---- */

#define TT_LOADI_MOD0_FLOATA  0     /* FP32, upper 16 bits */
#define TT_LOADI_MOD0_FLOATB  1     /* FP32, lower 16 bits */
#define TT_LOADI_MOD0_INTA    2     /* INT32, upper 16 bits */
#define TT_LOADI_MOD0_INTB    4     /* INT32, lower 16 bits */

/* ---- SFPLOAD/SFPSTORE mod0 values ---- */

#define TT_LDST_MOD0_SRCB     0     /* SrcB format */
#define TT_LDST_MOD0_FP16A    1     /* FP16 row A */
#define TT_LDST_MOD0_FP16B    2     /* FP16 row B */
#define TT_LDST_MOD0_FP32     3     /* FP32 */

/* ---- SFPSETCC condition modes ---- */

#define TT_CC_LT             0      /* less than zero */
#define TT_CC_GE             1      /* greater than or equal to zero */
#define TT_CC_EQ             2      /* equal to zero */
#define TT_CC_NE             3      /* not equal to zero */

/* ---- SFPENCC modes ---- */

#define TT_ENCC_INIT         0      /* initialise from condition codes */
#define TT_ENCC_COMP         1      /* complement */
#define TT_ENCC_AND          2      /* AND with current mask */

/* ---- Machine Operand ---- */

typedef enum {
    TT_MOP_NONE,
    TT_MOP_LREG,           /* physical LReg (0-15) */
    TT_MOP_VREG,           /* virtual vector reg (maps to LReg 0-7) */
    TT_MOP_IMM,            /* immediate value */
    TT_MOP_DST_ROW,        /* Dst register file row index */
    TT_MOP_LABEL,          /* machine block index */
} tt_mop_kind_t;

typedef struct {
    uint8_t  kind;          /* tt_mop_kind_t */
    uint8_t  pad;
    uint16_t reg_num;       /* physical or virtual reg number */
    int32_t  imm;           /* immediate value */
} tt_operand_t;             /* 8 bytes */

/* ---- Machine Instruction ---- */

#define TT_MINST_MAX_OPS 6

typedef struct {
    uint16_t    op;                         /* tt_sfpu_op_t */
    uint8_t     num_defs;                   /* outputs (0-1, SFPU is simple) */
    uint8_t     num_uses;                   /* inputs (0-4) */
    tt_operand_t operands[TT_MINST_MAX_OPS]; /* [0..num_defs-1]=defs, rest=uses */
    uint16_t    flags;                      /* mod0, mod1, addr_mode packed */
    uint8_t     fmt;                        /* tt_fmt_t */
    uint8_t     pad;
} tt_minst_t;   /* 56 bytes */

/* ---- Thread Coarsening ---- */

/* Classifies a kernel so the host knows how to partition work. */

#define TT_WH_NUM_CORES    64      /* Wormhole B0: 8x8 available compute cores */
#define TT_WH_CORES_X       8
#define TT_WH_CORES_Y       8

typedef enum {
    TT_PATTERN_GENERIC,         /* unknown, conservative */
    TT_PATTERN_ELEMENTWISE,     /* c[i] = f(a[i], ...) */
    TT_PATTERN_REDUCTION,       /* barriers / atomics / shuffles */
    TT_PATTERN_COUNT
} tt_coarsen_pattern_t;

/* ---- Machine Block / Function ---- */

typedef struct {
    uint32_t first_inst;
    uint32_t num_insts;
    uint32_t bir_block;     /* source BIR block index */
} tt_mblock_t;  /* 12 bytes */

typedef struct {
    uint32_t name;              /* string table offset */
    uint32_t first_block;
    uint16_t num_blocks;
    uint16_t num_lregs_used;    /* after regalloc: how many of L0-L7 we touched */
    uint16_t dst_rows_used;     /* spill slots consumed in Dst register file */
    uint16_t is_kernel;         /* 1 for __global__ */
    uint32_t launch_bounds_max;
    uint32_t launch_bounds_min;
    uint32_t tiles_per_core;    /* computed from grid dims */
    uint32_t bir_func;          /* source BIR function index */
    uint8_t  coarsen_pattern;   /* tt_coarsen_pattern_t */
    uint8_t  coarsen_pad[3];
} tt_mfunc_t;  /* 36 bytes */

/* ---- Module ---- */

#define TT_MAX_MINSTS    (1 << 18)   /* 256K machine instructions */
#define TT_MAX_MBLOCKS   (1 << 16)
#define TT_MAX_MFUNCS    (1 << 12)
#define TT_MAX_VREGS     (1 << 16)
#define TT_MAX_CODE_SIZE (1024 * 1024)  /* 1 MB output buffer */

typedef struct {
    const bir_module_t *bir;

    tt_minst_t  minsts[TT_MAX_MINSTS];
    uint32_t    num_minsts;

    tt_mblock_t mblocks[TT_MAX_MBLOCKS];
    uint32_t    num_mblocks;

    tt_mfunc_t  mfuncs[TT_MAX_MFUNCS];
    uint32_t    num_mfuncs;

    /* Virtual register tracking */
    uint32_t    vreg_count;
    uint8_t     reg_map[TT_MAX_VREGS];   /* vreg -> physical LReg (0-7) */

    /* BIR value -> machine vreg mapping */
    uint32_t    val_vreg[BIR_MAX_INSTS];  /* BIR inst index -> vreg */

    /* Output buffer (TT-Metalium C++ text) */
    char        out_buf[TT_MAX_CODE_SIZE];
    uint32_t    out_len;
} tt_module_t;

/* ---- Encoding Table Entry ---- */

typedef struct {
    uint8_t     fmt;            /* tt_fmt_t */
    uint8_t     hw_opcode;      /* bits [31:24] of instruction word */
    const char *mnemonic;       /* assembly text name */
} tt_enc_entry_t;

/* ---- Public API ---- */

/* Instruction selection: BIR -> Tensix machine IR */
int  tensix_compile(const bir_module_t *bir, tt_module_t *tt);

/* Thread coarsening: analyse BIR, classify patterns, compute tiles_per_core */
void tensix_coarsen(tt_module_t *tt);

/* Register allocation: virtual regs -> physical LRegs with Dst spilling */
void tensix_regalloc(tt_module_t *tt);

/* Emit TT-Metalium C++ compute kernel to file */
int  tensix_emit_metalium(tt_module_t *tt, const char *path);

/* Emit TT-Metalium host program skeleton */
int  tensix_emit_host(tt_module_t *tt, const char *host_path,
                      const char *compute_path);

#endif /* BARRACUDA_TENSIX_H */
