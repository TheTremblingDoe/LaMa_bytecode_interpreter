#ifndef BYTECODE_DEFS_H
#define BYTECODE_DEFS_H

/* Структура bytefile должна быть ОДИНАКОВОЙ в интерпретаторе и верификаторе */
typedef struct bytefile {
    char *string_ptr;              /* A pointer to the beginning of the string table */
    int  *public_ptr;              /* A pointer to the beginning of publics table    */
    char *code_ptr;                /* A pointer to the bytecode itself               */
    int  *global_ptr;              /* A pointer to the global area                   */
    int   stringtab_size;          /* The size (in bytes) of the string table        */
    int   global_area_size;        /* The size (in words) of global area             */
    int   public_symbols_number;   /* The number of public symbols                   */
    char  buffer[0];
} bytefile;


/* Opcode definitions */
typedef enum {
    OP_HALT     = 15,  // 0xF
    OP_BINOP    = 0,   // 0x0
    OP_PRIMARY  = 1,   // 0x1 - первичные операции (CONST, STRING, SEXP и т.д.)
    OP_LD       = 2,   // 0x2
    OP_LDA      = 3,   // 0x3
    OP_ST       = 4,   // 0x4
    OP_CTRL     = 5,   // 0x5
    OP_PATT     = 6,   // 0x6
    OP_BUILTIN  = 7    // 0x7
} OpcodePrefix;

typedef enum {
    // Primary operations (when h = OP_PRIMARY = 1)
    PRIMARY_CONST   = 0,
    PRIMARY_STRING  = 1,
    PRIMARY_SEXP    = 2,
    PRIMARY_STI     = 3,  // не используется
    PRIMARY_STA     = 4,
    PRIMARY_JMP     = 5,
    PRIMARY_END     = 6,
    PRIMARY_RET     = 7,  // не используется
    PRIMARY_DROP    = 8,
    PRIMARY_DUP     = 9,
    PRIMARY_SWAP    = 10,
    PRIMARY_ELEM    = 11
} PrimaryOpcode;

typedef enum {
    // Control operations (when h = OP_CTRL = 5)
    CTRL_CJMPz     = 0,
    CTRL_CJMPnz    = 1,
    CTRL_BEGIN     = 2,
    CTRL_CBEGIN    = 3,
    CTRL_CLOSURE   = 4,
    CTRL_CALLC     = 5,
    CTRL_CALL      = 6,
    CTRL_TAG       = 7,
    CTRL_ARRAY     = 8,
    CTRL_FAIL      = 9,
    CTRL_LINE      = 10
} CtrlOpcode;

typedef enum {
    // Pattern operations (when h = OP_PATT = 6)
    PATT_STR     = 0,
    PATT_STRING_TAG = 1,
    PATT_ARRAY_TAG  = 2,
    PATT_SEXP_TAG   = 3,
    PATT_REF        = 4,
    PATT_VAL        = 5,
    PATT_FUN        = 6
} PattOpcode;

typedef enum {
    // Builtin operations (when h = OP_BUILTIN = 7)
    BUILTIN_READ   = 0,
    BUILTIN_WRITE  = 1,
    BUILTIN_LENGTH = 2,
    BUILTIN_STRING = 3,
    BUILTIN_ARRAY  = 4
} BuiltinOpcode;

typedef enum {
    LOC_G = 0,
    LOC_L = 1,
    LOC_A = 2,
    LOC_C = 3,
    LOC_N = 4
} LocationType;

/* bytecode_common.h - дополнение */

/* Binary operations */
typedef enum {
    OP_ADD = 1,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_LT,
    OP_LE,
    OP_GT,
    OP_GE,
    OP_EQ,
    OP_NEQ,
    OP_AND,
    OP_OR,
    OP_N
} BinOp;

/* Other useful constants */
#define MAX_STACK_DEPTH 10000
#define MAX_GLOBALS 10000
#define MAX_STRINGS 100000

#endif /* BYTECODE_DEFS_H */
