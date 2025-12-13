#include "verifier.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include <signal.h>
#include <execinfo.h>

void sigsegv_handler(int sig) {
    void *array[10];
    size_t size;
    
    fprintf(stderr, "Segmentation fault!\n");
    
    size = backtrace(array, 10);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    
    exit(1);
}

#include "verifier.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>

#define MAX_STACK_DEPTH 10000
#define MAX_FUNCTIONS 1000
#define MAX_CAPTURES 255
#define MAX_PARAMS 255
#define MAX_LOCALS 255

/* Forward declaration */
static int count_bits(bool *array, int size);
static void propagate_stack_height(VerifierContext *ctx, int target, int height, 
                                  int *worklist, int *worklist_size);
static bool verify_bytecode_internal(bytefile *bf, const char *fname, bool verbose);

/* Initialize verification context */
static VerifierContext* create_verifier_context(bytefile *bf, const char *fname, int code_size, bool verbose) {
    VerifierContext *ctx = calloc(1, sizeof(VerifierContext));
    if (!ctx) return NULL;
    
    ctx->bf = bf;
    ctx->fname = fname ? strdup(fname) : NULL;
    ctx->error_count = 0;
    ctx->max_errors = 100;
    ctx->max_stack_height = 0;
    ctx->total_instructions = 0;
    ctx->code_size = code_size;
    ctx->verbose = verbose;
    ctx->current_function = -1;
    
    /* Allocate maps for control flow analysis */
    ctx->stack_heights = malloc(code_size * sizeof(int));
    ctx->visited = calloc(code_size, sizeof(bool));
    ctx->is_jump_target = calloc(code_size, sizeof(bool));
    ctx->is_function_start = calloc(code_size, sizeof(bool));
    
    if (!ctx->stack_heights || !ctx->visited || !ctx->is_jump_target || !ctx->is_function_start) {
        fprintf(stderr, "Failed to allocate memory for verification maps\n");
        free(ctx->stack_heights);
        free(ctx->visited);
        free(ctx->is_jump_target);
        free(ctx->is_function_start);
        free(ctx);
        return NULL;
    }
    
    /* Initialize stack heights to -1 (unreachable) */
    for (int i = 0; i < code_size; i++) {
        ctx->stack_heights[i] = -1;
    }
    
    /* Allocate function array */
    ctx->functions = malloc(MAX_FUNCTIONS * sizeof(FunctionInfo));
    ctx->function_count = 0;
    
    ctx->errors = malloc(ctx->max_errors * sizeof(VerificationError));
    
    return ctx;
}

/* Report a verification error */
static void report_error(VerifierContext *ctx, int offset, const char *fmt, ...) {
    if (ctx->error_count >= ctx->max_errors) {
        ctx->max_errors *= 2;
        VerificationError *new_errors = realloc(ctx->errors, 
                                               ctx->max_errors * sizeof(VerificationError));
        if (!new_errors) return;
        ctx->errors = new_errors;
    }
    
    VerificationError *err = &ctx->errors[ctx->error_count++];
    err->offset = offset;
    err->line = 0;  /* Would need debug info */
    err->column = 0;
    
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    err->message = strdup(buffer);
}

/* Get instruction name for debugging */
const char* get_opcode_name(unsigned char opcode, unsigned char subop) {
    static char buffer[32];
    
    switch (opcode) {
        case OP_HALT: return "HALT";
        case OP_BINOP:
            switch (subop) {
                case 1: return "ADD"; case 2: return "SUB"; case 3: return "MUL";
                case 4: return "DIV"; case 5: return "MOD"; case 6: return "LT";
                case 7: return "LE"; case 8: return "GT"; case 9: return "GE";
                case 10: return "EQ"; case 11: return "NEQ"; case 12: return "AND";
                case 13: return "OR"; default: return "BINOP?";
            }
        case OP_PRIMARY:
            switch (subop) {
                case PRIMARY_CONST: return "CONST";
                case PRIMARY_STRING: return "STRING";
                case PRIMARY_SEXP: return "SEXP";
                case PRIMARY_STA: return "STA";
                case PRIMARY_JMP: return "JMP";
                case PRIMARY_END: return "END";
                case PRIMARY_DROP: return "DROP";
                case PRIMARY_DUP: return "DUP";
                case PRIMARY_SWAP: return "SWAP";
                case PRIMARY_ELEM: return "ELEM";
                default: return "PRIMARY?";
            }
        case OP_LD: return "LD";
        case OP_LDA: return "LDA";
        case OP_ST: return "ST";
        case OP_CTRL:
            switch (subop) {
                case CTRL_CJMPz: return "CJMPz";
                case CTRL_CJMPnz: return "CJMPnz";
                case CTRL_BEGIN: return "BEGIN";
                case CTRL_CBEGIN: return "CBEGIN";
                case CTRL_CLOSURE: return "CLOSURE";
                case CTRL_CALLC: return "CALLC";
                case CTRL_CALL: return "CALL";
                case CTRL_TAG: return "TAG";
                case CTRL_ARRAY: return "ARRAY";
                case CTRL_FAIL: return "FAIL";
                case CTRL_LINE: return "LINE";
                default: return "CTRL?";
            }
        case OP_PATT:
            switch (subop) {
                case PATT_STR: return "PATT_STR";
                case PATT_STRING_TAG: return "PATT_STRING";
                case PATT_ARRAY_TAG: return "PATT_ARRAY";
                case PATT_SEXP_TAG: return "PATT_SEXP";
                case PATT_REF: return "PATT_REF";
                case PATT_VAL: return "PATT_VAL";
                case PATT_FUN: return "PATT_FUN";
                default: return "PATT?";
            }
        case OP_BUILTIN:
            switch (subop) {
                case BUILTIN_READ: return "READ";
                case BUILTIN_WRITE: return "WRITE";
                case BUILTIN_LENGTH: return "LENGTH";
                case BUILTIN_STRING: return "TOSTRING";
                case BUILTIN_ARRAY: return "ARRAY";
                default: return "BUILTIN?";
            }
        default:
            snprintf(buffer, sizeof(buffer), "UNK(0x%02x)", (opcode << 4) | subop);
            return buffer;
    }
}

/* Get instruction size in bytes */
int get_instruction_size(unsigned char opcode, unsigned char subop, const char *ip) {
    (void)ip;
    
    switch (opcode) {
        case OP_HALT: return 1;
        case OP_BINOP: return 1;
        case OP_PRIMARY:
            switch (subop) {
                case PRIMARY_CONST:
                case PRIMARY_STRING:
                case PRIMARY_SEXP:
                case PRIMARY_JMP:
                    return 1 + sizeof(int);
                default:
                    return 1;
            }
        case OP_LD:
        case OP_LDA:
        case OP_ST:
            return 1 + sizeof(int);
        case OP_CTRL:
            switch (subop) {
                case CTRL_CJMPz:
                case CTRL_CJMPnz:
                case CTRL_BEGIN:
                case CTRL_CBEGIN:
                case CTRL_CLOSURE:
                case CTRL_CALLC:
                case CTRL_CALL:
                case CTRL_TAG:
                case CTRL_ARRAY:
                case CTRL_FAIL:
                case CTRL_LINE:
                    return 1 + sizeof(int) * 2;
                default:
                    return 1;
            }
        case OP_PATT: return 1;
        case OP_BUILTIN:
            switch (subop) {
                case BUILTIN_ARRAY:
                    return 1 + sizeof(int);
                default:
                    return 1;
            }
        default:
            return 1;
    }
}

/* Get stack effect with context for functions */
int get_stack_effect(unsigned char opcode, unsigned char subop, const char *ip, VerifierContext *ctx) {
    switch (opcode) {
        case OP_HALT: return 0;
        case OP_BINOP: return 1;  /* Pops 2, pushes 1 */
            
        case OP_PRIMARY:
            switch (subop) {
                case PRIMARY_CONST:
                case PRIMARY_STRING:
                    return -1;  /* Pushes 1 */
                case PRIMARY_SEXP:
                    if (ip) {
                        int n = *(const int*)(ip + 1 + sizeof(int));
                        return n - 1;  /* Pops n, pushes 1 */
                    }
                    return 0;
                case PRIMARY_STA:
                    return 2;  /* Pops 3, pushes 1 */
                case PRIMARY_JMP:
                    return 0;
                case PRIMARY_END:
                    if (ctx && ctx->current_function >= 0) {
                        /* END pops return value and restores frame */
                        FunctionInfo *func = &ctx->functions[ctx->current_function];
                        return 1 + func->params + func->locals + func->captures;
                    }
                    return 1;  /* Pops 1 (return value) */
                case PRIMARY_DROP:
                    return 1;  /* Pops 1 */
                case PRIMARY_DUP:
                    return -1; /* Pops 1, pushes 2 */
                case PRIMARY_SWAP:
                    return 0;  /* Pops 2, pushes 2 */
                case PRIMARY_ELEM:
                    return 1;  /* Pops 2, pushes 1 */
                default:
                    return 0;
            }
            
        case OP_LD: return -1;  /* Pushes 1 */
        case OP_LDA: return -2; /* Pushes 2 (address + dummy) */
        case OP_ST: return 0;   /* Pops 1 */
            
        case OP_CTRL:
            switch (subop) {
                case CTRL_CJMPz:
                case CTRL_CJMPnz:
                    return 1;  /* Pops 1 */
                case CTRL_BEGIN:
                case CTRL_CBEGIN:
                    return 2;  /* Pops 2 (n_caps + function) */
                case CTRL_CLOSURE:
                    return -1; /* Pushes 1 */
                case CTRL_CALLC:
                    if (ip) {
                        int n_args = *(const int*)(ip + 1);
                        return n_args;  /* Pops n_args + 1, pushes 1 */
                    }
                    return 0;
                case CTRL_CALL:
                    if (ip) {
                        int n_args = *(const int*)(ip + 1 + sizeof(int));
                        return n_args - 1;  /* Pops n_args, pushes 1 */
                    }
                    return 0;
                case CTRL_TAG:
                case CTRL_ARRAY:
                    return 0;  /* Pops 1, pushes 1 */
                case CTRL_FAIL:
                    return 1;  /* Pops 1 */
                case CTRL_LINE:
                    return 0;
                default:
                    return 0;
            }
            
        case OP_PATT:
            switch (subop) {
                case PATT_STR:
                    return 1;  /* Pops 2, pushes 1 */
                default:
                    return 0;  /* Pops 1, pushes 1 */
            }
            
        case OP_BUILTIN:
            switch (subop) {
                case BUILTIN_READ:
                    return -1; /* Pushes 1 */
                case BUILTIN_WRITE:
                    return 0;  /* Pops 1, pushes 1 */
                case BUILTIN_LENGTH:
                case BUILTIN_STRING:
                    return 0;  /* Pops 1, pushes 1 */
                case BUILTIN_ARRAY:
                    if (ip) {
                        int n = *(const int*)(ip + 1);
                        return n - 1;  /* Pops n, pushes 1 */
                    }
                    return 0;
                default:
                    return 0;
            }
            
        default:
            return 0;
    }
}

/* Check if instruction is a function start */
bool is_function_start_instruction(unsigned char opcode, unsigned char subop) {
    return (opcode == OP_CTRL && (subop == CTRL_BEGIN || subop == CTRL_CBEGIN));
}

/* Read integer from bytecode at offset */
static int read_int_at(const char *ip, int offset) {
    return *(const int*)(ip + offset);
}

/* Phase 1: Verify instruction encoding */
bool verify_instruction_encoding(VerifierContext *ctx) {
    const char *code_start = ctx->bf->code_ptr;
    int offset = 0;
    int errors = 0;
    
    if (ctx->verbose) {
        printf("\n=== Phase 1: Instruction Encoding Verification ===\n");
    }
    
    while (offset < ctx->code_size) {
        if (offset < 0 || offset >= ctx->code_size) {
            report_error(ctx, offset, "Invalid offset");
            break;
        }
        
        const char *ip = code_start + offset;
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        /* Check opcode validity */
        if (h > OP_BUILTIN && h != OP_HALT) {
            report_error(ctx, offset, "Invalid opcode prefix: 0x%02x", x);
            errors++;
        }
        
        /* Check instruction fits in code */
        int size = get_instruction_size(h, l, ip);
        if (size <= 0) {
            report_error(ctx, offset, "Invalid instruction size: %d", size);
            errors++;
            break;
        }
        
        if (offset + size > ctx->code_size) {
            report_error(ctx, offset, "Instruction extends beyond code boundary");
            errors++;
            break;
        }
        
        /* Validate immediate operands */
        if (h == OP_PRIMARY && l == PRIMARY_STRING) {
            int str_idx = read_int_at(ip, 1);
            if (str_idx < 0 || str_idx >= ctx->bf->stringtab_size) {
                report_error(ctx, offset, "String index out of bounds: %d (max %d)", 
                           str_idx, ctx->bf->stringtab_size);
                errors++;
            }
        }
        
        /* Validate jumps */
        if ((h == OP_PRIMARY && l == PRIMARY_JMP) ||
            (h == OP_CTRL && (l == CTRL_CJMPz || l == CTRL_CJMPnz))) {
            int jump_offset = read_int_at(ip, 1);
            int target = offset + 1 + sizeof(int) + jump_offset;
            
            if (target < 0 || target >= ctx->code_size) {
                report_error(ctx, offset, "Jump target out of bounds: %d -> %d", 
                           jump_offset, target);
                errors++;
            } else {
                ctx->is_jump_target[target] = true;
            }
        }
        
        /* Validate CALL/CALLC targets */
        if (h == OP_CTRL && (l == CTRL_CALL || l == CTRL_CALLC || l == CTRL_CLOSURE)) {
            int target = read_int_at(ip, 1);
            if (target < 0 || target >= ctx->code_size) {
                report_error(ctx, offset, "Call target out of bounds: %d", target);
                errors++;
            } else {
                /* Mark as function start if BEGIN/CBEGIN */
                if (target < ctx->code_size) {
                    unsigned char target_op = (unsigned char)code_start[target];
                    unsigned char target_h = (target_op & 0xF0) >> 4;
                    unsigned char target_l = target_op & 0x0F;
                    if (target_h == OP_CTRL && 
                        (target_l == CTRL_BEGIN || target_l == CTRL_CBEGIN)) {
                        ctx->is_function_start[target] = true;
                    }
                }
            }
        }
        
        /* Validate variable indices */
        if (h == OP_LD || h == OP_LDA || h == OP_ST) {
            int idx = read_int_at(ip, 1);
            if (idx < 0) {
                report_error(ctx, offset, "Negative variable index: %d", idx);
                errors++;
            }
        }
        
        /* Mark function starts */
        if (is_function_start_instruction(h, l)) {
            ctx->is_function_start[offset] = true;
        }
        
        offset += size;
        ctx->total_instructions++;
    }
    
    if (ctx->verbose) {
        printf("Processed %d instructions\n", ctx->total_instructions);
        printf("Found %d function start points\n", 
               count_bits(ctx->is_function_start, ctx->code_size));
        printf("Found %d jump targets\n", 
               count_bits(ctx->is_jump_target, ctx->code_size));
        printf("Encoding errors: %d\n", errors);
    }
    
    return errors == 0;
}

/* Helper to count true bits in bool array */
static int count_bits(bool *array, int size) {
    int count = 0;
    for (int i = 0; i < size; i++) {
        if (array[i]) count++;
    }
    return count;
}

/* Phase 2: Control flow and stack analysis */
bool verify_control_flow(VerifierContext *ctx) {
    const char *code_start = ctx->bf->code_ptr;
    int *worklist = malloc(ctx->code_size * sizeof(int));
    int worklist_size = 0;
    int errors = 0;
    
    if (ctx->verbose) {
        printf("\n=== Phase 2: Control Flow Analysis ===\n");
    }
    
    /* Start from main (offset 0) */
    worklist[worklist_size++] = 0;
    ctx->stack_heights[0] = 0;
    ctx->visited[0] = true;
    
    while (worklist_size > 0) {
        int offset = worklist[--worklist_size];
        const char *ip = code_start + offset;
        
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        int current_height = ctx->stack_heights[offset];
        
        /* Update max stack height */
        if (current_height > ctx->max_stack_height) {
            ctx->max_stack_height = current_height;
        }
        
        /* Check stack underflow */
        int stack_effect = get_stack_effect(h, l, ip, ctx);
        int pops = -stack_effect > 0 ? -stack_effect : 0;
        
        if (current_height < pops) {
            report_error(ctx, offset, 
                        "Stack underflow: need %d values, have %d at %s", 
                        pops, current_height, get_opcode_name(h, l));
            errors++;
        }
        
        int new_height = current_height + stack_effect;
        
        if (new_height > MAX_STACK_DEPTH) {
            report_error(ctx, offset, "Stack overflow: height %d exceeds limit %d",
                        new_height, MAX_STACK_DEPTH);
            errors++;
        }
        
        /* Handle control flow */
        if (h == OP_PRIMARY && l == PRIMARY_JMP) {
            /* Unconditional jump */
            int jump_offset = read_int_at(ip, 1);
            int target = offset + 1 + sizeof(int) + jump_offset;
            
            if (target >= 0 && target < ctx->code_size) {
                propagate_stack_height(ctx, target, new_height, worklist, &worklist_size);
            }
            continue;
        }
        else if (h == OP_CTRL && (l == CTRL_CJMPz || l == CTRL_CJMPnz)) {
            /* Conditional jump - both successors */
            int jump_offset = read_int_at(ip, 1);
            int target = offset + 1 + sizeof(int) + jump_offset;
            int fallthrough = offset + get_instruction_size(h, l, ip);
            
            if (target >= 0 && target < ctx->code_size) {
                propagate_stack_height(ctx, target, new_height, worklist, &worklist_size);
            }
            if (fallthrough < ctx->code_size) {
                propagate_stack_height(ctx, fallthrough, new_height, worklist, &worklist_size);
            }
            continue;
        }
        else if (h == OP_PRIMARY && l == PRIMARY_END) {
            /* Function return - no successors */
            continue;
        }
        else if (h == OP_HALT) {
            /* Program termination */
            continue;
        }
        else {
            /* Normal fall-through */
            int next = offset + get_instruction_size(h, l, ip);
            if (next < ctx->code_size) {
                propagate_stack_height(ctx, next, new_height, worklist, &worklist_size);
            }
        }
    }
    
    /* Check for unreachable code */
    for (int i = 0; i < ctx->code_size; i++) {
        if (!ctx->visited[i] && code_start[i] != 0) {
            /* Check if it's a function start (might be called) */
            if (!ctx->is_function_start[i]) {
                report_error(ctx, i, "Unreachable code");
                errors++;
            }
        }
    }
    
    free(worklist);
    
    if (ctx->verbose) {
        printf("Maximum stack depth: %d\n", ctx->max_stack_height);
        printf("Reachable instructions: %d/%d\n", 
               count_bits(ctx->visited, ctx->code_size), ctx->total_instructions);
        printf("Control flow errors: %d\n", errors);
    }
    
    return errors == 0;
}

/* Propagate stack height to target */
static void propagate_stack_height(VerifierContext *ctx, int target, int height, 
                                  int *worklist, int *worklist_size) {
    if (ctx->stack_heights[target] == -1) {
        ctx->stack_heights[target] = height;
    } else if (ctx->stack_heights[target] != height) {
        report_error(ctx, target, 
                    "Stack height mismatch: %d vs %d at merge point",
                    ctx->stack_heights[target], height);
    }
    
    if (!ctx->visited[target]) {
        ctx->visited[target] = true;
        worklist[(*worklist_size)++] = target;
    }
}

/* Phase 3: Verify variable references */
bool verify_variable_references(VerifierContext *ctx) {
    const char *code_start = ctx->bf->code_ptr;
    int offset = 0;
    int errors = 0;
    
    if (ctx->verbose) {
        printf("\n=== Phase 3: Variable Reference Verification ===\n");
    }
    
    while (offset < ctx->code_size) {
        const char *ip = code_start + offset;
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        if (h == OP_LD || h == OP_LDA || h == OP_ST) {
            int idx = read_int_at(ip, 1);
            
            switch (l) {
                case LOC_G: /* Global */
                    if (idx >= ctx->bf->global_area_size) {
                        report_error(ctx, offset,
                                    "Global index %d out of bounds (max %d)",
                                    idx, ctx->bf->global_area_size);
                        errors++;
                    }
                    break;
                    
                case LOC_L: /* Local */
                    if (ctx->current_function >= 0) {
                        FunctionInfo *func = &ctx->functions[ctx->current_function];
                        if (idx >= func->locals) {
                            report_error(ctx, offset,
                                        "Local index %d out of bounds (max %d)",
                                        idx, func->locals);
                            errors++;
                        }
                    }
                    break;
                    
                case LOC_A: /* Argument */
                    if (ctx->current_function >= 0) {
                        FunctionInfo *func = &ctx->functions[ctx->current_function];
                        if (idx >= func->params) {
                            report_error(ctx, offset,
                                        "Argument index %d out of bounds (max %d)",
                                        idx, func->params);
                            errors++;
                        }
                    }
                    break;
                    
                case LOC_C: /* Capture */
                    if (ctx->current_function >= 0) {
                        FunctionInfo *func = &ctx->functions[ctx->current_function];
                        if (!func->is_closure) {
                            report_error(ctx, offset,
                                        "Cannot access captures in non-closure function");
                            errors++;
                        } else if (idx >= func->captures) {
                            report_error(ctx, offset,
                                        "Capture index %d out of bounds (max %d)",
                                        idx, func->captures);
                            errors++;
                        }
                    }
                    break;
            }
        }
        
        offset += get_instruction_size(h, l, ip);
    }
    
    if (ctx->verbose) {
        printf("Variable reference errors: %d\n", errors);
    }
    
    return errors == 0;
}

/* Phase 4: Verify function calls */
bool verify_function_calls(VerifierContext *ctx) {
    const char *code_start = ctx->bf->code_ptr;
    int offset = 0;
    int errors = 0;
    
    if (ctx->verbose) {
        printf("\n=== Phase 4: Function Call Verification ===\n");
    }
    
    /* First pass: collect function information */
    offset = 0;
    while (offset < ctx->code_size) {
        if (ctx->is_function_start[offset]) {
            const char *ip = code_start + offset;
            unsigned char x = (unsigned char)*ip;
            unsigned char l = x & 0x0F;
            
            if (ctx->function_count >= MAX_FUNCTIONS) {
                report_error(ctx, offset, "Too many functions (max %d)", MAX_FUNCTIONS);
                break;
            }
            
            FunctionInfo *func = &ctx->functions[ctx->function_count++];
            func->address = offset;
            func->is_closure = (l == CTRL_CBEGIN);
            
            /* Read params and locals */
            func->params = read_int_at(ip, 1 + sizeof(int));
            func->locals = read_int_at(ip, 1 + 2 * sizeof(int));
            
            if (func->is_closure) {
                /* For CBEGIN, first int is n_caps */
                func->captures = read_int_at(ip, 1);
            } else {
                func->captures = 0;
            }
            
            if (func->params > MAX_PARAMS) {
                report_error(ctx, offset, "Too many parameters: %d (max %d)",
                            func->params, MAX_PARAMS);
                errors++;
            }
            if (func->locals > MAX_LOCALS) {
                report_error(ctx, offset, "Too many locals: %d (max %d)",
                            func->locals, MAX_LOCALS);
                errors++;
            }
            if (func->captures > MAX_CAPTURES) {
                report_error(ctx, offset, "Too many captures: %d (max %d)",
                            func->captures, MAX_CAPTURES);
                errors++;
            }
        }
        
        /* Skip to next instruction */
        if (offset < ctx->code_size) {
            unsigned char x = (unsigned char)code_start[offset];
            int size = get_instruction_size((x & 0xF0) >> 4, x & 0x0F, code_start + offset);
            if (size <= 0) break;
            offset += size;
        }
    }
    
    /* Second pass: verify calls */
    offset = 0;
    while (offset < ctx->code_size) {
        const char *ip = code_start + offset;
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        if (h == OP_CTRL) {
            if (l == CTRL_CALL) {
                int target = read_int_at(ip, 1);
                int n_args = read_int_at(ip, 1 + sizeof(int));
                if (n_args > MAX_PARAMS) {
                    report_error(ctx, offset, "Too many arguments: %d", n_args);
                }
                
                /* Find function */
                FunctionInfo *target_func = NULL;
                for (int i = 0; i < ctx->function_count; i++) {
                    if (ctx->functions[i].address == target) {
                        target_func = &ctx->functions[i];
                        break;
                    }
                }
                
                if (!target_func) {
                    report_error(ctx, offset, "CALL to non-function address %d", target);
                    errors++;
                } else if (target_func->is_closure) {
                    report_error(ctx, offset, 
                                "CALL to closure (use CALLC instead)");
                    errors++;
                } else if (n_args != target_func->params) {
                    report_error(ctx, offset,
                                "Wrong number of arguments: expected %d, got %d",
                                target_func->params, n_args);
                    errors++;
                }
            }
            else if (l == CTRL_CALLC) {
                int n_args = read_int_at(ip, 1);
                /* CALLC pops function from stack, so target is dynamic */
                /* Can't fully verify statically */
            }
            else if (l == CTRL_CLOSURE) {
                int target = read_int_at(ip, 1);
                int n_caps = read_int_at(ip, 1 + sizeof(int));
                
                FunctionInfo *target_func = NULL;
                for (int i = 0; i < ctx->function_count; i++) {
                    if (ctx->functions[i].address == target) {
                        target_func = &ctx->functions[i];
                        break;
                    }
                }
                
                if (!target_func) {
                    report_error(ctx, offset, "CLOSURE of non-function address %d", target);
                    errors++;
                } else if (!target_func->is_closure) {
                    report_error(ctx, offset, 
                                "CLOSURE of non-closure function");
                    errors++;
                } else if (n_caps < target_func->captures) {
                    report_error(ctx, offset,
                                "Insufficient captures: need %d, got %d",
                                target_func->captures, n_caps);
                    errors++;
                }
            }
        }
        
        offset += get_instruction_size(h, l, ip);
    }
    
    if (ctx->verbose) {
        printf("Found %d functions\n", ctx->function_count);
        printf("Function call errors: %d\n", errors);
    }
    
    return errors == 0;
}

/* Phase 5: Verify stack usage in function blocks */
bool verify_stack_usage(VerifierContext *ctx) {
    int errors = 0;
    
    if (ctx->verbose) {
        printf("\n=== Phase 5: Stack Usage Verification ===\n");
    }
    
    for (int i = 0; i < ctx->function_count; i++) {
        FunctionInfo *func = &ctx->functions[i];
        
        /* Analyze stack usage in this function */
        int stack_at_entry = func->locals + func->captures;
        
        if (ctx->verbose) {
            printf("Function at 0x%04x: params=%d, locals=%d, captures=%d, entry_stack=%d\n",
                   func->address, func->params, func->locals, 
                   func->captures, stack_at_entry);
        }
        
        /* Check that BEGIN/CBEGIN have correct stack */
        if (func->address < ctx->code_size) {
            const char *ip = ctx->bf->code_ptr + func->address;
            unsigned char x = (unsigned char)*ip;
            unsigned char h = (x & 0xF0) >> 4;
            unsigned char l = x & 0x0F;
            
            if (h == OP_CTRL && (l == CTRL_BEGIN || l == CTRL_CBEGIN)) {
                /* BEGIN/CBEGIN expect n_caps and function on stack */
                int expected_stack_before = 2;  /* n_caps + function */
                
                if (ctx->stack_heights[func->address] != expected_stack_before) {
                    report_error(ctx, func->address,
                                "Wrong stack height at function entry: expected %d, got %d",
                                expected_stack_before, ctx->stack_heights[func->address]);
                    errors++;
                }
                
                /* Check stack after function prologue */
                int after_prologue = func->address + get_instruction_size(h, l, ip);
                if (after_prologue < ctx->code_size) {
                    if (ctx->stack_heights[after_prologue] != stack_at_entry) {
                        report_error(ctx, after_prologue,
                                    "Wrong stack after function prologue: expected %d, got %d",
                                    stack_at_entry, ctx->stack_heights[after_prologue]);
                        errors++;
                    }
                }
            }
        }
    }
    
    if (ctx->verbose) {
        printf("Stack usage errors: %d\n", errors);
    }
    
    return errors == 0;
}

/* Main verification function */
bool verify_bytecode(bytefile *bf, const char *fname) {
    return verify_bytecode_internal(bf, fname, false);
}

bool verify_bytecode_verbose(bytefile *bf, const char *fname) {
    return verify_bytecode_internal(bf, fname, true);
}

static bool verify_bytecode_internal(bytefile *bf, const char *fname, bool verbose) {
    printf("\n=== Lama Bytecode Verifier ===\n");
    printf("File: %s\n", fname);
    //printf("Code size: %ld bytes\n", (long)(code_stop_ptr - bf->code_ptr + 1));
    printf("Global variables: %d\n", bf->global_area_size);
    printf("String table: %d bytes\n", bf->stringtab_size);
    printf("Public symbols: %d\n\n", bf->public_symbols_number);
    
    /* Estimate code size */
    int code_size = 0;
    const char *code_start = bf->code_ptr;
    for (int i = 0; i < 1000000; i++) {
        if (i >= 1000000 - 1) {
            code_size = 10000;
            break;
        }
        unsigned char x = (unsigned char)code_start[i];
        if ((x & 0xF0) >> 4 == OP_HALT) {
            code_size = i + 1;
            break;
        }
    }
    
    if (code_size <= 0) {
        printf("❌ ERROR: Cannot determine code size\n");
        return false;
    }
    
    VerifierContext *ctx = create_verifier_context(bf, fname, code_size, verbose);
    if (!ctx) {
        printf("❌ ERROR: Failed to create verifier context\n");
        return false;
    }
    
    /* Run verification phases */
    bool phase1 = verify_instruction_encoding(ctx);
    bool phase2 = verify_control_flow(ctx);
    bool phase3 = verify_variable_references(ctx);
    bool phase4 = verify_function_calls(ctx);
    bool phase5 = verify_stack_usage(ctx);
    
    /* Summary */
    printf("\n=== Verification Summary ===\n");
    printf("1. Instruction encoding: %s\n", phase1 ? "✅ PASS" : "❌ FAIL");
    printf("2. Control flow: %s\n", phase2 ? "✅ PASS" : "❌ FAIL");
    printf("3. Variable references: %s\n", phase3 ? "✅ PASS" : "❌ FAIL");
    printf("4. Function calls: %s\n", phase4 ? "✅ PASS" : "❌ FAIL");
    printf("5. Stack usage: %s\n", phase5 ? "✅ PASS" : "❌ FAIL");
    printf("Maximum stack depth: %d\n", ctx->max_stack_height);
    printf("Total instructions: %d\n", ctx->total_instructions);
    
    if (ctx->error_count > 0) {
        printf("\n❌ VERIFICATION FAILED with %d error(s):\n", ctx->error_count);
        for (int i = 0; i < ctx->error_count && i < 20; i++) {
            printf("  [0x%04x] %s\n", ctx->errors[i].offset, 
                   ctx->errors[i].message ? ctx->errors[i].message : "(no message)");
        }
        if (ctx->error_count > 20) {
            printf("  ... and %d more errors\n", ctx->error_count - 20);
        }
    } else {
        printf("\n✅ VERIFICATION SUCCESSFUL\n");
    }
    
    print_verification_errors(ctx);
    free_verifier_context(ctx);
    
    return ctx->error_count == 0;
}

/* Print all errors */
void print_verification_errors(VerifierContext *ctx) {
    if (!ctx || ctx->error_count == 0) return;
    
    printf("\nDetailed errors:\n");
    for (int i = 0; i < ctx->error_count; i++) {
        printf("%4d. [0x%04x] %s\n", i+1, ctx->errors[i].offset, ctx->errors[i].message);
    }
}

/* Free resources */
void free_verifier_context(VerifierContext *ctx) {
    if (!ctx) return;
    
    if (ctx->fname) free(ctx->fname);
    if (ctx->stack_heights) free(ctx->stack_heights);
    if (ctx->visited) free(ctx->visited);
    if (ctx->is_jump_target) free(ctx->is_jump_target);
    if (ctx->is_function_start) free(ctx->is_function_start);
    if (ctx->functions) free(ctx->functions);
    
    if (ctx->errors) {
        for (int i = 0; i < ctx->error_count; i++) {
            if (ctx->errors[i].message) {
                free(ctx->errors[i].message);
            }
        }
        free(ctx->errors);
    }
    
    free(ctx);
}