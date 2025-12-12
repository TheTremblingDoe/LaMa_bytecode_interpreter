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

/* Теперь можно напрямую обращаться к полям bytefile */
static const char* get_bf_code_ptr(const bytefile *bf) {
    if (!bf) {
        fprintf(stderr, "ERROR: bytefile is NULL\n");
        return NULL;
    }
    return bf->code_ptr;  // Прямой доступ!
}

static int get_bf_stringtab_size(const bytefile *bf) {
    return bf ? bf->stringtab_size : 0;
}

static int get_bf_global_area_size(const bytefile *bf) {
    return bf ? bf->global_area_size : 0;
}

static int get_bf_public_symbols_number(const bytefile *bf) {
    return bf ? bf->public_symbols_number : 0;
}

/* Остальные функции остаются аналогичными, но с bytefile вместо bytefile */

/* Initialize verification context */
static VerifierContext* create_verifier_context(bytefile *bf, const char *fname, int code_size) {
    VerifierContext *ctx = malloc(sizeof(VerifierContext));
    if (!ctx) return NULL;
    
    ctx->bf = bf;
    ctx->fname = (char*)fname;
    ctx->error_count = 0;
    ctx->max_errors = 100;
    ctx->max_stack_height = 0;
    ctx->total_instructions = 0;
    ctx->code_size = code_size;
    
    /* Allocate maps for control flow analysis */
    ctx->stack_heights = malloc(code_size * sizeof(int));
    ctx->visited = malloc(code_size * sizeof(bool));
    ctx->is_jump_target = malloc(code_size * sizeof(bool));
    
    if (!ctx->stack_heights || !ctx->visited || !ctx->is_jump_target) {
        free(ctx->stack_heights);
        free(ctx->visited);
        free(ctx->is_jump_target);
        free(ctx);
        return NULL;
    }
    
    /* Initialize stack heights to -1 (unreachable) */
    for (int i = 0; i < code_size; i++) {
        ctx->stack_heights[i] = -1;
        ctx->visited[i] = false;
        ctx->is_jump_target[i] = false;
    }
    
    ctx->errors = malloc(ctx->max_errors * sizeof(VerificationError));
    if (!ctx->errors) {
        free(ctx->stack_heights);
        free(ctx->visited);
        free(ctx->is_jump_target);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

/* Report a verification error */
static void report_error(VerifierContext *ctx, int offset, const char *fmt, ...) {
    if (ctx->error_count >= ctx->max_errors) {
        /* Resize error array */
        ctx->max_errors *= 2;
        VerificationError *new_errors = realloc(ctx->errors, ctx->max_errors * sizeof(VerificationError));
        if (!new_errors) return;
        ctx->errors = new_errors;
    }
    
    VerificationError *err = &ctx->errors[ctx->error_count++];
    err->offset = offset;
    err->line = 0;
    err->column = 0;
    
    /* Format message */
    va_list args;
    va_start(args, fmt);
    
    /* Determine needed size */
    va_list args_copy;
    va_copy(args_copy, args);
    int size = vsnprintf(NULL, 0, fmt, args_copy) + 1;
    va_end(args_copy);
    
    err->message = malloc(size);
    if (err->message) {
        vsnprintf(err->message, size, fmt, args);
    }
    
    va_end(args);
}

/* Get instruction size in bytes */
int get_instruction_size(unsigned char opcode, unsigned char subop, const char *ip) {
    (void)ip;  /* Подавляем warning о неиспользуемом параметре */
    
    switch (opcode) {
        case OP_HALT:
            return 1;
            
        case OP_BINOP:
            return 1;
            
        case OP_PRIMARY:
            switch (subop) {
                case PRIMARY_CONST:
                case PRIMARY_STRING:
                case PRIMARY_SEXP:
                case PRIMARY_JMP:
                    return 1 + sizeof(int);
                case PRIMARY_STA:
                    return 1;
                case PRIMARY_END:
                case PRIMARY_DROP:
                case PRIMARY_DUP:
                case PRIMARY_SWAP:
                case PRIMARY_ELEM:
                    return 1;
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
            
        case OP_PATT:
            return 1;
            
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

/* Get stack effect of an instruction (pops - pushes) */
int get_stack_effect(unsigned char opcode, unsigned char subop, const char *ip) {
    switch (opcode) {
        case OP_HALT:
            return 0;
            
        case OP_BINOP:
            return 1;  /* Pops 2, pushes 1 */
            
        case OP_PRIMARY:
            switch (subop) {
                case PRIMARY_CONST:
                case PRIMARY_STRING:
                    return -1;  /* Pushes 1 */
                case PRIMARY_SEXP:
                    /* Pops n, pushes 1 */
                    if (ip) {
                        int n = *(const int*)(ip + 1 + sizeof(int));
                        return n - 1;
                    }
                    return 0;
                case PRIMARY_STA:
                    return 2;  /* Pops 3, pushes 1 */
                case PRIMARY_JMP:
                    return 0;
                case PRIMARY_END:
                    return 1;  /* Pops 1 */
                case PRIMARY_DROP:
                    return 1;
                case PRIMARY_DUP:
                    return -1;  /* Pops 1, pushes 2 */
                case PRIMARY_SWAP:
                    return 0;  /* Pops 2, pushes 2 */
                case PRIMARY_ELEM:
                    return 1;  /* Pops 2, pushes 1 */
                default:
                    return 0;
            }
            
        case OP_LD:
            return -1;  /* Pushes 1 */
            
        case OP_LDA:
            return -2;  /* Pushes 2 (address + dummy) */
            
        case OP_ST:
            return 0;  /* Pops 1, pushes nothing */
            
        case OP_CTRL:
            switch (subop) {
                case CTRL_CJMPz:
                case CTRL_CJMPnz:
                    return 1;  /* Pops 1 */
                case CTRL_BEGIN:
                case CTRL_CBEGIN:
                    return 2;  /* Pops 2 (n_caps + function) */
                case CTRL_CLOSURE:
                    return -1;  /* Pushes 1 */
                case CTRL_CALLC:
                    /* Pops n_args + 1 (function), pushes 1 */
                    if (ip) {
                        int n_args = *(const int*)(ip + 1);
                        return n_args;
                    }
                    return 0;
                case CTRL_CALL:
                    /* Pops n_args, pushes 1 */
                    if (ip) {
                        int n_args = *(const int*)(ip + 1 + sizeof(int));
                        return n_args - 1;
                    }
                    return 0;
                case CTRL_TAG:
                case CTRL_ARRAY:
                    return 0;
                case CTRL_FAIL:
                    return 1;
                case CTRL_LINE:
                    return 0;
                default:
                    return 0;
            }
            
        case OP_PATT:
            switch (subop) {
                case PATT_STR:
                    return 1;
                case PATT_STRING_TAG:
                case PATT_ARRAY_TAG:
                case PATT_SEXP_TAG:
                case PATT_REF:
                case PATT_VAL:
                case PATT_FUN:
                    return 0;
                default:
                    return 0;
            }
            
        case OP_BUILTIN:
            switch (subop) {
                case BUILTIN_READ:
                    return -1;
                case BUILTIN_WRITE:
                    return 0;
                case BUILTIN_LENGTH:
                case BUILTIN_STRING:
                    return 0;
                case BUILTIN_ARRAY:
                    if (ip) {
                        int n = *(const int*)(ip + 1);
                        return n - 1;
                    }
                    return 0;
                default:
                    return 0;
            }
            
        default:
            return 0;
    }
}

/* Check if instruction affects control flow */
bool is_control_flow_instruction(unsigned char opcode, unsigned char subop) {
    if (opcode == OP_PRIMARY && subop == PRIMARY_JMP) return true;
    if (opcode == OP_CTRL) {
        return (subop == CTRL_CJMPz || subop == CTRL_CJMPnz ||
                subop == CTRL_BEGIN || subop == CTRL_CBEGIN ||
                subop == CTRL_CALLC || subop == CTRL_CALL);
    }
    return false;
}

/* Check if instruction terminates basic block */
bool is_terminator_instruction(unsigned char opcode, unsigned char subop) {
    if (opcode == OP_HALT) return true;
    if (opcode == OP_PRIMARY && subop == PRIMARY_JMP) return true;
    if (opcode == OP_CTRL && 
        (subop == CTRL_CJMPz || subop == CTRL_CJMPnz || 
         subop == CTRL_BEGIN || subop == CTRL_CBEGIN ||
         subop == CTRL_CALLC || subop == CTRL_CALL ||
         subop == CTRL_FAIL || subop == PRIMARY_END)) {
        return true;
    }
    return false;
}

/* Verify individual instruction encoding */
static bool verify_instruction_at(VerifierContext *ctx, const char *ip, int offset) {
    unsigned char x = (unsigned char)*ip;
    unsigned char h = (x & 0xF0) >> 4;
    unsigned char l = x & 0x0F;
    
    /* Check for valid opcode prefix */
    if (h > OP_BUILTIN && h != OP_HALT) {
        report_error(ctx, offset, "Invalid opcode prefix: %d", h);
        return false;
    }
    
    /* Instruction-specific validation */
    switch (h) {
        case OP_PRIMARY:
            if (l > PRIMARY_ELEM) {
                report_error(ctx, offset, "Invalid primary opcode: %d", l);
                return false;
            }
            break;
            
        case OP_LD:
        case OP_LDA:
        case OP_ST:
            if (l >= LOC_N) {
                report_error(ctx, offset, "Invalid location type: %d", l);
                return false;
            }
            break;
            
        case OP_CTRL:
            if (l > CTRL_LINE) {
                report_error(ctx, offset, "Invalid control opcode: %d", l);
                return false;
            }
            break;
            
        case OP_PATT:
            if (l > PATT_FUN) {
                report_error(ctx, offset, "Invalid pattern opcode: %d", l);
                return false;
            }
            break;
            
        case OP_BUILTIN:
            if (l > BUILTIN_ARRAY) {
                report_error(ctx, offset, "Invalid builtin opcode: %d", l);
                return false;
            }
            break;
    }
    
    /* Validate instruction fits within code */
    int size = get_instruction_size(h, l, ip);
    if (offset + size > ctx->code_size) {
        report_error(ctx, offset, "Instruction extends beyond code boundary");
        return false;
    }
    
    /* Validate immediate values */
    if (h == OP_PRIMARY && l == PRIMARY_STRING) {
        int str_idx = *(const int*)(ip + 1);
        if (str_idx < 0 || str_idx >= get_bf_stringtab_size(ctx->bf)) {
            report_error(ctx, offset, "String index out of bounds: %d", str_idx);
            return false;
        }
    }
    
    /* Validate jumps */
    if ((h == OP_PRIMARY && l == PRIMARY_JMP) ||
        (h == OP_CTRL && (l == CTRL_CJMPz || l == CTRL_CJMPnz))) {
        int jump_offset = *(const int*)(ip + 1);
        int target = offset + 1 + sizeof(int) + jump_offset;
        
        if (target < 0 || target >= ctx->code_size) {
            report_error(ctx, offset, "Jump target out of bounds: %d (target=%d, code_size=%d)", 
                        jump_offset, target, ctx->code_size);
            return false;
        }
        
        /* Mark target as a jump target */
        ctx->is_jump_target[target] = true;
    }
    
    /* Validate variable references */
    if (h == OP_LD || h == OP_LDA || h == OP_ST) {
        int idx = *(const int*)(ip + 1);
        if (idx < 0) {
            report_error(ctx, offset, "Negative variable index: %d", idx);
            return false;
        }
    }
    
    return true;
}

/* Perform control flow analysis */
static bool analyze_control_flow(VerifierContext *ctx) {
    const char *code_start = get_bf_code_ptr(ctx->bf);
    int code_size = ctx->code_size;
    
    /* Worklist for reachability analysis */
    int *worklist = malloc(code_size * sizeof(int));
    if (!worklist) {
        report_error(ctx, 0, "Failed to allocate worklist");
        return false;
    }
    
    int worklist_size = 0;
    
    /* Start from main entry point (assuming offset 0) */
    worklist[worklist_size++] = 0;
    ctx->stack_heights[0] = 0;
    
    while (worklist_size > 0) {
        int offset = worklist[--worklist_size];
        
        if (ctx->visited[offset]) {
            continue;
        }
        ctx->visited[offset] = true;
        
        const char *ip = code_start + offset;
        
        if (offset >= code_size) {
            report_error(ctx, offset, "Fell off end of code");
            free(worklist);
            return false;
        }
        
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        /* Get current stack height */
        int current_height = ctx->stack_heights[offset];
        if (current_height < 0) {
            continue;
        }
        
        /* Update max stack height */
        if (current_height > ctx->max_stack_height) {
            ctx->max_stack_height = current_height;
        }
        
        /* Check stack underflow */
        int stack_effect = get_stack_effect(h, l, ip);
        int pops = -stack_effect > 0 ? -stack_effect : 0;
        
        if (current_height < pops) {
            report_error(ctx, offset, 
                        "Stack underflow: need %d values, have %d", 
                        pops, current_height);
            free(worklist);
            return false;
        }
        
        /* Calculate new stack height */
        int new_height = current_height + stack_effect;
        
        /* Handle control flow */
        if (h == OP_PRIMARY && l == PRIMARY_JMP) {
            /* Unconditional jump */
            int jump_offset = *(const int*)(ip + 1);
            int target = offset + 1 + sizeof(int) + jump_offset;
            
            if (target >= 0 && target < code_size) {
                if (ctx->stack_heights[target] == -1) {
                    ctx->stack_heights[target] = new_height;
                } else if (ctx->stack_heights[target] != new_height) {
                    report_error(ctx, offset,
                                "Stack height mismatch at jump target: %d vs %d",
                                ctx->stack_heights[target], new_height);
                }
                worklist[worklist_size++] = target;
            }
            continue;
        }
        else if (h == OP_CTRL && (l == CTRL_CJMPz || l == CTRL_CJMPnz)) {
            /* Conditional jump */
            int jump_offset = *(const int*)(ip + 1);
            int target = offset + 1 + sizeof(int) + jump_offset;
            
            /* Add both successors */
            int next_offset = offset + get_instruction_size(h, l, ip);
            
            if (target >= 0 && target < code_size) {
                if (ctx->stack_heights[target] == -1) {
                    ctx->stack_heights[target] = new_height;
                } else if (ctx->stack_heights[target] != new_height) {
                    report_error(ctx, offset,
                                "Stack height mismatch at jump target: %d vs %d",
                                ctx->stack_heights[target], new_height);
                }
                worklist[worklist_size++] = target;
            }
            
            if (next_offset < code_size) {
                if (ctx->stack_heights[next_offset] == -1) {
                    ctx->stack_heights[next_offset] = new_height;
                } else if (ctx->stack_heights[next_offset] != new_height) {
                    report_error(ctx, offset,
                                "Stack height mismatch at fall-through: %d vs %d",
                                ctx->stack_heights[next_offset], new_height);
                }
                worklist[worklist_size++] = next_offset;
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
            /* Normal instruction - continue to next */
            int next_offset = offset + get_instruction_size(h, l, ip);
            if (next_offset < code_size) {
                if (ctx->stack_heights[next_offset] == -1) {
                    ctx->stack_heights[next_offset] = new_height;
                } else if (ctx->stack_heights[next_offset] != new_height) {
                    report_error(ctx, offset,
                                "Stack height mismatch: %d vs %d",
                                ctx->stack_heights[next_offset], new_height);
                }
                worklist[worklist_size++] = next_offset;
            }
        }
    }
    
    free(worklist);
    
    /* Check for unreachable code */
    for (int i = 0; i < code_size; i++) {
        if (!ctx->visited[i] && code_start[i] != 0) {
            report_error(ctx, i, "Unreachable code");
        }
    }
    
    return true;
}

/* Verify variable references are in bounds */
bool verify_variable_references(VerifierContext *ctx) {
    const char *ip = get_bf_code_ptr(ctx->bf);
    int offset = 0;
    int code_size = ctx->code_size;
    
    while (offset < code_size) {
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        if (h == OP_LD || h == OP_LDA || h == OP_ST) {
            int var_index = *(const int*)(ip + 1);
            unsigned char loc_type = l;
            
            if (var_index < 0) {
                report_error(ctx, offset, "Negative variable index: %d", var_index);
            }
            
            switch (loc_type) {
                case LOC_G:  /* Global */
                    if (var_index >= get_bf_global_area_size(ctx->bf)) {
                        report_error(ctx, offset, 
                                    "Global index out of bounds: %d >= %d",
                                    var_index, get_bf_global_area_size(ctx->bf));
                    }
                    break;
                    
                case LOC_L:  /* Local */
                case LOC_A:  /* Argument */
                case LOC_C:  /* Capture */
                    /* Более сложная проверка требует контекста функции */
                    break;
            }
        }
        
        /* Move to next instruction */
        int size = get_instruction_size(h, l, ip);
        if (size <= 0) {
            report_error(ctx, offset, "Invalid instruction size");
            break;
        }
        
        offset += size;
        ip += size;
    }
    
    return ctx->error_count == 0;
}

/* Main verification function */
bool verify_bytecode(bytefile *bf, const char *fname) {

    signal(SIGSEGV, sigsegv_handler);

    /* Временное решение: вычисляем размер кода грубо */
    const char *code_start = get_bf_code_ptr(bf);
    
    /* Ищем конец кода по инструкции HALT */
    int code_size = 0;
    for (int i = 0; i < 100000; i++) {  /* Ограничиваем поиск */
        if (i >= 100000 - 1) {
            /* Не нашли HALT в пределах лимита */
            code_size = 10000; /* Консервативная оценка */
            break;
        }
        
        unsigned char x = (unsigned char)code_start[i];
        unsigned char h = (x & 0xF0) >> 4;
        
        if (h == OP_HALT) {
            code_size = i + 1;
            break;
        }
    }
    
    if (code_size == 0) {
        code_size = 1000; /* Минимальная оценка */
    }
    
    VerifierContext *ctx = create_verifier_context(bf, fname, code_size);
    if (!ctx) {
        fprintf(stderr, "Failed to create verifier context\n");
        return false;
    }
    
    printf("Verifying bytecode file: %s\n", fname);
    printf("Code size: %d bytes\n", ctx->code_size);
    printf("String table: %d bytes\n", get_bf_stringtab_size(bf));
    printf("Global area: %d words\n", get_bf_global_area_size(bf));
    printf("Public symbols: %d\n", get_bf_public_symbols_number(bf));
    
    bool ok = true;
    
    /* Step 1: Verify instruction encoding */
    printf("\n[1/5] Verifying instruction encoding...\n");
    const char *ip = code_start;
    int offset = 0;
    
    while (offset < ctx->code_size) {
        if (!verify_instruction_at(ctx, ip, offset)) {
            ok = false;
        }
        
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        int size = get_instruction_size(h, l, ip);
        if (size <= 0) {
            report_error(ctx, offset, "Invalid instruction size");
            ok = false;
            break;
        }
        
        offset += size;
        ip += size;
        ctx->total_instructions++;
    }
    
    /* Step 2: Control flow analysis */
    printf("[2/5] Analyzing control flow...\n");
    if (!analyze_control_flow(ctx)) {
        ok = false;
    }
    
    /* Step 3: Verify variable references */
    printf("[3/5] Verifying variable references...\n");
    if (!verify_variable_references(ctx)) {
        ok = false;
    }
    
    /* Step 4: Report results */
    printf("[4/5] Generating report...\n");
    
    if (ctx->error_count > 0) {
        printf("\n❌ Verification failed with %d error(s):\n", ctx->error_count);
        for (int i = 0; i < ctx->error_count; i++) {
            printf("  Error at offset 0x%04x: %s\n", 
                   ctx->errors[i].offset, ctx->errors[i].message);
        }
        ok = false;
    } else {
        printf("\n✅ Bytecode verification passed!\n");
        printf("   Total instructions: %d\n", ctx->total_instructions);
        printf("   Maximum stack height: %d\n", ctx->max_stack_height);
        if (ctx->code_size > 0) {
            printf("   Reachable code: %d%%\n", 
                   (int)(100.0 * ctx->total_instructions / ctx->code_size));
        }
    }
    
    print_verification_errors(ctx);
    free_verifier_context(ctx);
    return ok;
}

/* Print verification errors */
void print_verification_errors(VerifierContext *ctx) {
    if (ctx->error_count == 0) {
        printf("No verification errors found.\n");
        return;
    }
    
    printf("Verification errors (%d):\n", ctx->error_count);
    for (int i = 0; i < ctx->error_count; i++) {
        printf("  [%04x] %s\n", ctx->errors[i].offset, ctx->errors[i].message);
    }
}

/* Free verifier context */
void free_verifier_context(VerifierContext *ctx) {
    if (!ctx) return;
    
    free(ctx->stack_heights);
    free(ctx->visited);
    free(ctx->is_jump_target);
    
    for (int i = 0; i < ctx->error_count; i++) {
        free(ctx->errors[i].message);
    }
    free(ctx->errors);
    
    free(ctx);
}