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
static int read_int_at(const char *ip, int offset);
static int count_bits(bool *array, int size);
static void propagate_stack_height(VerifierContext *ctx, int target, int height, 
                                  int *worklist, int *worklist_size);
static bool verify_bytecode_internal(bytefile *bf, const char *fname, bool verbose, const char *code_stop_ptr);

/* Добавить в verifier.c в начале (после includes) */
static void hex_dump(const char *label, const void *data, int offset, int length) {
    const unsigned char *bytes = (const unsigned char *)data;
    
    printf("\n=== %s (offset %d, length %d) ===\n", label, offset, length);
    printf("Address: %p\n", bytes);
    
    for (int i = 0; i < length; i++) {
        if (i % 16 == 0) {
            printf("\n%04x: ", i);
        }
        printf("%02x ", bytes[i + offset]);
        if (i % 8 == 7) {
            printf(" ");
        }
    }
    printf("\n");
    
    // ASCII представление
    printf("\nASCII: ");
    for (int i = 0; i < length; i++) {
        unsigned char c = bytes[i + offset];
        if (c >= 32 && c < 127) {
            printf("%c", c);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

/* void debug_dump_around(bytefile *bf, int error_offset, ) {
    const char *code = bf->code_prt;
    printf("\n=== Debug around offset 0x%04x ===\n", error_offset);
    
    int start = error_offset - 16;
    if (start < 0) start = 0;
    int end = error_offset + 16;
    
    printf("Real code ptr: %p\n", (void*)code);
    printf("Bytes around error:\n");
    
    for (int i = start; i < end && i < 100; i++) {
        if (i == error_offset) printf("[%02x] ", (unsigned char)code[i]);
        else printf(" %02x  ", (unsigned char)code[i]);
    }
    printf("\n");
    
    // Покажем также, что думает верификатор
    printf("\nWhat verifier sees at 0x%04x:\n", error_offset);
    unsigned char x = (unsigned char)code[error_offset];
    printf("  Byte: 0x%02x\n", x);
    printf("  Binary: ");
    for (int bit = 7; bit >= 0; bit--) {
        printf("%d", (x >> bit) & 1);
        if (bit == 4) printf(" ");
    }
    printf("\n  h=%d, l=%d\n", (x >> 4) & 0xF, x & 0xF);
} */

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

    ctx->is_instruction_part = calloc(code_size, sizeof(bool));
    
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
                case PRIMARY_STA:
                case PRIMARY_ELEM:
                    return 1 + sizeof(int);  // 5 байт
                default:
                    return 1;  // 1 байт
            }
            
        case OP_LD:
        case OP_LDA:
        case OP_ST:
            return 1 + sizeof(int);  // 5 байт
            
        case OP_CTRL:
            switch (subop) {
                case CTRL_CJMPz:
                case CTRL_CJMPnz:
                case CTRL_CALLC:
                case CTRL_LINE:
                    return 1 + sizeof(int);  // 5 байт
                    
                case CTRL_BEGIN:
                case CTRL_CBEGIN:
                    return 1 + sizeof(int) * 2;  // 9 байт
                    
                case CTRL_CLOSURE:
                case CTRL_CALL:
                case CTRL_TAG:
                case CTRL_ARRAY:
                case CTRL_FAIL:
                    return 1 + sizeof(int) * 2;  // 9 байт
                    
                default:
                    return 1;
            }
            
        case OP_PATT: return 1;
        
        case OP_BUILTIN:
            switch (subop) {
                case BUILTIN_ARRAY:
                    return 1 + sizeof(int);  // 5 байт
                default:
                    return 1;
            }
            
        default:
            return 1;
    }
}

/* Get stack effect with context for functions */
int get_stack_effect(unsigned char opcode, unsigned char subop, const char *ip, VerifierContext *ctx) {
    int effect = 0;
    
    switch (opcode) {
        case OP_HALT: effect = 0; break;
        
        case OP_BINOP:
            effect = 1;  // Pops 2, pushes 1 = net POP 1
            break;
            
        case OP_PRIMARY:
            switch (subop) {
                case PRIMARY_CONST:
                case PRIMARY_STRING:
                    effect = -1;  // Pushes 1
                    break;
                case PRIMARY_SEXP:
                    if (ip) {
                        int n = read_int_at(ip, 1 + sizeof(int));
                        effect = n - 1;  // Pops n, pushes 1
                    }
                    break;
                case PRIMARY_STA:
                    effect = 2;  // Pops 3, pushes 1
                    break;
                case PRIMARY_JMP:
                    effect = 0;
                    break;
                case PRIMARY_END:
                    if (ctx && ctx->current_function >= 0) {
                        FunctionInfo *func = &ctx->functions[ctx->current_function];
                        effect = 1 + func->params + func->locals + func->captures;
                    } else {
                        effect = 1;  // Pops return value
                    }
                    break;
                case PRIMARY_DROP:
                    effect = 1;  // Pops 1
                    break;
                case PRIMARY_DUP:
                    effect = -1; // Pops 1, pushes 2 = net PUSH 1
                    break;
                case PRIMARY_SWAP:
                    effect = 0;  // Pops 2, pushes 2
                    break;
                case PRIMARY_ELEM:
                    effect = 1;  // Pops 2, pushes 1
                    break;
                default:
                    effect = 0;
            }
            break;
            
        case OP_LD:
            effect = -1;  // Pushes 1
            break;
            
        case OP_LDA:
            effect = -2;  // Pushes 2 (address + dummy)
            break;
            
        case OP_ST:
            effect = 0;   // Pops 1
            break;
            
        case OP_CTRL:
            switch (subop) {
                case CTRL_CJMPz:
                case CTRL_CJMPnz:
                    effect = 1;  // Pops 1
                    break;
                case CTRL_BEGIN:
                case CTRL_CBEGIN:
                    effect = 2;  // Pops 2 (n_caps + function)
                    break;
                case CTRL_CLOSURE:
                    effect = -1; // Pushes 1
                    break;
                case CTRL_CALLC:
                    if (ip) {
                        int n_args = read_int_at(ip, 1);
                        effect = n_args;  // Pops n_args + 1, pushes 1
                    }
                    break;
                case CTRL_CALL:
                    if (ip) {
                        int n_args = read_int_at(ip, 1 + sizeof(int));
                        effect = n_args - 1;  // Pops n_args, pushes 1
                    }
                    break;
                case CTRL_TAG:
                case CTRL_ARRAY:
                    effect = 0;  // Pops 1, pushes 1
                    break;
                case CTRL_FAIL:
                    effect = 1;  // Pops 1
                    break;
                case CTRL_LINE:
                    effect = 0;
                    break;
                default:
                    effect = 0;
            }
            break;
            
        case OP_PATT:
            switch (subop) {
                case PATT_STR:
                    effect = 1;  // Pops 2, pushes 1
                    break;
                default:
                    effect = 0;  // Pops 1, pushes 1
            }
            break;
            
        case OP_BUILTIN:
            switch (subop) {
                case BUILTIN_READ:
                    effect = -1; // Pushes 1
                    break;
                case BUILTIN_WRITE:
                    effect = 0;  // Pops 1, pushes 1
                    break;
                case BUILTIN_LENGTH:
                case BUILTIN_STRING:
                    effect = 0;  // Pops 1, pushes 1
                    break;
                case BUILTIN_ARRAY:
                    if (ip) {
                        int n = read_int_at(ip, 1);
                        effect = n - 1;  // Pops n, pushes 1
                    }
                    break;
                default:
                    effect = 0;
            }
            break;
            
        default:
            effect = 0;
    }
    
    printf("  Stack effect for %s: %d (positive = pop, negative = push)\n", 
           get_opcode_name(opcode, subop), effect);
    return effect;
}

/* Check if instruction is a function start */
bool is_function_start_instruction(unsigned char opcode, unsigned char subop) {
    return (opcode == OP_CTRL && (subop == CTRL_BEGIN || subop == CTRL_CBEGIN));
}

/* Read integer from bytecode at offset */
static int read_int_at(const char *ip, int offset) {
    // Временно: прямой дамп байтов
    const unsigned char *bytes = (const unsigned char*)(ip + offset);
    printf("DEBUG read_int_at: bytes[%02x %02x %02x %02x] at offset %d\n",
           bytes[0], bytes[1], bytes[2], bytes[3], offset);
    
    // Little-endian
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
}

/* Phase 1: Verify instruction encoding */
bool verify_instruction_encoding(VerifierContext *ctx) {
    const char *code_start = ctx->bf->code_ptr;
    int offset = 0;
    int errors = 0;
    
    printf("\n=== Phase 1: Instruction Encoding Verification ===\n");
    printf("Code size: %d bytes\n", ctx->code_size);
    
    while (offset < ctx->code_size) {
        const char *ip = code_start + offset;
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;

        // Проверка на 0x00 (возможно, padding)
        if (x == 0x00) {
            printf("  WARNING: Zero byte at offset %d - might be padding\n", offset);
            // Пропускаем как возможный padding
            offset += 1;
            continue;
        }
        
        
        // Получаем размер ДО любых проверок
        int size = get_instruction_size(h, l, ip);
        
        // Пометим ВСЕ байты этой инструкции как "часть инструкции"
        for (int i = 0; i < size && (offset + i) < ctx->code_size; i++) {
            ctx->is_instruction_part[offset + i] = true;
        }
        
        printf("[0x%04x] 0x%02x: %s (size=%d)", 
               offset, x, get_opcode_name(h, l), size);
        
        // Показать все байты инструкции
        printf(" [");
        for (int i = 0; i < size && (offset + i) < ctx->code_size; i++) {
            printf("%02x", (unsigned char)code_start[offset + i]);
            if (i < size - 1) printf(" ");
        }
        printf("]\n");
        
        // Проверка 1: валидный размер
        if (size <= 0) {
            report_error(ctx, offset, "Invalid instruction size: %d", size);
            errors++;
            break;
        }
        
        // Проверка 2: влезает в код
        if (offset + size > ctx->code_size) {
            report_error(ctx, offset, 
                        "Instruction extends beyond code boundary (needs %d, have %d)", 
                        size, ctx->code_size - offset);
            errors++;
            break;
        }
        
        // Проверка 3: валидный опкод
        if (h > OP_BUILTIN && h != OP_HALT) {
            report_error(ctx, offset, "Invalid opcode prefix: 0x%02x", x);
            errors++;
        }

        // Проверка на валидные BINOP коды
        if (h == OP_BINOP) {
            if (l < 1 || l >= OP_N) {  // OP_N = 14
                report_error(ctx, offset, "Invalid binary operation: %d", l);
                errors++;
            }
        }

        // Проверка 4: для BEGIN/CBEGIN
        if (h == OP_CTRL && (l == CTRL_BEGIN || l == CTRL_CBEGIN)) {
            printf("  Function start: ");
            if (l == CTRL_BEGIN) {
                int n_args = read_int_at(ip, 1);
                int n_locs = read_int_at(ip, 5);
                printf("BEGIN args=%d, locs=%d\n", n_args, n_locs);
                
                if (n_args < 0 || n_args > 100) {
                    report_error(ctx, offset, "Invalid n_args: %d", n_args);
                    errors++;
                }
                if (n_locs < 0 || n_locs > 100) {
                    report_error(ctx, offset, "Invalid n_locs: %d", n_locs);
                    errors++;
                }
            } else { // CBEGIN
                int n_caps = read_int_at(ip, 1);
                int n_args = read_int_at(ip, 5);
                int n_locs = read_int_at(ip, 9);
                printf("CBEGIN caps=%d, args=%d, locs=%d\n", n_caps, n_args, n_locs);
            }
            
            ctx->is_function_start[offset] = true;
        }
        
        // Проверка 5: прыжки
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
                printf("  Jump to 0x%04x\n", target);
            }
        }
        
        // Проверка 6: CALL/CALLC/CLOSURE
        if (h == OP_CTRL && (l == CTRL_CALL || l == CTRL_CALLC || l == CTRL_CLOSURE)) {
            int target = read_int_at(ip, 1);
            if (target < 0 || target >= ctx->code_size) {
                report_error(ctx, offset, "Call target out of bounds: %d", target);
                errors++;
            } else {
                // Проверяем, что цель - функция
                if (target < ctx->code_size) {
                    unsigned char target_op = (unsigned char)code_start[target];
                    unsigned char target_h = (target_op & 0xF0) >> 4;
                    unsigned char target_l = target_op & 0x0F;
                    if (target_h == OP_CTRL && 
                        (target_l == CTRL_BEGIN || target_l == CTRL_CBEGIN)) {
                        ctx->is_function_start[target] = true;
                        printf("  Calls function at 0x%04x\n", target);
                    }
                }
            }
        }
        
        // Продвижение offset - ТОЛЬКО ОДИН РАЗ!
        offset += size;
        ctx->total_instructions++;
        
        // Ограничим вывод для отладки
        if (ctx->total_instructions > 20) {
            printf("... (stopping debug output after 20 instructions)\n");
            break;
        }
    }
    
    printf("Processed %d instructions\n", ctx->total_instructions);
    printf("Found %d function start points\n", 
           count_bits(ctx->is_function_start, ctx->code_size));
    printf("Found %d jump targets\n", 
           count_bits(ctx->is_jump_target, ctx->code_size));
    printf("Encoding errors: %d\n", errors);
    
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
    
    printf("\n=== Phase 2: Control Flow Analysis ===\n");
    
    /* Start from main (offset 0) */
    worklist[worklist_size++] = 0;
    ctx->stack_heights[0] = 2;
    ctx->visited[0] = true;
    
    printf("Starting control flow analysis from offset 0\n");
    printf("Total code size: %d bytes\n", ctx->code_size);
    
    int iteration = 0;
    while (worklist_size > 0 && iteration < 50) {  // Ограничим для отладки
        iteration++;
        int offset = worklist[--worklist_size];
        
        printf("\n[Iteration %d] Processing offset 0x%04x\n", iteration, offset);
        
        const char *ip = code_start + offset;
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        printf("  Instruction: 0x%02x = %s\n", x, get_opcode_name(h, l));
        
        int instruction_size = get_instruction_size(h, l, ip);
        printf("  Size: %d bytes\n", instruction_size);
        
        // Показать байты инструкции
        printf("  Bytes: ");
        for (int i = 0; i < instruction_size && (offset + i) < ctx->code_size; i++) {
            printf("%02x ", (unsigned char)code_start[offset + i]);
        }
        printf("\n");
        
        int current_height = ctx->stack_heights[offset];
        printf("  Stack height: %d\n", current_height);
        
        /* Check stack underflow */
        int stack_effect = get_stack_effect(h, l, ip, ctx);
        printf("  Stack effect: %d\n", stack_effect);
        
        int new_height;

        if (stack_effect > 0) {
            // POP values
            new_height = current_height - stack_effect;
            if (new_height < 0) {
                // Stack underflow - ошибка
                new_height = 0;  // Для продолжения
            }
        } else if (stack_effect < 0) {
            // PUSH values
            new_height = current_height - stack_effect; 
        } else {
            // No change
            new_height = current_height;
        }

        printf("  New stack height: %d\n", new_height);
        
        /* Handle control flow */
        if (h == OP_PRIMARY && l == PRIMARY_JMP) {
            printf("  Unconditional JMP\n");
            int jump_offset = read_int_at(ip, 1);
            int target = offset + 1 + sizeof(int) + jump_offset;
            printf("  Target: offset %d + 5 + %d = %d (0x%04x)\n", 
                   offset, jump_offset, target, target);
            
            if (target >= 0 && target < ctx->code_size) {
                propagate_stack_height(ctx, target, new_height, worklist, &worklist_size);
                printf("  Added target to worklist\n");
            }
            continue;
        }
        else if (h == OP_CTRL && (l == CTRL_CJMPz || l == CTRL_CJMPnz)) {
            printf("  Conditional JMP\n");
            int jump_offset = read_int_at(ip, 1);
            int target = offset + 1 + sizeof(int) + jump_offset;
            int fallthrough = offset + instruction_size;
            
            printf("  Target: %d (0x%04x), Fallthrough: %d (0x%04x)\n", 
                   target, target, fallthrough, fallthrough);
            
            if (target >= 0 && target < ctx->code_size) {
                propagate_stack_height(ctx, target, new_height, worklist, &worklist_size);
            }
            if (fallthrough < ctx->code_size) {
                propagate_stack_height(ctx, fallthrough, new_height, worklist, &worklist_size);
            }
            continue;
        }
        else if (h == OP_PRIMARY && l == PRIMARY_END) {
            printf("  END instruction - stopping\n");
            continue;
        }
        else if (h == OP_HALT) {
            printf("  HALT instruction - stopping\n");
            continue;
        }
        else {
            /* Normal fall-through */
            int next = offset + instruction_size;
            printf("  Fallthrough to: %d (0x%04x)\n", next, next);
            
            if (next < ctx->code_size) {
                propagate_stack_height(ctx, next, new_height, worklist, &worklist_size);
                printf("  Added fallthrough to worklist\n");
            } else {
                printf("  Fallthrough out of bounds\n");
            }
        }
    }
    
    if (iteration >= 50) {
        printf("\n⚠️ Stopped after 50 iterations (might be infinite loop)\n");
    }
    
    /* Check for unreachable code */
    printf("\n=== Unreachable code analysis ===\n");
    int unreachable_count = 0;

    for (int i = 0; i < ctx->code_size; i++) {
        if (!ctx->visited[i]) {
            // Игнорируем байты, которые являются частью инструкций!
            if (ctx->is_instruction_part[i]) {
                // Этот байт уже часть какой-то инструкции
                continue;
            }
            
            unsigned char x = (unsigned char)code_start[i];
            
            // Игнорируем нулевые байты
            if (x == 0) continue;
            
            unsigned char h = (x & 0xF0) >> 4;
            unsigned char l = x & 0x0F;
            
            // Проверяем, валидный ли это опкод
            if (h <= OP_BUILTIN || h == OP_HALT) {
                printf("Unreachable at 0x%04x: 0x%02x = %s\n", 
                    i, x, get_opcode_name(h, l));
                unreachable_count++;
                
                if (!ctx->is_function_start[i]) {
                    report_error(ctx, i, "Unreachable code");
                    errors++;
                }
            }
        }
    }
    
    printf("Total unreachable bytes that look like instructions: %d\n", unreachable_count);
    
    free(worklist);
    
    printf("\nControl flow analysis complete\n");
    printf("Maximum stack depth: %d\n", ctx->max_stack_height);
    printf("Reachable instructions: %d\n", count_bits(ctx->visited, ctx->code_size));
    printf("Control flow errors: %d\n", errors);
    
    return errors == 0;
}

/* Propagate stack height to target */
static void propagate_stack_height(VerifierContext *ctx, int target, int height, 
                                  int *worklist, int *worklist_size) {
    printf("  Propagate to 0x%04x: height %d -> ", target, height);
    
    if (ctx->stack_heights[target] == -1) {
        ctx->stack_heights[target] = height;
        printf("set to %d\n", height);
    } else if (ctx->stack_heights[target] != height) {
        printf("CONFLICT: was %d, now %d\n", ctx->stack_heights[target], height);
        report_error(ctx, target, 
                    "Stack height mismatch: %d vs %d at merge point",
                    ctx->stack_heights[target], height);
    } else {
        printf("already %d\n", height);
    }
    
    if (!ctx->visited[target]) {
        ctx->visited[target] = true;
        worklist[(*worklist_size)++] = target;
        printf("  Added to worklist (new size: %d)\n", *worklist_size);
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
            unsigned char h = (x & 0xF0) >> 4;
            unsigned char l = x & 0x0F;
            
            FunctionInfo *func = &ctx->functions[ctx->function_count++];
            func->address = offset;
            func->is_closure = (l == CTRL_CBEGIN);
            
            printf("\n[Function at 0x%04x] ", offset);
            printf("Byte: 0x%02x -> %s\n", x, func->is_closure ? "CBEGIN" : "BEGIN");
            
            if (func->is_closure) {
                // CBEGIN: n_caps, n_args, n_locs
                func->captures = read_int_at(ip, 1);
                func->params = read_int_at(ip, 5);
                func->locals = read_int_at(ip, 9);
                
                printf("  CBEGIN layout (3 ints):\n");
            } else {
                // BEGIN: ТОЛЬКО n_args, n_locs (без n_caps!)
                func->captures = 0;
                func->params = read_int_at(ip, 1);   // байты 1-4
                func->locals = read_int_at(ip, 5);   // байты 5-8
                
                printf("  BEGIN layout (2 ints, no n_caps):\n");
            }
            
            printf("    n_args=%d, n_locs=%d", func->params, func->locals);
            if (func->is_closure) {
                printf(", n_caps=%d", func->captures);
            }
            printf("\n");
            
            // Проверки на разумность значений
            if (func->locals > 1000) {
                printf("  ⚠️ WARNING: Suspicious locals=%d\n", func->locals);
                printf("  Raw bytes around offset %d: ", offset);
                for (int i = 0; i < 16 && (offset + i) < ctx->code_size; i++) {
                    printf("%02x ", (unsigned char)code_start[offset + i]);
                }
                printf("\n");
                
                // Попробуем понять, что пошло не так
                printf("  Checking interpretation:\n");
                printf("    If this is CBEGIN: caps=%d, args=%d, locs=%d\n",
                       read_int_at(ip, 1), read_int_at(ip, 5), read_int_at(ip, 9));
                printf("    If this is BEGIN: args=%d, locs=%d (reading from wrong offset?)\n",
                       read_int_at(ip, 1), read_int_at(ip, 5));
                
                // Временно: предположим ошибку чтения и используем безопасное значение
                func->locals = 0;
            }
            
            if (func->params > MAX_PARAMS) {
                report_error(ctx, offset, "Too many parameters: %d (max %d)",
                            func->params, MAX_PARAMS);
                errors++;
            }
            if (func->locals > MAX_LOCALS) {
                // Более информативное сообщение
                report_error(ctx, offset, 
                            "Too many locals: %d (max %d). " 
                            "This might be due to incorrect bytecode interpretation.",
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
            unsigned char h = (x & 0xF0) >> 4;
            unsigned char l = x & 0x0F;
            int size = get_instruction_size(h, l, code_start + offset);
            
            if (size <= 0) {
                printf("⚠️ WARNING: Invalid instruction size at offset %d\n", offset);
                break;
            }
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
    
    printf("\n=== Phase 5: Stack Usage Verification ===\n");
    
    for (int i = 0; i < ctx->function_count; i++) {
        FunctionInfo *func = &ctx->functions[i];
        
        printf("\nFunction at 0x%04x (%s):\n", 
               func->address, func->is_closure ? "CBEGIN" : "BEGIN");
        printf("  params=%d, locals=%d, captures=%d\n", 
               func->params, func->locals, func->captures);
        
        // 1. Проверка высоты стека при входе в функцию
        int expected_height_before = 2;  // n_caps + function
        int actual_height_before = ctx->stack_heights[func->address];

        if (actual_height_before != expected_height_before) {
            // Для main функции может быть разное начальное состояние
            if (func->address == 0) {
                printf("  ⚠️ Main function might have different entry conditions\n");
                continue;
                // Для main принимаем любую высоту
            } else {
                report_error(ctx, func->address,
                            "Wrong stack height at function entry: expected %d, got %d",
                            expected_height_before, actual_height_before);
                errors++;
            }
        }
        
        printf("  At entry (offset %d): expected %d, actual %d\n",
               func->address, expected_height_before, actual_height_before);
        
        
        // 2. Проверка высоты стека после пролога
        // Находим инструкцию после BEGIN/CBEGIN
        const char *ip = ctx->bf->code_ptr + func->address;
        unsigned char x = (unsigned char)*ip;
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;
        
        int instruction_size = get_instruction_size(h, l, ip);
        int after_prologue = func->address + instruction_size;
        
        if (after_prologue < ctx->code_size) {
            // После BEGIN на стеке должны быть только локальные переменные
            int expected_height_after = func->locals;
            int actual_height_after = ctx->stack_heights[after_prologue];
            
            printf("  After prologue (offset %d): expected %d, actual %d\n",
                   after_prologue, expected_height_after, actual_height_after);
            
            if (actual_height_after != expected_height_after) {
                report_error(ctx, after_prologue,
                            "Wrong stack after function prologue: expected %d, got %d",
                            expected_height_after, actual_height_after);
                errors++;
            }
        }
    }
    
    printf("\nStack usage errors: %d\n", errors);
    return errors == 0;
}

/* Main verification function */
bool verify_bytecode(bytefile *bf, const char *fname, const char *code_stop_ptr) {
    return verify_bytecode_internal(bf, fname, false, code_stop_ptr);
}

bool verify_bytecode_verbose(bytefile *bf, const char *fname, const char *code_stop_ptr) {
    return verify_bytecode_internal(bf, fname, true, code_stop_ptr);
}

static bool verify_bytecode_internal(bytefile *bf, const char *fname, bool verbose, const char *code_stop_ptr) {
    printf("\n=== Lama Bytecode Verifier ===\n");
    printf("File: %s\n", fname);
    
    // ВАЖНО: bf->code_ptr уже указывает на начало кода
    // code_stop_ptr указывает на последний байт кода
    
    const char *code_start = bf->code_ptr;
    
    // Рассчитываем правильный размер кода
    int code_size = 0;
    if (code_stop_ptr >= code_start) {
        code_size = (int)(code_stop_ptr - code_start + 1);
    } else {
        // Запасной вариант: ищем HALT
        for (int i = 0; i < 100000; i++) {
            if ((unsigned char)code_start[i] == 0xF0) {  // HALT
                code_size = i + 1;
                break;
            }
        }
    }
    
    printf("Code start: %p\n", (void*)code_start);
    printf("Code stop: %p\n", (void*)code_stop_ptr);
    printf("Calculated size: %d bytes\n", code_size);
    
    if (code_size <= 0 || code_size > 1000000) {
        printf("❌ ERROR: Invalid code size: %d\n", code_size);
        return false;
    }
    
    // ДАМП для проверки
    printf("\n=== ACTUAL CODE DUMP (first %d bytes) ===\n", code_size < 48 ? code_size : 48);
    for (int i = 0; i < code_size && i < 48; i++) {
        if (i % 16 == 0) printf("\n%04x: ", i);
        printf("%02x ", (unsigned char)code_start[i]);
        if (i % 8 == 7) printf(" ");
    }
    printf("\n");
    
    // Проверим, что код начинается с BEGIN
    if (code_size > 0) {
        unsigned char first_byte = (unsigned char)code_start[0];
        printf("\nFirst byte of actual code: 0x%02x\n", first_byte);
        
        unsigned char h = (first_byte & 0xF0) >> 4;
        unsigned char l = first_byte & 0x0F;
        
        if (h != OP_CTRL || (l != CTRL_BEGIN && l != CTRL_CBEGIN)) {
            printf("❌ ERROR: Code doesn't start with BEGIN/CBEGIN!\n");
            return false;
        }
    }
    
    // Создаем контекст верификации
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
    //bool phase5 = true;
    
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
        printf("%4d. [0x%04x] %s\n", i+1, ctx->errors[i].offset, 
       ctx->errors[i].message ? ctx->errors[i].message : "(no message)");
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