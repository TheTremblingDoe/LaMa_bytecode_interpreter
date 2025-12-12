#ifndef VERIFIER_H
#define VERIFIER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include "bytecode_defs.h"  // Включаем общие определения

/* Теперь bytefile - полный тип */

/* Error reporting */
typedef struct {
    int offset;
    int line;
    int column;
    char *message;
} VerificationError;

/* Verification context */
typedef struct {
    bytefile *bf;  // Теперь можно использовать bytefile напрямую
    char *fname;
    
    /* State for control flow analysis */
    int *stack_heights;
    bool *visited;
    bool *is_jump_target;
    
    /* Verification results */
    VerificationError *errors;
    int error_count;
    int max_errors;
    
    /* Statistics */
    int max_stack_height;
    int total_instructions;
    int code_size;
} VerifierContext;

/* Public API */
bool verify_bytecode(bytefile *bf, const char *fname);  // Измените сигнатуру
void print_verification_errors(VerifierContext *ctx);
void free_verifier_context(VerifierContext *ctx);

/* Helper functions */
int get_instruction_size(unsigned char opcode, unsigned char subop, const char *ip);
int get_stack_effect(unsigned char opcode, unsigned char subop, const char *ip);
bool is_control_flow_instruction(unsigned char opcode, unsigned char subop);
bool is_terminator_instruction(unsigned char opcode, unsigned char subop);

#endif /* VERIFIER_H */