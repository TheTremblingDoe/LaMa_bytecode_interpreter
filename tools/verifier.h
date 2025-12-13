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

/* Function frame information */
typedef struct {
    uint32_t address;
    uint32_t params;
    uint32_t locals;
    uint32_t captures;
    uint32_t stack_size;
    bool is_closure;
} FunctionInfo;

/* Verification context */
typedef struct {
    bytefile *bf;
    char *fname;
    
    /* State for control flow analysis */
    int *stack_heights;      /* Map from instruction offset to stack height */
    bool *visited;           /* Which instructions were visited */
    bool *is_jump_target;    /* Which instructions are jump targets */
    bool *is_function_start; /* Which instructions are function starts (BEGIN/CBEGIN) */
    
    /* Function analysis */
    FunctionInfo *functions;
    int function_count;
    int current_function;    /* Index in functions array for current analysis */
    
    /* Verification results */
    VerificationError *errors;
    int error_count;
    int max_errors;
    
    /* Statistics */
    int max_stack_height;
    int total_instructions;
    int code_size;
    
    /* Configuration */
    bool verbose;
} VerifierContext;

/* Public API */
bool verify_bytecode(bytefile *bf, const char *fname);
bool verify_bytecode_verbose(bytefile *bf, const char *fname); /* With detailed output */
void print_verification_errors(VerifierContext *ctx);
void free_verifier_context(VerifierContext *ctx);

/* Verification phases */
bool verify_instruction_encoding(VerifierContext *ctx);
bool verify_control_flow(VerifierContext *ctx);
bool verify_stack_usage(VerifierContext *ctx);
bool verify_variable_references(VerifierContext *ctx);
bool verify_function_calls(VerifierContext *ctx);
bool verify_global_references(VerifierContext *ctx);

/* Helper functions */
int get_instruction_size(unsigned char opcode, unsigned char subop, const char *ip);
int get_stack_effect(unsigned char opcode, unsigned char subop, const char *ip, VerifierContext *ctx);
bool is_control_flow_instruction(unsigned char opcode, unsigned char subop);
bool is_terminator_instruction(unsigned char opcode, unsigned char subop);
bool is_function_start_instruction(unsigned char opcode, unsigned char subop);
const char* get_opcode_name(unsigned char opcode, unsigned char subop);

/* Analysis results */
typedef struct {
    bool valid;
    int max_stack_depth;
    int function_count;
    int error_count;
    const char *summary;
} VerificationResult;

VerificationResult get_verification_summary(VerifierContext *ctx);

#endif /* VERIFIER_H */