#ifndef DECODE_H
#define DECODE_H

#include <stdint.h>
#include <stdbool.h>

// Типы ошибок декодирования
typedef enum {
    DECODE_OK = 0,
    DECODE_EOF,
    DECODE_ILLEGAL_VARKIND,
    DECODE_ILLEGAL_OP
} DecodeError;

uint16_t get_parametrized_word(uint16_t instr_word);

// Результат декодирования (вариантный тип)
typedef struct {
    enum { RESULT_START, RESULT_END, RESULT_IMM32, RESULT_VARSPEC, RESULT_ERROR } type;
    union {
        struct {
            uint32_t addr;
            uint8_t opcode;
        } start;
        struct {
            uint32_t addr;
            uint32_t start;
        } end;
        struct {
            uint32_t addr;
            uint32_t imm;
        } imm32;
        struct {
            uint32_t addr;
            uint8_t kind;  // 0=Global, 1=Local, 2=Param, 3=Capture
            uint32_t idx;
        } varspec;
        struct {
            uint32_t addr;
            DecodeError kind;
            const char* msg;
        } error;
    };
} DecodeResult;

// Декодер байткода
typedef struct {
    const uint8_t* bc;
    uint32_t size;
    uint32_t pos;
} Decoder;

void decoder_init(Decoder* d, const uint8_t* bc, uint32_t size);
void decoder_move_to(Decoder* d, uint32_t addr);
uint32_t decoder_pos(const Decoder* d);
bool decoder_next(Decoder* d, void (*listener)(const DecodeResult*, void*), void* userdata);

// Вспомогательные функции для проверки инструкций
bool is_jump_opcode(uint8_t opcode);
bool is_terminal_opcode(uint8_t opcode);
bool should_split_after_opcode(uint8_t opcode);

#endif
