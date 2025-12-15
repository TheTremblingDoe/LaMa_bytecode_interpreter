#include "decode.h"
#include <string.h>
#include <stdio.h>

static uint32_t read_u32_le(const uint8_t* p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

void decoder_init(Decoder* d, const uint8_t* bc, uint32_t size) {
    d->bc = bc;
    d->size = size;
    d->pos = 0;
}

void decoder_move_to(Decoder* d, uint32_t addr) {
    if (addr < d->size) {
        d->pos = addr;
    }
}

uint32_t decoder_pos(const Decoder* d) {
    return d->pos;
}

static void emit_result(Decoder* d, void (*listener)(const DecodeResult*, void*), 
                       void* userdata, DecodeResult* result) {
    if (listener) {
        listener(result, userdata);
    }
}

bool decoder_next(Decoder* d, void (*listener)(const DecodeResult*, void*), void* userdata) {
    if (d->pos >= d->size) {
        DecodeResult result = {.type = RESULT_ERROR};
        result.error.addr = d->pos;
        result.error.kind = DECODE_EOF;
        result.error.msg = "encountered EOF while reading opcode";
        emit_result(d, listener, userdata, &result);
        return false;
    }

    uint32_t op_start = d->pos;
    uint8_t opcode = d->bc[d->pos++];
    
    // Emit start
    DecodeResult start_result = {.type = RESULT_START};
    start_result.start.addr = op_start;
    start_result.start.opcode = opcode;
    emit_result(d, listener, userdata, &start_result);
    
    bool success = true;
    
    // Определяем тип и количество immediate
    switch (opcode) {
        // 0 байт immediate
        case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
        case 0x06: case 0x07: case 0x08: case 0x09: case 0x0a:
        case 0x0b: case 0x0c: case 0x0d: // Бинарные операции
        case 0x13: case 0x14: // STI, STA
        case 0x16: case 0x17: case 0x18: case 0x19: case 0x1a: case 0x1b: // END, RET, DROP, DUP, SWAP, ELEM
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: // Паттерны
        case 0x70: case 0x71: case 0x72: case 0x73: // Встроенные функции (кроме 0x74)
        case 0x55: // CALLC
            // Нет immediate
            break;
            
        // 1 immediate (4 байта)
        case 0x10: case 0x11: // CONST, STRING
        case 0x15: // JMP
        case 0x50: case 0x51: // CJMPz, CJMPnz
        case 0x58: // ARRAY
        case 0x5a: // LINE
        case 0x74: // Barray
        // LD, LDA, ST - один immediate (4 байта) согласно спецификации
        case 0x20: case 0x21: case 0x22: case 0x23: // LD
        case 0x30: case 0x31: case 0x32: case 0x33: // LDA
        case 0x40: case 0x41: case 0x42: case 0x43: // ST
            if (d->pos + 4 <= d->size) {
                DecodeResult imm_result = {.type = RESULT_IMM32};
                imm_result.imm32.addr = d->pos;
                imm_result.imm32.imm = read_u32_le(d->bc + d->pos);
                d->pos += 4;
                emit_result(d, listener, userdata, &imm_result);
            } else {
                success = false;
            }
            break;
            
        // 2 immediate (8 байт)
        case 0x12: // SEXP
        case 0x52: case 0x53: // BEGIN, CBEGIN
        case 0x56: case 0x57: // CALL, TAG
        case 0x59: // FAIL
            if (d->pos + 8 <= d->size) {
                for (int i = 0; i < 2; i++) {
                    DecodeResult imm_result = {.type = RESULT_IMM32};
                    imm_result.imm32.addr = d->pos;
                    imm_result.imm32.imm = read_u32_le(d->bc + d->pos);
                    d->pos += 4;
                    emit_result(d, listener, userdata, &imm_result);
                }
            } else {
                success = false;
            }
            break;
            
        // CLOSURE - переменная длина
        case 0x54:
            if (d->pos + 8 <= d->size) {
                // Цель вызова (4 байта)
                DecodeResult target_result = {.type = RESULT_IMM32};
                target_result.imm32.addr = d->pos;
                target_result.imm32.imm = read_u32_le(d->bc + d->pos);
                d->pos += 4;
                emit_result(d, listener, userdata, &target_result);
                
                // Количество захватов (4 байта)
                DecodeResult count_result = {.type = RESULT_IMM32};
                count_result.imm32.addr = d->pos;
                count_result.imm32.imm = read_u32_le(d->bc + d->pos);
                d->pos += 4;
                emit_result(d, listener, userdata, &count_result);
                
                // Читаем захваты (varspec: 1 байт kind + 4 байта index)
                uint32_t capture_count = count_result.imm32.imm;
                for (uint32_t i = 0; i < capture_count && success; i++) {
                    if (d->pos + 5 <= d->size) {
                        DecodeResult var_result = {.type = RESULT_VARSPEC};
                        var_result.varspec.addr = d->pos;
                        var_result.varspec.kind = d->bc[d->pos] & 0xF;
                        d->pos++;
                        var_result.varspec.idx = read_u32_le(d->bc + d->pos);
                        d->pos += 4;
                        emit_result(d, listener, userdata, &var_result);
                    } else {
                        success = false;
                    }
                }
            } else {
                success = false;
            }
            break;
            
        default:
            DecodeResult error_result = {.type = RESULT_ERROR};
            error_result.error.addr = op_start;
            error_result.error.kind = DECODE_ILLEGAL_OP;
            error_result.error.msg = "illegal opcode";
            emit_result(d, listener, userdata, &error_result);
            success = false;
            break;
    }
    
    if (!success) {
        d->pos = d->size; // При ошибке перемещаемся в конец
    }
    
    // Всегда эмитим конец инструкции
    DecodeResult end_result = {.type = RESULT_END};
    end_result.end.addr = d->pos;
    end_result.end.start = op_start;
    emit_result(d, listener, userdata, &end_result);
    
    return success;
}

bool is_jump_opcode(uint8_t opcode) {
    return opcode == 0x15 ||    // JMP
           opcode == 0x50 ||    // CJMPz
           opcode == 0x51;      // CJMPnz
}

bool should_split_after_opcode(uint8_t opcode) {
    return opcode == 0x15 ||    // JMP
           opcode == 0x50 ||    // CJMPz  
           opcode == 0x51 ||    // CJMPnz
           opcode == 0x16 ||    // END
           opcode == 0x17 ||    // RET
           opcode == 0x59;      // FAIL
}

bool is_terminal_opcode(uint8_t opcode) {
    return opcode == 0x15 ||    // JMP
           opcode == 0x16 ||    // END
           opcode == 0x17 ||    // RET
           opcode == 0x59 ||    // FAIL
           opcode == 0xff;      // EOF
}

uint16_t get_parametrized_word(uint16_t instr_word) {
    return instr_word & 0xF000;
}
