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
    
    switch (opcode) {
        case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
        case 0x06: case 0x07: case 0x08: case 0x09: case 0x0a:
        case 0x0b: case 0x0c: case 0x0d: // Бинарные операции
        case 0x13: case 0x14: // STI, STA
        case 0x16: case 0x17: // END, RET
        case 0x18: case 0x19: case 0x1a: case 0x1b: // DROP, DUP, SWAP, ELEM
        case 0x5a: // LINE
        case 0xff: // EOF
            break;
            
        case 0x10: // CONST
        case 0x11: // STRING
        case 0x15: // JMP
        case 0x50: // CJMPz
        case 0x51: // CJMPnz
        case 0x55: // CALLC
        case 0x58: // ARRAY
        case 0x59: // FAIL (только первый immediate)
            if (d->pos + 4 <= d->size) {
                DecodeResult imm_result = {.type = RESULT_IMM32};
                imm_result.imm32.addr = d->pos;
                imm_result.imm32.imm = read_u32_le(d->bc + d->pos);
                d->pos += 4;
                emit_result(d, listener, userdata, &imm_result);
                
                if (opcode == 0x59) { // FAIL имеет два immediate
                    if (d->pos + 4 <= d->size) {
                        DecodeResult imm2_result = {.type = RESULT_IMM32};
                        imm2_result.imm32.addr = d->pos;
                        imm2_result.imm32.imm = read_u32_le(d->bc + d->pos);
                        d->pos += 4;
                        emit_result(d, listener, userdata, &imm2_result);
                    } else {
                        success = false;
                    }
                }
            } else {
                success = false;
            }
            break;
            
        case 0x12: // SEXP
        case 0x56: // CALL
        case 0x57: // TAG
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
            
        case 0x52: // BEGIN
        case 0x53: // CBEGIN
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
            
        case 0x54: // CLOSURE
            if (d->pos + 8 <= d->size) {
                // Цель вызова
                DecodeResult target_result = {.type = RESULT_IMM32};
                target_result.imm32.addr = d->pos;
                target_result.imm32.imm = read_u32_le(d->bc + d->pos);
                d->pos += 4;
                emit_result(d, listener, userdata, &target_result);
                
                // Количество захватов
                DecodeResult count_result = {.type = RESULT_IMM32};
                count_result.imm32.addr = d->pos;
                count_result.imm32.imm = read_u32_le(d->bc + d->pos);
                d->pos += 4;
                emit_result(d, listener, userdata, &count_result);
                
                // Читаем захваты
                uint32_t capture_count = count_result.imm32.imm;
                for (uint32_t i = 0; i < capture_count && success; i++) {
                    if (d->pos + 5 <= d->size) {
                        DecodeResult var_result = {.type = RESULT_VARSPEC};
                        var_result.varspec.addr = d->pos;
                        var_result.varspec.kind = d->bc[d->pos] & 0xF; // Игнорируем старшие 4 бита
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
            
        // Загрузки и сохранения с varspec
        case 0x20: case 0x21: case 0x22: case 0x23: // LD
        case 0x30: case 0x31: case 0x32: case 0x33: // LDA
        case 0x40: case 0x41: case 0x42: case 0x43: // ST
            if (d->pos + 5 <= d->size) {
                DecodeResult var_result = {.type = RESULT_VARSPEC};
                var_result.varspec.addr = d->pos;
                var_result.varspec.kind = d->bc[d->pos] & 0xF; // Для этих инструкций игнорируем старшие 4 бита
                d->pos++;
                var_result.varspec.idx = read_u32_le(d->bc + d->pos);
                d->pos += 4;
                emit_result(d, listener, userdata, &var_result);
            } else {
                success = false;
            }
            break;
            
        // Паттерны
        case 0x60: case 0x61: case 0x62: case 0x63:
        case 0x64: case 0x65: case 0x66:
        // Встроенные функции
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
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
    return opcode == 0x15 || opcode == 0x50 || opcode == 0x51;
}

bool is_terminal_opcode(uint8_t opcode) {
    return opcode == 0x15 || opcode == 0x16 || opcode == 0x17 || opcode == 0x59;
}

bool should_split_after_opcode(uint8_t opcode) {
    return opcode == 0x15 || opcode == 0x56 || opcode == 0x55 || 
           opcode == 0x17 || opcode == 0x16 || opcode == 0x59;
}
