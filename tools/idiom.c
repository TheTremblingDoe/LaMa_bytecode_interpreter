#include "idiom.h"
#include "decode.h"
#include "opcode_names.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define HASH_CAPACITY 65536
#define FNV_OFFSET_BASIS 2166136261U
#define FNV_PRIME 16777619U

// Структура для хеш-таблицы (полное определение)
struct HashEntry {
    uint8_t* bytes;
    uint32_t len;
    uint32_t hash;
    uint32_t count;
    struct HashEntry* next;
};

typedef struct {
    struct HashEntry** buckets;
    uint32_t capacity;
    uint32_t size;
} HashTable;

static uint32_t fnv1a_hash(const uint8_t* data, uint32_t len) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (uint32_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

static HashTable* hash_table_create(uint32_t capacity) {
    HashTable* table = malloc(sizeof(HashTable));
    if (!table) return NULL;

    table->buckets = calloc(capacity, sizeof(struct HashEntry*));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    table->capacity = capacity;
    table->size = 0;
    return table;
}

static void hash_table_free(HashTable* table) {
    if (!table) return;

    for (uint32_t i = 0; i < table->capacity; i++) {
        struct HashEntry* entry = table->buckets[i];
        while (entry) {
            struct HashEntry* next = entry->next;
            free(entry->bytes); // Освобождаем память байтов
            free(entry);
            entry = next;
        }
    }
    free(table->buckets);
    free(table);
}

static void hash_table_insert(HashTable* table, uint8_t* bytes, uint32_t len, uint32_t hash) {
    if (!table || !bytes || len == 0) return;

    uint32_t index = hash % table->capacity;
    struct HashEntry* entry = table->buckets[index];
    

    // Поиск существующей записи
    while (entry) {
        if (entry->hash == hash && entry->len == len &&
            memcmp(entry->bytes, bytes, len) == 0) {
            entry->count++;
            free(bytes); // Освобождаем дубликат
            return;
        }
        entry = entry->next;
    }

    // Создание новой записи
    entry = malloc(sizeof(struct HashEntry));
    if (!entry) {
        free(bytes);
        return;
    }

    entry->bytes = bytes;
    entry->len = len;
    entry->hash = hash;
    entry->count = 1;
    entry->next = table->buckets[index];
    table->buckets[index] = entry;
    table->size++;
}

void idiom_list_init(IdiomList* list) {
    if (!list) return;
    list->idioms = NULL;
    list->count = 0;
    list->capacity = 0;
}

void idiom_list_free(IdiomList* list) {
    if (!list) return;

    for (uint32_t i = 0; i < list->count; i++) {
        free((void*)list->idioms[i].bytes);  // Освобождаем выделенную память
    }

    free(list->idioms);
    list->idioms = NULL;
    list->count = 0;
    list->capacity = 0;
}

void idiom_list_add(IdiomList* list, const uint8_t* bytes, uint32_t len, uint32_t count) {
    if (!list || !bytes || len == 0) return;

    if (list->count >= list->capacity) {
        uint32_t new_capacity = list->capacity ? list->capacity * 2 : 16;
        Idiom* new_idioms = realloc(list->idioms, new_capacity * sizeof(Idiom));
        if (!new_idioms) return;

        list->idioms = new_idioms;
        list->capacity = new_capacity;
    }

    // Выделяем память и копируем байты
    uint8_t* bytes_copy = malloc(len);
    if (!bytes_copy) return;
    memcpy(bytes_copy, bytes, len);

    list->idioms[list->count].bytes = bytes_copy;
    list->idioms[list->count].len = len;
    list->idioms[list->count].occurrences = count;
    list->count++;
}

static int compare_idioms(const void* a, const void* b) {
    const Idiom* ia = (const Idiom*)a;
    const Idiom* ib = (const Idiom*)b;

    // Сначала по убыванию частоты
    if (ia->occurrences > ib->occurrences) return -1;
    if (ia->occurrences < ib->occurrences) return 1;

    // При равной частоте - по длине (короткие сначала)
    if (ia->len < ib->len) return -1;
    if (ia->len > ib->len) return 1;

    // При равной длине - лексикографически
    return memcmp(ia->bytes, ib->bytes, ia->len);
}

void idiom_list_sort(IdiomList* list) {
    if (!list || list->count <= 1) return;
    qsort(list->idioms, list->count, sizeof(Idiom), compare_idioms);
}

Reachability find_reachable_instrs(const uint8_t* bytecode, uint32_t size,
                                  const uint32_t* proc_starts, uint32_t proc_count) {
    Reachability result = {0};
    
    if (!bytecode || size == 0) {
        return result;
    }
    
    result.reachable = calloc(size, sizeof(bool));
    result.jump_targets = calloc(size, sizeof(bool));
    result.size = size;
    
    if (!result.reachable || !result.jump_targets) {
        free(result.reachable);
        free(result.jump_targets);
        return (Reachability){0};
    }
    
    // Используем декодер для точного анализа
    Decoder decoder;
    decoder_init(&decoder, bytecode, size);
    
    uint32_t* queue = malloc(size * sizeof(uint32_t));
    if (!queue) {
        free(result.reachable);
        free(result.jump_targets);
        return (Reachability){0};
    }
    
    uint32_t queue_front = 0, queue_back = 0;
    
    // Добавляем все точки входа
    for (uint32_t i = 0; i < proc_count; i++) {
        uint32_t addr = proc_starts[i];
        if (addr < size && !result.reachable[addr]) {
            result.reachable[addr] = true;
            queue[queue_back++] = addr;
        }
    }
    
    // Если нет точек входа, начинаем с 0
    if (queue_back == 0 && size > 0) {
        result.reachable[0] = true;
        queue[queue_back++] = 0;
    }
    
    while (queue_front < queue_back) {
        uint32_t addr = queue[queue_front++];
        
        // Пропускаем если уже обрабатывали инструкцию с этого адреса
        decoder_move_to(&decoder, addr);
        
        // Структура для сбора информации об инструкции
        typedef struct {
            uint32_t start_addr;
            uint8_t opcode;
            uint32_t end_addr;
            uint32_t jump_target;
            bool has_jump_target;
            uint32_t call_target;
            bool has_call_target;
        } InstrInfo;
        
        InstrInfo instr = {0};
        uint32_t imm_count = 0;
        
        void decode_callback(const DecodeResult* result, void* userdata) {
            InstrInfo* info = (InstrInfo*)userdata;
            
            switch (result->type) {
                case RESULT_START:
                    info->start_addr = result->start.addr;
                    info->opcode = result->start.opcode;
                    imm_count = 0;
                    break;
                case RESULT_END:
                    info->end_addr = result->end.addr;
                    break;
                case RESULT_IMM32:
                    imm_count++;
                    // Проверяем различные типы инструкций
                    if (is_jump_opcode(info->opcode) && imm_count == 1) {
                        // Для прыжков: immediate содержит смещение
                        info->jump_target = info->start_addr + 5 + result->imm32.imm;
                        info->has_jump_target = true;
                    }
                    // CALL (0x56) - первое immediate содержит адрес функции
                    else if (info->opcode == 0x56 && imm_count == 1) {
                        info->call_target = result->imm32.imm;
                        info->has_call_target = true;
                    }
                    // CLOSURE (0x54) - первое immediate содержит адрес функции
                    else if (info->opcode == 0x54 && imm_count == 1) {
                        info->call_target = result->imm32.imm;
                        info->has_call_target = true;
                    }
                    // CALLC (0x55) - нет immediate
                    break;
                default:
                    break;
            }
        }
        
        if (!decoder_next(&decoder, decode_callback, &instr)) {
            continue; // Пропускаем невалидные инструкции
        }
        
        // Проверяем границы
        if (instr.end_addr > size) {
            instr.end_addr = size;
        }
        
        // Обрабатываем прыжки
        if (instr.has_jump_target && instr.jump_target < size) {
            result.jump_targets[instr.jump_target] = true;
            if (!result.reachable[instr.jump_target]) {
                result.reachable[instr.jump_target] = true;
                queue[queue_back++] = instr.jump_target;
            }
        }
        
        // Обрабатываем вызовы функций
        if (instr.has_call_target && instr.call_target < size) {
            if (!result.reachable[instr.call_target]) {
                result.reachable[instr.call_target] = true;
                queue[queue_back++] = instr.call_target;
            }
        }
        
        // Добавляем следующую инструкцию (fall-through)
        // НЕ добавляем после терминальных инструкций
        if (instr.end_addr < size && !is_terminal_opcode(instr.opcode)) {
            if (!result.reachable[instr.end_addr]) {
                result.reachable[instr.end_addr] = true;
                queue[queue_back++] = instr.end_addr;
            }
        }
    }
    
    free(queue);
    return result;
}

void reachability_free(Reachability* r) {
    if (!r) return;
    free(r->reachable);
    free(r->jump_targets);
    r->reachable = NULL;
    r->jump_targets = NULL;
    r->size = 0;
}

static void parametrize_instruction(const uint8_t* bytecode, uint32_t start,
                                   uint32_t end, uint8_t* param_buffer,
                                   uint32_t* param_len);

typedef struct {
    uint32_t start_addr;
    uint8_t opcode;
    uint32_t end_addr;
} WalkInstr;

typedef struct {
    HashTable* table;
    const uint8_t* bytecode;
    const bool* jump_targets;
    uint32_t size;
} WalkData;

static void walk_callback(uint32_t start_addr, uint8_t opcode, uint32_t end_addr, void* userdata);

static void parametrize_instruction(const uint8_t* bytecode, uint32_t start,
                                   uint32_t end, uint8_t* param_buffer,
                                   uint32_t* param_len) {
    if (start >= end) {
        *param_len = 0;
        return;
    }
    
    uint8_t opcode = bytecode[start];
    uint32_t pos = 0;
    
    // Копируем опкод
    param_buffer[pos++] = opcode;
    
    // Определяем длину immediate в зависимости от опкода
    uint32_t imm_len = 0;
    
    switch (opcode) {
        // Инструкции без immediate (1 байт)
        case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
        case 0x06: case 0x07: case 0x08: case 0x09: case 0x0a:
        case 0x0b: case 0x0c: case 0x0d: // Бинарные операции
        case 0x13: case 0x14: // STI, STA
        case 0x16: case 0x17: case 0x18: case 0x19: case 0x1a: case 0x1b: // END, RET, DROP, DUP, SWAP, ELEM
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: // Паттерны
        case 0x70: case 0x71: case 0x72: case 0x73: // Встроенные функции (кроме 0x74)
        case 0x55: // CALLC
            *param_len = pos;
            return;
            
        // 4 байта immediate
        case 0x10: case 0x11: // CONST, STRING
        case 0x15: // JMP
        case 0x50: case 0x51: // CJMPz, CJMPnz
        case 0x58: // ARRAY
        case 0x5a: // LINE
        case 0x74: // Barray
        case 0x20: case 0x21: case 0x22: case 0x23: // LD
        case 0x30: case 0x31: case 0x32: case 0x33: // LDA
        case 0x40: case 0x41: case 0x42: case 0x43: // ST
            imm_len = 4;
            break;
            
        // 8 байт immediate
        case 0x12: // SEXP
        case 0x52: case 0x53: // BEGIN, CBEGIN
        case 0x56: case 0x57: // CALL, TAG
        case 0x59: // FAIL
            imm_len = 8;
            break;
            
        // CLOSURE - переменная длина
        case 0x54:
            // Минимальная длина CLOSURE: опкод + 8 байт (target + count)
            // Проверяем, что есть место для чтения count
            if (start + 9 <= end) {
                // Читаем count из оригинального байткода (байты 5-8, little-endian)
                uint32_t capture_count = 0;
                if (start + 9 <= end) {
                    capture_count = *((uint32_t*)(bytecode + start + 5));
                }
                
                // Обнуляем target (4 байта) и count (4 байта)
                for (int i = 0; i < 8; i++) {
                    if (pos < (end - start)) {
                        param_buffer[pos++] = 0;
                    }
                }
                
                // Для captured vars обнуляем kind (1 байт) и index (4 байта) для каждого
                for (uint32_t i = 0; i < capture_count; i++) {
                    // Kind (1 байт)
                    if (pos < (end - start)) param_buffer[pos++] = 0;
                    
                    // Index (4 байта)
                    for (int j = 0; j < 4; j++) {
                        if (pos < (end - start)) param_buffer[pos++] = 0;
                    }
                }
            }
            *param_len = pos;
            return;
            
        default:
            // Для неизвестных опкодов копируем как есть
            for (uint32_t i = 1; i < (end - start) && i < 32; i++) {
                param_buffer[pos++] = bytecode[start + i];
            }
            *param_len = pos;
            return;
    }
    
    // Заполняем immediate нулями для инструкций с фиксированной длиной
    for (uint32_t i = 0; i < imm_len && pos < (end - start); i++) {
        param_buffer[pos++] = 0;
    }
    
    *param_len = pos;
}

static void walk_callback(uint32_t start_addr, uint8_t opcode, uint32_t end_addr, void* userdata) {
    WalkData* data = (WalkData*)userdata;

    if (start_addr >= data->size || end_addr > data->size || end_addr <= start_addr) {
        printf("Invalid boundaries\n");
        return;
    }

    // Параметризуем текущую инструкцию
    uint8_t curr_param[32];
    uint32_t curr_len = 0;
    parametrize_instruction(data->bytecode, start_addr, end_addr, curr_param, &curr_len);

    if (curr_len > 0) {
        uint8_t* curr_bytes = malloc(curr_len);
        if (curr_bytes) {
            memcpy(curr_bytes, curr_param, curr_len);
            uint32_t hash = fnv1a_hash(curr_bytes, curr_len);
            hash_table_insert(data->table, curr_bytes, curr_len, hash);
        }
    }
    
    // Проверяем, можно ли создать пару инструкций
    // Не создаем пары если:
    // 1. Это конец кода
    // 2. Следующий адрес - метка перехода
    // 3. Текущая инструкция терминальная (JMP, END и т.д.)
    if (end_addr < data->size &&
        !data->jump_targets[end_addr] &&
        !should_split_after_opcode(opcode)) {
        
        Decoder decoder;
        decoder_init(&decoder, data->bytecode, data->size);
        decoder_move_to(&decoder, end_addr);
        
        typedef struct {
            uint32_t start_addr;
            uint8_t opcode;
            uint32_t end_addr;
        } NextInstrInfo;
        
        NextInstrInfo next_instr = {0};
        
        void next_callback(const DecodeResult* result, void* userdata) {
            NextInstrInfo* info = (NextInstrInfo*)userdata;
            switch (result->type) {
                case RESULT_START:
                    info->start_addr = result->start.addr;
                    info->opcode = result->start.opcode;
                    break;
                case RESULT_END:
                    info->end_addr = result->end.addr;
                    break;
                default:
                    break;
            }
        }
        
        if (decoder_next(&decoder, next_callback, &next_instr)) {
            // Проверяем что следующая инструкция существует и не является меткой
            if (next_instr.start_addr == end_addr &&
                next_instr.end_addr <= data->size &&
                !data->jump_targets[next_instr.start_addr]) {
                
                // Параметризуем следующую инструкцию
                uint8_t next_param[32];
                uint32_t next_len = 0;
                parametrize_instruction(data->bytecode, next_instr.start_addr,
                                       next_instr.end_addr, next_param, &next_len);
                
                if (curr_len > 0 && next_len > 0) {
                    uint32_t total_len = curr_len + next_len;
                    uint8_t* pair_bytes = malloc(total_len);
                    if (pair_bytes) {
                        memcpy(pair_bytes, curr_param, curr_len);
                        memcpy(pair_bytes + curr_len, next_param, next_len);
                        uint32_t hash = fnv1a_hash(pair_bytes, total_len);
                        hash_table_insert(data->table, pair_bytes, total_len, hash);
                    }
                }
            }
        }
    }
}

// Функция для преобразования параметризованной последовательности в читаемый вид
void decode_parametrized_sequence(const uint8_t* bytes, uint32_t len, char* buffer, size_t buffer_size) {
    if (!bytes || len == 0 || !buffer || buffer_size == 0) {
        buffer[0] = '\0';
        return;
    }

    buffer[0] = '\0';

    Decoder decoder;
    decoder_init(&decoder, bytes, len);
    uint32_t pos = 0;

    while (pos < len) {
        decoder_move_to(&decoder, pos);

        typedef struct {
            uint32_t start_addr;
            uint8_t opcode;
            uint32_t end_addr;
        } InstrInfo;

        InstrInfo instr = {0};

        void decode_callback(const DecodeResult* result, void* userdata) {
            InstrInfo* info = (InstrInfo*)userdata;
            switch (result->type) {
                case RESULT_START:
                    info->start_addr = result->start.addr;
                    info->opcode = result->start.opcode;
                    break;
                case RESULT_END:
                    info->end_addr = result->end.addr;
                    break;
                default:
                    break;
            }
        }

        if (!decoder_next(&decoder, decode_callback, &instr)) {
            break;
        }

        // Добавляем мнемонику в буфер
        const char* opname = get_opcode_human_name(instr.opcode);
        if (buffer[0] != '\0') {
            strncat(buffer, " ", buffer_size - strlen(buffer) - 1);
        }
        strncat(buffer, opname, buffer_size - strlen(buffer) - 1);

        pos = instr.end_addr;
    }
}

static void walk_reachable_instrs(const uint8_t* bytecode, uint32_t size,
                                 const bool* reachable,
                                 void (*callback)(uint32_t, uint8_t, uint32_t, void*),
                                 void* userdata) {
    if (!bytecode || !reachable || !callback) return;
    
    Decoder decoder;
    decoder_init(&decoder, bytecode, size);
    
    for (uint32_t i = 0; i < size; i++) {
        if (!reachable[i]) continue;
        
        decoder_move_to(&decoder, i);
        
        typedef struct {
            uint32_t start_addr;
            uint8_t opcode;
            uint32_t end_addr;
        } WalkInstr;
        
        WalkInstr instr = {0};
        
        void walk_instr_callback(const DecodeResult* result, void* userdata) {
            WalkInstr* info = (WalkInstr*)userdata;
            
            switch (result->type) {
                case RESULT_START:
                    info->start_addr = result->start.addr;
                    info->opcode = result->start.opcode;
                    break;
                case RESULT_END:
                    info->end_addr = result->end.addr;
                    break;
                default:
                    break;
            }
        }
        
        if (!decoder_next(&decoder, walk_instr_callback, &instr)) {
            continue; // Пропускаем невалидные инструкции
        }
        
        // Проверяем границы
        if (instr.end_addr > size) {
            instr.end_addr = size;
        }
        
        // Вызываем callback
        callback(instr.start_addr, instr.opcode, instr.end_addr, userdata);
        
        // Пропускаем обработанные байты
        if (instr.end_addr > i) {
            i = instr.end_addr - 1; // -1 потому что цикл увеличит i
        } else {
            i++; // Защита от бесконечного цикла
        }
    }
}

IdiomList analyze_idioms(const uint8_t* bytecode, uint32_t size,
                        const uint32_t* proc_starts, uint32_t proc_count) {
    IdiomList result = {0};
    idiom_list_init(&result);

    if (!bytecode || size == 0 || !proc_starts || proc_count == 0) {
        return result;
    }

    // 1. Находим достижимые инструкции
    Reachability reach = find_reachable_instrs(bytecode, size, proc_starts, proc_count);
    if (!reach.reachable) {
        return result;
    }

    // 2. Создаем хеш-таблицу для подсчета
    HashTable* table = hash_table_create(HASH_CAPACITY);
    if (!table) {
        reachability_free(&reach);
        return result;
    }

    // 3. Обходим достижимые инструкции
    typedef struct {
        HashTable* table;
        const uint8_t* bytecode;
        const bool* jump_targets;
        uint32_t size;
    } WalkData;

    WalkData walk_data = {table, bytecode, reach.jump_targets, size};

    walk_reachable_instrs(bytecode, size, reach.reachable, walk_callback, &walk_data);

    // 4. Собираем результаты из хеш-таблицы
    for (uint32_t i = 0; i < table->capacity; i++) {
        struct HashEntry* entry = table->buckets[i];
        while (entry) {
            if (entry->count > 0) {
                idiom_list_add(&result, entry->bytes, entry->len, entry->count);
            }
            entry = entry->next;
        }
    }

    // 5. Сортируем
    idiom_list_sort(&result);

    // 6. Очищаем
    hash_table_free(table);
    reachability_free(&reach);

    return result;
}

IdiomList find_idioms(const uint8_t* bytecode, uint32_t size,
                     const uint32_t* proc_starts, uint32_t proc_count) {
    return analyze_idioms(bytecode, size, proc_starts, proc_count);
}

void free_idiom_list(IdiomList* list) {
    idiom_list_free(list);
}
