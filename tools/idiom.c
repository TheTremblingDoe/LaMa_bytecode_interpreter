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

    entry->bytes = bytes; // Забираем владение памятью
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

    // Используем кольцевой буфер для BFS
    uint32_t* queue = malloc(size * sizeof(uint32_t));
    if (!queue) {
        free(result.reachable);
        free(result.jump_targets);
        return (Reachability){0};
    }

    uint32_t queue_front = 0, queue_back = 0;

    // Инициализируем точками входа
    for (uint32_t i = 0; i < proc_count; i++) {
        uint32_t addr = proc_starts[i];
        if (addr < size && !result.reachable[addr]) {
            result.reachable[addr] = true;
            queue[queue_back] = addr;
            queue_back = (queue_back + 1) % size;
        }
    }

    Decoder decoder;
    decoder_init(&decoder, bytecode, size);

    while (queue_front != queue_back) {
        uint32_t addr = queue[queue_front];
        queue_front = (queue_front + 1) % size;

        if (addr >= size) continue;

        decoder_move_to(&decoder, addr);

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

        void decode_callback(const DecodeResult* result, void* userdata) {
            InstrInfo* info = (InstrInfo*)userdata;
            static uint32_t imm_count = 0;  // Счетчик immediate значений

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
                    // Для инструкций перехода (JMP, CJMPz, CJMPnz)
                    if (is_jump_opcode(info->opcode)) {
                        info->jump_target = result->imm32.imm;
                        info->has_jump_target = true;
                    }
                    // Для инструкции CALL (0x56) первое immediate - адрес функции
                    else if (info->opcode == 0x56 && imm_count == 1) {
                        info->call_target = result->imm32.imm;
                        info->has_call_target = true;
                    }
                    // Для инструкции CLOSURE (0x54) первое immediate - адрес функции
                    else if (info->opcode == 0x54 && imm_count == 1) {
                        info->call_target = result->imm32.imm;
                        info->has_call_target = true;
                    }
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

        // Если это прыжок, добавляем цель в очередь
        if (instr.has_jump_target && instr.jump_target < size) {
            result.jump_targets[instr.jump_target] = true;
            if (!result.reachable[instr.jump_target]) {
                result.reachable[instr.jump_target] = true;
                queue[queue_back] = instr.jump_target;
                queue_back = (queue_back + 1) % size;
            }
        }

        // Если это вызов функции, добавляем адрес функции в очередь
        if (instr.has_call_target && instr.call_target < size) {
            if (!result.reachable[instr.call_target]) {
                result.reachable[instr.call_target] = true;
                queue[queue_back] = instr.call_target;
                queue_back = (queue_back + 1) % size;
            }
        }

        // Добавляем следующую инструкцию, даже если текущая терминальная
        // Это нужно для обработки последовательных функций
        if (instr.end_addr < size) {
            if (!result.reachable[instr.end_addr]) {
                result.reachable[instr.end_addr] = true;
                queue[queue_back] = instr.end_addr;
                queue_back = (queue_back + 1) % size;
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

    // В зависимости от опкода определяем длину immediate
    uint32_t imm_len = 0;

    switch (opcode) {
        // Инструкции без immediate (1 байт)
        case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
        case 0x06: case 0x07: case 0x08: case 0x09: case 0x0a:
        case 0x0b: case 0x0c: case 0x0d:
        case 0x13: case 0x14: case 0x16: case 0x17: case 0x18:
        case 0x19: case 0x1a: case 0x1b:
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64:
        case 0x65: case 0x66:
        case 0x70: case 0x71: case 0x72: case 0x73:
            imm_len = 0;
            break;

        // Инструкции с 4-байтным immediate
        case 0x10: case 0x11: case 0x15:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x50: case 0x51: case 0x58: case 0x5a:
        case 0x74:
            imm_len = 4;
            break;

        // Инструкции с 8-байтным immediate (два 4-байтных)
        case 0x12: case 0x52: case 0x53: case 0x56: case 0x57:
        case 0x59:
            imm_len = 8;
            break;

        // CLOSURE - переменная длина, обрабатываем как есть
        case 0x54:
            // Для CLOSURE сохраняем структуру, но обнуляем captured variables
            // Длина CLOSURE: опкод + 8 байт (target + count) + 5 * n байт для captured vars
            // Пока упростим: обнуляем все после опкода
            imm_len = end - start - 1;
            break;

        case 0x55: // CALLC
            imm_len = 0;
            break;

        default:
            // Для неизвестных опкодов считаем, что нет immediate
            imm_len = 0;
            break;
    }

    // Заполняем immediate нулями
    for (uint32_t i = 0; i < imm_len; i++) {
        param_buffer[pos++] = 0;
    }

    *param_len = pos;
}

static void walk_callback(uint32_t start_addr, uint8_t opcode, uint32_t end_addr, void* userdata) {
    WalkData* data = (WalkData*)userdata;

    // DEBUG walk_callback
    printf("Debug: walk_callback: addr=0x%x, opcode=0x%02x, end=0x%x\n",
           start_addr, opcode, end_addr);

    if (start_addr >= data->size || end_addr > data->size || end_addr <= start_addr) {
        printf("Debug: Invalid instruction boundaries\n");
        return;
    }

    // Параметризуем текущую инструкцию
    uint8_t curr_param[32];
    uint32_t curr_len = 0;
    parametrize_instruction(data->bytecode, start_addr, end_addr, curr_param, &curr_len);
    printf("Debug: Parametrized instruction: ");
    for (uint32_t i = 0; i < curr_len; i++) {
        printf("%02x ", curr_param[i]);
    }
    printf("\n");

    if (curr_len > 0) {
        // Копируем в динамическую память
        uint8_t* curr_bytes = malloc(curr_len);
        if (curr_bytes) {
            memcpy(curr_bytes, curr_param, curr_len);
            uint32_t hash1 = fnv1a_hash(curr_bytes, curr_len);
            hash_table_insert(data->table, curr_bytes, curr_len, hash1);
        }
    }

    // Проверяем, можно ли добавить пару инструкций
    // НЕ разрываем на метках переходов
    if (end_addr < data->size &&
        !data->jump_targets[end_addr] &&
        !should_split_after_opcode(opcode)) {

        Decoder decoder;
        decoder_init(&decoder, data->bytecode, data->size);
        decoder_move_to(&decoder, end_addr);

        WalkInstr next_instr = {0};

        void next_callback(const DecodeResult* result, void* userdata) {
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

        if (decoder_next(&decoder, next_callback, &next_instr)) {
            if (next_instr.start_addr < data->size &&
                next_instr.end_addr <= data->size &&
                next_instr.start_addr == end_addr) {

                // Параметризуем следующую инструкцию
                uint8_t next_param[32];
                uint32_t next_len = 0;
                parametrize_instruction(data->bytecode, next_instr.start_addr,
                                       next_instr.end_addr, next_param, &next_len);

                if (curr_len > 0 && next_len > 0) {
                    // Создаем пару инструкций
                    uint32_t total_len = curr_len + next_len;
                    uint8_t* pair_bytes = malloc(total_len);
                    if (pair_bytes) {
                        memcpy(pair_bytes, curr_param, curr_len);
                        memcpy(pair_bytes + curr_len, next_param, next_len);

                        uint32_t hash2 = fnv1a_hash(pair_bytes, total_len);
                        hash_table_insert(data->table, pair_bytes, total_len, hash2);
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

        WalkInstr instr = {0};

        void walk_callback(const DecodeResult* result, void* userdata) {
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

        if (!decoder_next(&decoder, walk_callback, &instr)) {
            continue; // Пропускаем невалидные инструкции
        }

        // Проверяем границы
        if (instr.end_addr > size) {
            instr.end_addr = size;
        }

        callback(instr.start_addr, instr.opcode, instr.end_addr, userdata);

        // Переходим к следующей инструкции
        if (instr.end_addr > i) {
            i = instr.end_addr - 1;
        } else {
            break; // Защита от бесконечного цикла
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
