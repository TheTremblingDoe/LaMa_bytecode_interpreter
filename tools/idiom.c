#include "idiom.h"
#include "decode.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define HASH_CAPACITY 65536
#define FNV_OFFSET_BASIS 2166136261U
#define FNV_PRIME 16777619U

// Структура для хеш-таблицы (полное определение)
struct HashEntry {
    const uint8_t* bytes;
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
            free(entry);
            entry = next;
        }
    }
    free(table->buckets);
    free(table);
}

static void hash_table_insert(HashTable* table, const uint8_t* bytes, uint32_t len, uint32_t hash) {
    if (!table || !bytes || len == 0) return;

    uint32_t index = hash % table->capacity;
    struct HashEntry* entry = table->buckets[index];

    // Поиск существующей записи
    while (entry) {
        if (entry->hash == hash && entry->len == len &&
            memcmp(entry->bytes, bytes, len) == 0) {
            entry->count++;
            return;
        }
        entry = entry->next;
    }

    // Создание новой записи
    entry = malloc(sizeof(struct HashEntry));
    if (!entry) return;

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

    list->idioms[list->count].bytes = bytes;
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

    // При равной частоте - лексикографически
    uint32_t min_len = ia->len < ib->len ? ia->len : ib->len;
    int cmp = memcmp(ia->bytes, ib->bytes, min_len);
    if (cmp != 0) return cmp;

    // Более короткая последовательность идет первой
    return (int)ia->len - (int)ib->len;
}

void idiom_list_sort(IdiomList* list) {
    if (!list || list->count <= 1) return;
    qsort(list->idioms, list->count, sizeof(Idiom), compare_idioms);
}

Reachability find_reachable_instrs(const uint8_t* bytecode, uint32_t size,
                                  const uint32_t* proc_starts, uint32_t proc_count) {
    Reachability result = {0};

    if (!bytecode || size == 0 || !proc_starts || proc_count == 0) {
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
                case RESULT_IMM32:
                    if (is_jump_opcode(info->opcode)) {
                        info->jump_target = result->imm32.imm;
                        info->has_jump_target = true;
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

        // Если не терминальная инструкция, добавляем следующую
        if (!is_terminal_opcode(instr.opcode) && instr.end_addr < size) {
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

typedef struct {
    uint32_t start_addr;
    uint8_t opcode;
    uint32_t end_addr;
} WalkInstr;

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

    void walk_callback(uint32_t start_addr, uint8_t opcode, uint32_t end_addr, void* userdata) {
        WalkData* data = (WalkData*)userdata;

        if (start_addr >= data->size || end_addr > data->size || end_addr <= start_addr) {
            return;
        }

        // Одиночная инструкция
        uint32_t len1 = end_addr - start_addr;
        if (len1 > 0) {
            uint32_t hash1 = fnv1a_hash(data->bytecode + start_addr, len1);
            hash_table_insert(data->table, data->bytecode + start_addr, len1, hash1);
        }

        // Проверяем, можно ли добавить пару инструкций
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
                if (next_instr.end_addr <= data->size) {
                    uint32_t len2 = next_instr.end_addr - start_addr;
                    if (len2 > 0) {
                        uint32_t hash2 = fnv1a_hash(data->bytecode + start_addr, len2);
                        hash_table_insert(data->table, data->bytecode + start_addr, len2, hash2);
                    }
                }
            }
        }
    }

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
