#ifndef IDIOM_H
#define IDIOM_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

// Идиома - последовательность байткода
typedef struct {
    const uint8_t* bytes;
    uint32_t len;
    uint32_t occurrences;
} Idiom;

// Список идиом
typedef struct {
    Idiom* idioms;
    uint32_t count;
    uint32_t capacity;
} IdiomList;

// Результат анализа достижимости
typedef struct {
    bool* reachable;
    bool* jump_targets;
    uint32_t size;
} Reachability;

// Структура для хеш-таблицы (предварительное объявление)
typedef struct HashEntry HashEntry;

// Инициализация и очистка списка идиом
void idiom_list_init(IdiomList* list);
void idiom_list_free(IdiomList* list);
void idiom_list_add(IdiomList* list, const uint8_t* bytes, uint32_t len, uint32_t count);  // Исправлено: добавлен count

// Анализ достижимости
Reachability find_reachable_instrs(const uint8_t* bytecode, uint32_t size,
                                  const uint32_t* proc_starts, uint32_t proc_count);
void reachability_free(Reachability* r);

// Основная функция анализа идиом
IdiomList analyze_idioms(const uint8_t* bytecode, uint32_t size,
                        const uint32_t* proc_starts, uint32_t proc_count);

// Альтернативный интерфейс (совместимость)
IdiomList find_idioms(const uint8_t* bytecode, uint32_t size,
                     const uint32_t* proc_starts, uint32_t proc_count);

// Освобождение результата
void free_idiom_list(IdiomList* list);

#endif
