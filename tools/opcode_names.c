#include "opcode_names.h"
#include <string.h>

// Таблица соответствия опкодов и их мнемоник из спецификации
static const struct {
    uint8_t opcode;
    const char* name;
    const char* description;
} opcode_table[] = {
    // Бинарные операции
    {0x01, "BINOP +", "Adds two integers, with wraparound"},
    {0x02, "BINOP -", "Subtracts two integers, with wraparound"},
    {0x03, "BINOP *", "Multiplies two integers, with wraparound"},
    {0x04, "BINOP /", "Divides two integers, with wraparound"},
    {0x05, "BINOP %", "Computes an integer remainder, with wraparound"},
    {0x06, "BINOP <", "Tests if left < right"},
    {0x07, "BINOP <=", "Tests if left <= right"},
    {0x08, "BINOP >", "Tests if left > right"},
    {0x09, "BINOP >=", "Tests if left >= right"},
    {0x0a, "BINOP ==", "Tests if left == right"},
    {0x0b, "BINOP !=", "Tests if left != right"},
    {0x0c, "BINOP &&", "Tests if both are non-zero"},
    {0x0d, "BINOP ||", "Tests if either is non-zero"},

    // Первичные операции
    {0x10, "CONST", "Pushes a constant immediate onto the stack"},
    {0x11, "STRING", "Pushes a string from string table"},
    {0x12, "SEXP", "Constructs an S-expression with n members"},
    {0x13, "STI", "Performs an indirect store to a variable"},
    {0x14, "STA", "Performs an indirect store to a variable or aggregate"},
    {0x15, "JMP", "Sets the instruction counter to immediate"},
    {0x16, "END", "Marks the end of procedure definition"},
    {0x17, "RET", "Returns the top value to caller"},
    {0x18, "DROP", "Removes the top value from the stack"},
    {0x19, "DUP", "Duplicates the top value of the stack"},
    {0x1a, "SWAP", "Swaps the top two values on the stack"},
    {0x1b, "ELEM", "Looks up an element of an aggregate by index"},

    // Загрузки
    {0x20, "LD G", "Pushes the mth global onto the stack"},
    {0x21, "LD L", "Pushes the mth local onto the stack"},
    {0x22, "LD A", "Pushes the mth function argument onto the stack"},
    {0x23, "LD C", "Pushes the mth captured variable onto the stack"},

    // Адресные загрузки
    {0x30, "LDA G", "Pushes a reference to the mth global"},
    {0x31, "LDA L", "Pushes a reference to the mth local"},
    {0x32, "LDA A", "Pushes a reference to the mth function argument"},
    {0x33, "LDA C", "Pushes a reference to the mth captured variable"},

    // Сохранения
    {0x40, "ST G", "Stores a value in the mth global"},
    {0x41, "ST L", "Stores a value in the mth local"},
    {0x42, "ST A", "Stores a value in the mth function argument"},
    {0x43, "ST C", "Stores a value in the mth captured variable"},

    // Управление потоком
    {0x50, "CJMPz", "Jumps if operand is zero"},
    {0x51, "CJMPnz", "Jumps if operand is non-zero"},
    {0x52, "BEGIN", "Marks start of procedure definition"},
    {0x53, "CBEGIN", "Marks start of closure definition"},
    {0x54, "CLOSURE", "Pushes a new closure with captured variables"},
    {0x55, "CALLC", "Calls a closure with n arguments"},
    {0x56, "CALL", "Calls a function with n arguments"},
    {0x57, "TAG", "Tests if operand is S-expression with specific tag"},
    {0x58, "ARRAY", "Tests if operand is an array of n elements"},
    {0x59, "FAIL", "Raises an error, reporting match failure"},
    {0x5a, "LINE", "Marks bytecode as corresponding to source line"},

    // Паттерны
    {0x60, "PATT =str", "Tests if two operands are equal strings"},
    {0x61, "PATT #string", "Tests if operand is a string"},
    {0x62, "PATT #array", "Tests if operand is an array"},
    {0x63, "PATT #sexp", "Tests if operand is an S-expression"},
    {0x64, "PATT #ref", "Tests if operand has boxed representation"},
    {0x65, "PATT #val", "Tests if operand has unboxed representation"},
    {0x66, "PATT #fun", "Tests if operand is a closure"},

    // Встроенные функции
    {0x70, "CALL Lread", "Calls built-in read function"},
    {0x71, "CALL Lwrite", "Calls built-in write function"},
    {0x72, "CALL Llength", "Calls built-in length function"},
    {0x73, "CALL Lstring", "Calls built-in string function"},
    {0x74, "CALL Barray", "Calls built-in .array function"},

    // Конец файла
    {0xff, "EOF", "End of bytecode file"},

    // Терминатор для таблицы
    {0x00, NULL, NULL}
};

const char* get_opcode_human_name(uint8_t opcode) {
    for (int i = 0; opcode_table[i].name != NULL; i++) {
        if (opcode_table[i].opcode == opcode) {
            return opcode_table[i].name;
        }
    }
    return "UNKNOWN";
}
