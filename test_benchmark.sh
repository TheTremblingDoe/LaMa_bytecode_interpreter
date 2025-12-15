#!/usr/bin/env bash

set -o pipefail

PROJECT_DIR="$(pwd)"
LAMAC="${LAMAC:-$PROJECT_DIR/Lama/src/lamac}"
LVM="${LVM:-build/lvm}"

# Конкретные файлы для теста
TEST_LAMA="$PROJECT_DIR/performance/Sort.lama"
INPUT_FILE="$PROJECT_DIR/regression/test802.input"

echo "=== Performance Test: Sort.lama ==="
echo ""

# Проверяем наличие lamac
if [ -e "$LAMAC" ]; then
    echo "lamac exists at: $LAMAC"
else
    echo "building lamac from sources..."
    make -C "$PROJECT_DIR/Lama/runtime"
    make -C "$PROJECT_DIR/Lama/src"
    
    if [ ! -e "$LAMAC" ]; then
        echo -e "\033[91mERROR: Failed to build lamac\033[m"
        exit 1
    fi
fi

# Проверяем наличие входного файла
if [ ! -f "$INPUT_FILE" ]; then
    echo -e "\033[91mERROR: Input file not found: $INPUT_FILE\033[m"
    exit 1
fi

# Проверяем наличие тестового файла
if [ ! -f "$TEST_LAMA" ]; then
    echo -e "\033[91mERROR: Test file not found: $TEST_LAMA\033[m"
    exit 1
fi

echo -e "\033[1mRunning $TEST_LAMA...\033[m" >&2
echo "Using input file: $INPUT_FILE"

# Запускаем reference interpreter (lamac -i)
echo ""
echo -e "\033[1mReference interpreter (lamac -i):\033[m"
EXPECTED_OUTPUT="$("$LAMAC" -i "$TEST_LAMA" < "$INPUT_FILE" 2>&1 | tee /dev/tty)"
REFERENCE_EXIT_CODE=$?

echo ""
echo -e "\033[1mOur interpreter (lvm):\033[m"

# Сначала компилируем в байткод
BC_FILE="${TEST_LAMA%.lama}.bc"
echo "Compiling to bytecode: $BC_FILE"

if ! (
	set -o pipefail
	cd "$BUILD_DIR/"
	"$LAMAC" -b "$TEST_LAMA"
); then
    echo -e "\033[91mcompilation failed!\033[m"
    exit 1
fi

# Проверяем, что байткод создан
if [ ! -f "$BC_FILE" ]; then
    echo -e "\033[91mERROR: Bytecode file not created: $BC_FILE\033[m"
    exit 1
fi

# Запускаем наш интерпретатор
ACTUAL_OUTPUT="$("$LVM" "$BC_FILE" < "$INPUT_FILE" 2>&1 | tee /dev/tty)"
LVM_EXIT_CODE=$?

echo ""
echo -e "\033[1m=== Test Results ===\033[m"

# Сравниваем выходные данные
if [ "$REFERENCE_EXIT_CODE" -ne "$LVM_EXIT_CODE" ]; then
    echo -e "\033[91mExit codes differ!\033[m"
    echo "  lamac -i exit code: $REFERENCE_EXIT_CODE"
    echo "  lvm exit code: $LVM_EXIT_CODE"
    exit 1
fi

if ! [ "$EXPECTED_OUTPUT" = "$ACTUAL_OUTPUT" ]; then
    echo -e "\033[91mOutput differs!\033[m"
    echo ""
    echo -e "\033[93mExpected output (lamac -i):\033[m"
    echo "$EXPECTED_OUTPUT"
    echo ""
    echo -e "\033[93mActual output (lvm):\033[m"
    echo "$ACTUAL_OUTPUT"
    exit 1
else
    echo -e "\033[92mTest passed! Outputs match.\033[m"
    exit 0
fi
