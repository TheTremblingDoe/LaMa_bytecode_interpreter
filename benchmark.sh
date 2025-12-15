#!/usr/bin/env bash

set -o pipefail

PROJECT_DIR="$(pwd)"
LAMAC="${LAMAC:-$PROJECT_DIR/Lama/src/lamac}"
BUILD_DIR="${BUILD_DIR:-regression/}"
LVM="${LVM:-build/lvm}"

# Функция для измерения времени выполнения
measure_time() {
    local cmd="$1"
    local runs="${2:-5}"
    local total=0
    
    for i in $(seq 1 $runs); do
        # Используем /usr/bin/time для точного измерения
        # -p: POSIX формат (real, user, sys)
        # tail -1: берем последнюю строку (real time)
        local time_output
        time_output=$({ /usr/bin/time -p sh -c "$cmd" 2>&1; } | grep real | awk '{print $2}')
        total=$(echo "$total + $time_output" | bc -l)
    done
    
    # Вычисляем среднее время
    echo "$total / $runs" | bc -l | awk '{printf "%.3f", $1}'
}

# Функция для проверки корректности
check_correctness() {
    local file="$1"
    local interpreter="$2"
    
    case "$interpreter" in
        "lamac-i")
            "$LAMAC" -i "$file" 2>&1
            ;;
        "lamac-s")
            "$LAMAC" -s "$file" 2>&1
            ;;
        "lvm")
            local bc_file="${file%.lama}.bc"
            "$LVM" "$bc_file" 2>&1
            ;;
        "lvm-verify")
            local bc_file="${file%.lama}.bc"
            "$LVM" --verify "$bc_file" 2>&1
            ;;
    esac
}

echo "=== Performance Benchmark: Sort.lama ==="
echo ""

# Компилируем в байткод
BC_FILE="$PROJECT_DIR/performance/Sort.lama"
"$LAMAC" -b $BC_FILE

if [ ! -f "$BC_FILE" ]; then
    echo "Error: Failed to compile Sort.lama"
    exit 1
fi

# Проверяем корректность всех интерпретаторов
echo "Checking correctness of all interpreters..."
echo ""

REF_OUTPUT=$(check_correctness "/tmp/Sort_benchmark.lama" "lamac-i")

for interpreter in "lamac-i" "lamac-s" "lvm" "lvm-verify"; do
    if [ "$interpreter" = "lamac-i" ] || [ "$interpreter" = "lamac-s" ]; then
        OUTPUT=$(check_correctness "$BC_FILE" "$interpreter")
    else
        OUTPUT=$(check_correctness "$BC_FILE" "$interpreter")
    fi
    
    if [ "$OUTPUT" = "$REF_OUTPUT" ]; then
        echo "✓ $interpreter: Output matches reference"
    else
        echo "✗ $interpreter: Output differs from reference"
        echo "  Reference: $REF_OUTPUT"
        echo "  Got: $OUTPUT"
    fi
done

echo ""
echo "=== Performance Measurements (5 runs each) ==="
echo ""

# Замеряем производительность
echo "1. lamac -i (рекурсивный интерпретатор):"
TIME_LAMAC_I=$(measure_time "\"$LAMAC\" -i "$BC_FILE" > /dev/null" 5)
echo "   Average time: ${TIME_LAMAC_I}s"
echo ""

echo "2. lamac -s (внутренний стековый интерпретатор):"
TIME_LAMAC_S=$(measure_time "\"$LAMAC\" -s "$BC_FILE" > /dev/null" 5)
echo "   Average time: ${TIME_LAMAC_S}s"
echo ""

echo "3. lvm (наш внешний итеративный интерпретатор, без верификации):"
# Сначала делаем верификацию отдельно
echo "   Verification only:"
TIME_VERIFY_ONLY=$(measure_time "\"$LVM\" --verify \"$BC_FILE\" > /dev/null" 3)
echo "   Average verification time: ${TIME_VERIFY_ONLY}s"
echo "   Execution without verification:"
TIME_LVM_NO_VERIFY=$(measure_time "\"$LVM\" \"$BC_FILE\" > /dev/null" 5)
echo "   Average execution time: ${TIME_LVM_NO_VERIFY}s"
echo "   Total (verification + execution): $(echo "$TIME_VERIFY_ONLY + $TIME_LVM_NO_VERIFY" | bc -l | awk '{printf "%.3f", $1}')s"
echo ""

echo "4. lvm --verify (с верификацией перед выполнением):"
TIME_LVM_VERIFY=$(measure_time "\"$LVM\" --verify \"$BC_FILE\" > /dev/null" 5)
echo "   Average time: ${TIME_LVM_VERIFY}s"
echo ""

echo "=== Summary ==="
echo "Interpreters sorted by speed (fastest first):"
echo ""

# Создаем таблицу для сравнения
cat > /tmp/benchmark_results.txt << EOF
Interpreter               Time (s)  Relative to lamac-i
-----------------------  ---------  -------------------
lamac -s                 $TIME_LAMAC_S       $(echo "$TIME_LAMAC_I / $TIME_LAMAC_S" | bc -l | awk '{printf "%.2fx", $1}')
lvm (no verify)          $TIME_LVM_NO_VERIFY       $(echo "$TIME_LAMAC_I / $TIME_LVM_NO_VERIFY" | bc -l | awk '{printf "%.2fx", $1}')
lvm --verify            $TIME_LVM_VERIFY       $(echo "$TIME_LAMAC_I / $TIME_LVM_VERIFY" | bc -l | awk '{printf "%.2fx", $1}')
lamac -i                $TIME_LAMAC_I       1.00x
EOF

column -t -s $'\t' /tmp/benchmark_results.txt

echo ""
echo "=== Overhead Analysis ==="
echo "Verification overhead: $(echo "($TIME_VERIFY_ONLY / $TIME_LVM_NO_VERIFY) * 100" | bc -l | awk '{printf "%.1f", $1}')% of execution time"
echo "Total overhead with verification: $(echo "(($TIME_LVM_VERIFY - $TIME_LVM_NO_VERIFY) / $TIME_LVM_NO_VERIFY) * 100" | bc -l | awk '{printf "%.1f", $1}')%"

echo ""
echo "=== Running regression tests with timing ==="
echo ""

# Также можно запустить все regression тесты с замерами времени
for FILE_PATH in "$BUILD_DIR"/*.lama; do
    FILE_NAME="$(basename "$FILE_PATH")"
    STEM="${FILE_NAME%.*}"
    BC_FILE="$BUILD_DIR/$STEM.bc"
    
    echo "Testing $FILE_NAME..."
    
    # Измеряем время выполнения lamac -i
    TIME_LAMAC_I=$(measure_time "\"$LAMAC\" -i \"$FILE_PATH\" > /dev/null" 3)
    
    # Измеряем время выполнения lvm без верификации
    TIME_LVM=$(measure_time "\"$LVM\" \"$BC_FILE\" > /dev/null" 3)
    
    echo "  lamac -i: ${TIME_LAMAC_I}s, lvm: ${TIME_LVM}s, ratio: $(echo "$TIME_LAMAC_I / $TIME_LVM" | bc -l | awk '{printf "%.2f", $1}')x"
done
