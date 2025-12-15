#!/usr/bin/env bash

set -o pipefail

PROJECT_DIR="$(pwd)"
LAMAC="${LAMAC:-$PROJECT_DIR/Lama/src/lamac}"
BUILD_DIR="${BUILD_DIR:-regression/}"
LVM="${LVM:-build/lvm}"

PASSED=0
FAILED=0

declare -a FAILED_NAMES
declare -a COMPILE_FAILED_NAMES

if [ -e "$LAMAC" ]
then
    echo "lamac exists"
else
    echo "building lamac from sources"
    make -C "$PROJECT_DIR/Lama/runtime"
    make -C "$PROJECT_DIR/Lama/src"
fi

for FILE_PATH in "$BUILD_DIR"/*.lama; do
	FILE_NAME="$(basename "$FILE_PATH")"
	STEM="${FILE_NAME%.*}"
	BC_FILE="$BUILD_DIR/$STEM.bc"

	echo -e "\033[1mRunning $FILE_PATH...\033[m" >&2

	# compile.
	if ! (
		set -o pipefail
		cd "$BUILD_DIR/"
		"$LAMAC" -b "$PROJECT_DIR/$FILE_PATH"

	); then
		echo -e "\033[91mcompilation failed!\033[m"
		COMPILE_FAILED_NAMES+=("$FILE_NAME")
		continue
	fi

	INPUT_FILE="$BUILD_DIR/$STEM.input"

	# run the reference interpreter.
	EXPECTED_OUTPUT="$("$LAMAC" -i "$FILE_PATH" < "$INPUT_FILE" 2>&1)"

	ACTUAL_OUTPUT="$("$LVM" "$BC_FILE" < "$INPUT_FILE" 2>&1 | tee /dev/tty)"

	if ! [ "$EXPECTED_OUTPUT" = "$ACTUAL_OUTPUT" ]; then
		echo -e "\033[91mtest failed!\033[m expected output:"
		echo "$EXPECTED_OUTPUT"
		FAILED=$(($FAILED + 1))
		FAILED_NAMES+=("$FILE_NAME")
	else
		echo -e "\033[92mtest passed\033[m"
		PASSED=$(($PASSED + 1))
	fi
done

echo -e "\033[1mresult: $PASSED passed, $FAILED failed\033[m"

if [[ ${#COMPILE_FAILED_NAMES[@]} -ne 0 ]]; then
	echo -e "\033[91mcompilation failed for:\033[m ${COMPILE_FAILED_NAMES[@]}"
fi

if [[ ${#FAILED_NAMES[@]} -ne 0 ]]; then
	echo -e "\033[91mfailed tests:\033[m ${FAILED_NAMES[@]}"
fi
