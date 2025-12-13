#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>

#include "tools/idiom.h"
#include "tools/decode.h"
#include "tools/verifier.h"
#include "runtime/runtime.h"
#include "tools/bytecode_defs.h"

#define swap(x,y) do {    \
   typeof(x) _x = x;      \
   typeof(y) _y = y;      \
   x = _y;                \
   y = _x;                \
 } while(0)

//#define DEBUG

void *__start_custom_data;
void *__stop_custom_data;

char *code_stop_ptr;

extern size_t __gc_stack_top, __gc_stack_bottom;
//extern void __gc_root_scan_stack();

/* Forward declarations */
static void vfailure(char *s, va_list args);
void failure(char *s, ...);

/* The unpacked representation of bytecode file */
//typedef struct {
//    char *string_ptr;              /* A pointer to the beginning of the string table */
//    int  *public_ptr;              /* A pointer to the beginning of publics table    */
//    char *code_ptr;                /* A pointer to the bytecode itself               */
//    int  *global_ptr;              /* A pointer to the global area                   */
//    int   stringtab_size;          /* The size (in bytes) of the string table        */
//    int   global_area_size;        /* The size (in words) of global area             */
//    int   public_symbols_number;   /* The number of public symbols                   */
//    char  buffer[0];
//} bytefile;

/* Gets a string from a string table by an index */
char* get_string (bytefile *f, int pos) {
    if (pos < 0 || pos >= f->stringtab_size) {
        failure("String index out of bounds: %d (stringtab_size: %d)\n", pos, f->stringtab_size);
    }
    return &f->string_ptr[pos];
}

/* Gets a name for a public symbol */
char* get_public_name (bytefile *f, int i) {
    if (i < 0 || i >= f->public_symbols_number) {
        failure("Public symbol index out of bounds: %d (public_symbols_number: %d)\n",
                i, f->public_symbols_number);
    }
    return get_string (f, f->public_ptr[i*2]);
}

/* Gets an offset for a public symbol */
int get_public_offset (bytefile *f, int i) {
    if (i < 0 || i >= f->public_symbols_number) {
        failure("Public symbol index out of bounds: %d (public_symbols_number: %d)\n",
                i, f->public_symbols_number);
    }
    return f->public_ptr[i*2+1];
}

static void vfailure (char *s, va_list args) {
    fprintf(stderr, "*** FAILURE: ");
    vfprintf(stderr, s, args);
    exit(255);
}

void failure (char *s, ...) {
    va_list args;
    va_start(args, s);
    vfailure(s, args);
    va_end(args);
}

/* Reads a binary bytecode file by name and unpacks it */
bytefile* read_file (char *fname) {
    FILE *f = fopen (fname, "rb");
    long size;
    bytefile *file;

    if (f == 0) {
        failure ("%s\n", strerror (errno));
    }

    if (fseek (f, 0, SEEK_END) == -1) {
        failure ("%s\n", strerror (errno));
    }

    size = ftell (f);

    if (size == -1) {
        failure ("%s\n", strerror (errno));
    }

    // Проверка максимального размера файла
    if (size > INT_MAX - (long)sizeof(int)*4) {
        failure("File too large: %ld bytes (max: %ld)\n", size, INT_MAX - (long)sizeof(int)*4);
    }

    rewind (f);

    file = (bytefile*) malloc (sizeof(int)*4 + size);
    if (file == 0) {
        failure ("*** FAILURE: unable to allocate memory.\n");
    }

    if (size != fread (&file->stringtab_size, 1, size, f)) {
        free(file);
        failure ("%s\n", strerror (errno));
    }

    fclose (f);

    // Проверка корректности полей заголовка
    if (file->stringtab_size < 0 || file->global_area_size < 0 || file->public_symbols_number < 0) {
        free(file);
        failure("Invalid header fields: negative values\n");
    }

    // Проверка, что указатели в пределах выделенной памяти
    size_t buffer_size = sizeof(int)*4 + size;
    char *buffer_end = (char*)file + buffer_size;

    // Проверка public_ptr
    size_t public_table_size = file->public_symbols_number * 2 * sizeof(int);
    if ((char*)file->buffer + public_table_size > buffer_end) {
        free(file);
        failure("Public symbols table exceeds file bounds\n");
    }

    file->public_ptr = (int*) file->buffer;
    file->string_ptr = &file->buffer[public_table_size];

    // Проверка string_ptr
    if (file->string_ptr + file->stringtab_size > buffer_end) {
        free(file);
        failure("String table exceeds file bounds\n");
    }

    file->code_ptr = &file->string_ptr[file->stringtab_size];

    // Проверка code_ptr
    if (file->code_ptr > buffer_end) {
        free(file);
        failure("Bytecode exceeds file bounds\n");
    }

    /* ВАЖНО: сохраняем оригинальную логику вычисления code_stop_ptr */
    code_stop_ptr = file->buffer + (size - 3 * sizeof(int)) - 1;

    // Дополнительная проверка code_stop_ptr
    if (code_stop_ptr < file->buffer || code_stop_ptr >= (char*)file + buffer_size) {
        free(file);
        failure("Invalid code_stop_ptr calculation\n");
    }

    file->global_ptr = (int*) malloc (file->global_area_size * sizeof (int));
    if (file->global_ptr == NULL && file->global_area_size > 0) {
        free(file);
        failure ("*** FAILURE: unable to allocate memory for globals.\n");
    }

    return file;
}

#define INIT_STACK_SIZE 10000

typedef struct Lama_Loc {
    int idx;
    int tt;
} lama_Loc;

typedef void** StkId;

typedef struct Lama_CallInfo {
    int n_args, n_locs, n_caps;
    StkId base;
    char *ret_ip;
} lama_CallInfo;

typedef struct Lama_State {
    char *ip;
    char *code_start;
    char *code_end;  /* Первый байт ПОСЛЕ конца кода */
    StkId base;
    StkId stack_last;
    lama_CallInfo *base_ci;
    lama_CallInfo *ci;
    lama_CallInfo *end_ci;
    int size_ci;
    int stacksize;
    int n_globals;
} lama_State;

lama_State eval_state;

#define ttisnumber(o)(UNBOXED(o))
#define ttisstring(o)(!UNBOXED(o)&&TAG(TO_DATA(o)->tag)==STRING_TAG)
#define ttisarray(o)(!UNBOXED(o)&&TAG(TO_DATA(o)->tag)==ARRAY_TAG)
#define ttissexp(o)(!UNBOXED(o)&&TAG(TO_DATA(o)->tag)==SEXP_TAG)
#define ttisfunction(o)(!UNBOXED(o)&&TAG(TO_DATA(o)->tag)==CLOSURE_TAG)

#define cast(t,exp)((t)(exp))
#define check(p) do { if (!(p)) failure("Assertion failed: %s\n", #p); } while(0)

#define stack_bottom cast(StkId, __gc_stack_bottom)
#define stack_top cast(StkId, __gc_stack_top)
#define foreach_stack(ptr) for(ptr = stack_bottom; ptr > stack_top; --ptr)
#define foreach_ci(L, ptr) for(ptr = L->base_ci; ptr >= L->ci; --ptr)

#define set_gc_ptr(ptr,v)ptr=cast(size_t,v)

#define alloc_stack(type,size)(cast(type*, malloc(sizeof(type) * size)))
#define alloc_stack_end(type,size)(alloc_stack(type,size) + size - 1)

static void lama_reallocstack(lama_State *L, int newsize) {
    StkId prev_base = L->base;
    StkId prev_stack_last = L->stack_last;
    StkId prev_stack_top = stack_top;
    StkId prev_stack_bottom = stack_bottom;
    int prev_stacksize = L->stacksize;

    void **new_stack = alloc_stack(void*, newsize);
    if (!new_stack) {
        failure("Failed to allocate stack of size %d\n", newsize);
    }

    set_gc_ptr(__gc_stack_bottom, new_stack + newsize - 1);
    int shift = stack_bottom - prev_stack_bottom;
    set_gc_ptr(__gc_stack_top, prev_stack_top + shift);
    L->base = prev_base + shift;
    L->stacksize = newsize;
    L->stack_last = stack_bottom - L->stacksize;

    int elements_to_copy = prev_stacksize;
    if (elements_to_copy > 0) {
        memcpy(new_stack,
               prev_stack_last + 1,
               elements_to_copy * sizeof(void*));
    }

    StkId st_ptr;
    foreach_stack(st_ptr) {
        if (!UNBOXED(*st_ptr) && \
            prev_stack_last <= cast(StkId, *st_ptr) && \
            cast(StkId, *st_ptr) <= prev_stack_bottom)
        {
            *st_ptr = cast(StkId, *st_ptr) + shift;
        }
    }

    lama_CallInfo *ci_ptr;
    foreach_ci(L, ci_ptr)
        ci_ptr->base = ci_ptr->base + shift;

    free(prev_stack_last + 1 - prev_stacksize);
}

static void lama_growstack(lama_State *L, int n) {
    if(n > L->stacksize)
        lama_reallocstack(L, L->stacksize + n);
    else
        lama_reallocstack(L, 2 * L->stacksize);
}

#define lama_checkstack(L,n)if(stack_top-(L->stack_last)<=n)lama_growstack(L,n);
#define incr_top(L){lama_checkstack(L,1);set_gc_ptr(__gc_stack_top, stack_top - 1);}

#define lama_numadd(a,b)((a)+(b))
#define lama_numsub(a,b)((a)-(b))
#define lama_nummul(a,b)((a)*(b))

static int safe_div(lama_State *L, bytefile *bf, int a, int b) {
    if (b == 0) {
            failure("Division by zero at offset %ld: %d / %d\n",
                   (long)(L->ip - bf->code_ptr - 1), a, b);
    }
    return a / b;
}

static int safe_mod(lama_State *L, bytefile *bf, int a, int b) {
    if (b == 0) {
            failure("Modulo by zero at offset %ld: %d %% %d\n",
                   (long)(L->ip - bf->code_ptr - 1), a, b);
    }

    int result = a % b;
    if (result < 0) {
        result += (b > 0) ? b : -b;
    }
    return result;
}

#define lama_numdiv(a,b) safe_div(L, bf, (a), (b))
#define lama_nummod(a,b) safe_mod(L, bf, (a), (b))
#define lama_numlt(a,b)((a)<(b))
#define lama_numle(a,b)((a)<=(b))
#define lama_numgt(a,b)((a)>(b))
#define lama_numge(a,b)((a)>=(b))
#define lama_numeq(a,b)((a)==(b))
#define lama_numneq(a,b)((a)!=(b))
#define lama_numand(a,b)(((a != 0) && (b != 0)) ? 1 : 0)
#define lama_numor(a,b)(((a != 0) || (b != 0)) ? 1 : 0)

#define FAIL check(false)

static void lama_settop(lama_State *L, int idx) {
    if(idx < 0) {
        if (-idx > (L->base - stack_top)) {
            failure("Stack underflow in lama_settop: idx=%d, available=%ld\n",
                   idx, (long)(L->base - stack_top));
        }
    } else {
        if (idx > (stack_top - L->stack_last)) {
            failure("Stack overflow in lama_settop: idx=%d, available=%ld\n",
                   idx, (long)(stack_top - L->stack_last));
        }
    }
    set_gc_ptr(__gc_stack_top, stack_top - idx);
}

#define lama_pop(L,n)lama_settop(L,-(n))

static void check_ip_bounds(lama_State *L, size_t bytes_to_read) {
    /* Изменено: проверяем, что ip + bytes_to_read не выходит за code_end */
    /* code_end указывает на ПЕРВЫЙ байт ПОСЛЕ конца кода */
    if (L->ip + bytes_to_read > L->code_end) {
        failure("Bytecode read out of bounds: ip=%p, bytes=%zu, code_end=%p (last valid byte at %p)\n",
               L->ip, bytes_to_read, L->code_end, L->code_end - 1);
    }
}

static int read_int(lama_State *L) {
    check_ip_bounds(L, sizeof(int));
    L->ip += sizeof(int);
    return *(int*)(L->ip - sizeof(int));
}

static unsigned char read_byte(lama_State *L) {
    check_ip_bounds(L, 1);
    return (unsigned char)*L->ip++;
}

static StkId idx2StkId(lama_State *L, int idx) {
    if (idx > L->base - stack_top) {
        failure("Stack index out of bounds: idx=%d, available=%ld\n",
               idx, (long)(L->base - stack_top));
    }
    return stack_top + idx;
}

#define lama_isdummy(L,n)(*idx2StkId(L,n)==idx2StkId)

static void check_loc_bounds(lama_State *L, int idx, int max, const char *loc_type) {
    if (idx < 0 || idx >= max) {
        failure("%s index out of bounds: idx=%d, max=%d\n", loc_type, idx, max);
    }
}

static void **loc2adr(lama_State *L, lama_Loc loc) {
    int idx = loc.idx;

    // Быстрая проверка
    if (idx < 0) {
        goto bounds_error;
    }

    int n_caps = L->ci->n_caps;
    int n_args = L->ci->n_args;
    int n_locs = L->ci->n_locs;

    const char *type_name = NULL;
    int max = 0;
    int offset = 0;
    void **base_ptr = NULL;

    switch (loc.tt) {
        case LOC_G:
            type_name = "global";
            max = L->n_globals;
            base_ptr = stack_bottom;
            offset = -idx;  // globals растут вниз от stack_bottom
            break;
        case LOC_L:
            type_name = "local";
            max = n_locs;
            base_ptr = L->base;
            offset = n_locs - idx;
            break;
        case LOC_C:
            type_name = "capture";
            max = n_caps;
            base_ptr = L->base;
            offset = n_caps + n_locs - idx;
            break;
        case LOC_A:
            type_name = "argument";
            max = n_args;
            base_ptr = L->base;
            offset = n_caps + n_args + n_locs + 1 - idx;
            break;
        default:
            failure("INTERNAL: Invalid location type %d\n"
                    "Valid: LOC_G=0, LOC_L=1, LOC_A=2, LOC_C=3\n"
                    "This is likely a bytecode corruption\n",
                    loc.tt);
            return NULL;
    }

    if (idx >= max) {
        bounds_error:
        failure("Bounds error accessing %s[%d]\n"
                "  Maximum allowed: %d\n"
                "  Current frame layout:\n"
                "    [stack_bottom] Globals (%d total)\n"
                "    ...\n"
                "    [base+%d] Locals (%d total, accessing index %d)\n"
                "    [base+%d] Captures (%d total, accessing index %d)\n"
                "    [base+%d] Arguments (%d total, accessing index %d)\n"
                "    [base+%d] Return address\n"
                "    [base+%d] Function/dummy\n"
                "  Calculated address would be: base%+d = %p\n",
                type_name, idx, max,
                L->n_globals,
                n_locs, n_locs, idx,
                n_locs + n_caps, n_caps, idx,
                n_locs + n_caps + n_args, n_args, idx,
                n_locs + n_caps + n_args,
                n_locs + n_caps + n_args + 1,
                offset, base_ptr + offset);
        return NULL;
    }

    return base_ptr + offset;
}

static int lama_tonumber(lama_State *L, int idx) {
    void *o = *idx2StkId(L, idx);
    if(!UNBOXED(o)) {
        char *type_desc = "boxed value";
        if (ttisstring(o)) type_desc = "string";
        else if (ttisarray(o)) type_desc = "array";
        else if (ttissexp(o)) type_desc = "sexp";
        else if (ttisfunction(o)) type_desc = "function";

        failure("Expected number at stack[%d], got %s (address: %p)\n",
                idx, type_desc, o);
    }
    return UNBOX(o);
}

#define lama_push(L,o){*stack_top = o;incr_top(L);}
#define lama_pushnumber(L,o){*stack_top = cast(void*, BOX(o));incr_top(L);}
#define lama_pushdummy(L){*stack_top = cast(void*, __gc_stack_top);incr_top(L);}

static void lama_reallocCI(lama_State *L, int newsize) {
    lama_CallInfo *prev_base_ci = L->base_ci;
    lama_CallInfo *prev_end_ci = L->end_ci;
    lama_CallInfo *prev_ci = L->ci;
    int prev_size_ci = L->size_ci;

    L->base_ci = alloc_stack(lama_CallInfo, newsize);
    if (!L->base_ci) {
        failure("Failed to allocate CallInfo of size %d\n", newsize);
    }

    int shift = L->base_ci - prev_base_ci;

    L->size_ci = newsize;
    L->ci = prev_ci + shift;
    L->end_ci = L->base_ci - L->size_ci;

    memcpy(L->end_ci + 1,
           prev_end_ci + 1,
           prev_size_ci * sizeof(lama_CallInfo));

    free(prev_end_ci + 1 - prev_size_ci);
}

static void lama_growCI(lama_State *L, int n) {
    if(n > L->size_ci)
        lama_reallocCI(L, L->size_ci + n);
    else
        lama_reallocCI(L, 2 * L->size_ci);
}

#define lama_checkCI(L,n)if((L->ci)-(L->end_ci)<=n)lama_growCI(L,n);
#define inc_ci(L){lama_checkCI(L,1);--L->ci;}

#ifdef DEBUG
#define print_debug(...) printf(__VA_ARGS__)
#else
#define print_debug(...) (void)0
#endif

void printstack(lama_State *L) {
    printf("stack\n");
    for (int i = 0; i < L->base - stack_top; i++) {
        int idx = L->base - stack_top - i;
        void *d = *idx2StkId(L, idx);
        if(ttisnumber(d))
            printf("(int)");
        else if(ttissexp(d))
            printf("(sexp)");
        else if(ttisarray(d))
            printf("(arr)");
        else if(ttisstring(d))
            printf("(str)");
        else if(ttisfunction(d))
            printf("(fun)");
        printf("%s ", cast(char*, Bstringval(d)));
    }
    printf("\n");
}

void printglobals(lama_State *L) {
    printf("globals\n");
    for (int i = 0; i < L->n_globals; i++) {
        lama_Loc loc = {i, LOC_G};
        void *d = *loc2adr(L, loc);
        if(ttisnumber(d))
            printf("(int)");
        else if(ttissexp(d))
            printf("(sexp)");
        else if(ttisarray(d))
            printf("(arr)");
        else if(ttisstring(d))
            printf("(str)");
        else if(ttisfunction(d))
            printf("(fun)");
        printf("%s ", cast(char*, Bstringval(d)));
    }
    printf("\n");
}

void printlocals(lama_State *L) {
    printf("locals\n");
    for (int i = 0; i < L->ci->n_locs; i++) {
        lama_Loc loc = {i, LOC_L};
        void *d = *loc2adr(L, loc);
        if(ttisnumber(d))
            printf("(int)");
        else if(ttissexp(d))
            printf("(sexp)");
        else if(ttisarray(d))
            printf("(arr)");
        else if(ttisstring(d))
            printf("(str)");
        else if(ttisfunction(d))
            printf("(fun)");
        printf("%s ", cast(char*, Bstringval(d)));
    }
    printf("\n");
}

void printargs(lama_State *L) {
    printf("args\n");
    for (int i = 0; i < L->ci->n_args; i++) {
        lama_Loc loc = {i, LOC_A};
        void *d = *loc2adr(L, loc);
        if(ttisnumber(d))
            printf("(int)");
        else if(ttissexp(d))
            printf("(sexp)");
        else if(ttisarray(d))
            printf("(arr)");
        else if(ttisstring(d))
            printf("(str)");
        else if(ttisfunction(d))
            printf("(fun)");
        printf("%s ", cast(char*, Bstringval(d)));
    }
    printf("\n");
}

#ifndef DEBUG
#define printstack(l) (void)0
#define printglobals(l) (void)0
#define printlocals(l) (void)0
#define printargs(l) (void)0
#endif

static void lama_begin(lama_State *L, int n_caps, int n_args, int n_locs, char *retip, void *fun) {
    inc_ci(L)
    lama_CallInfo *ci = L->ci;
    ci->ret_ip = retip;
    ci->n_caps = n_caps;
    ci->n_args = n_args;
    ci->n_locs = n_locs;

    if(fun == NULL)
        lama_pushdummy(L)
    else
        lama_push(L, fun);

    lama_checkstack(L, n_caps + n_locs)
    lama_settop(L, n_caps + n_locs);
    L->base = ci->base = stack_top;

    for(int i = 0; i < n_caps; i++) {
        lama_Loc loc = {i, LOC_C};
        *loc2adr(L, loc) = cast(void**, fun)[i + 1];
    }
    for(int i = 0; i < n_locs; i++) {
        lama_Loc loc = {i, LOC_L};
        *loc2adr(L, loc) = cast(void*, 1);
    }
}

static void lama_end(lama_State *L) {
    void *ret = *idx2StkId(L, 1);
    int n_caps = L->ci->n_caps;
    int n_args = L->ci->n_args;
    int n_locs = L->ci->n_locs;

    if ((L->base - stack_top) != 1) {
        failure("Stack frame corruption in lama_end: expected 1 value, got %ld\n",
               (long)(L->base - stack_top));
    }

    void *fun = *(L->base + (n_caps + n_locs + 1));
    for(int i = 0; i < n_caps; i++) {
        lama_Loc loc = {i, LOC_C};
        cast(void**, fun)[i + 1] = *loc2adr(L, loc);
    }

    set_gc_ptr(__gc_stack_top, stack_top + (n_caps + n_args + n_locs + 2));

    L->ip = L->ci->ret_ip;
    ++L->ci;
    L->base = L->ci->base;
    lama_push(L, ret);
}

/* Найти точку входа main в таблице публичных символов */
static char* find_main_entrypoint(bytefile *bf) {
    if (bf->public_symbols_number == 0) {
        failure("No public symbols in bytecode file\n");
    }

    for (int i = 0; i < bf->public_symbols_number; i++) {
        char *name = get_public_name(bf, i);
        if (strcmp(name, "main") == 0) {
            int offset = get_public_offset(bf, i);

            if (offset < 0) {
                failure("Invalid offset for 'main': %d (must be >= 0)\n", offset);
            }

            if (offset > (code_stop_ptr - bf->code_ptr)) {
                failure("'main' offset %d exceeds code size %ld\n",
                        offset, (long)(code_stop_ptr - bf->code_ptr));
            }

            return bf->code_ptr + offset;
        }
    }

    // Вывод первых нескольких символов для помощи
    fprintf(stderr, "Main not found. Available symbols (%d total):\n",
            bf->public_symbols_number);
    for (int i = 0; i < bf->public_symbols_number && i < 10; i++) {
        fprintf(stderr, "  '%s'\n", get_public_name(bf, i));
    }

    failure("Required public symbol 'main' not found\n");
    return NULL;
}

static void check_jump_offset(lama_State *L, int offset) {
    /* code_start + offset должен указывать внутрь кода (до code_end) */
    if (offset < 0 || L->code_start + offset >= L->code_end) {
        failure("Invalid jump offset: %d (code range: %p-%p, last valid at %p)\n",
               offset, L->code_start, L->code_end, L->code_end - 1);
    }
}

void eval (bytefile *bf, char *fname) {
   lama_State *L = &eval_state;
   L->ip = find_main_entrypoint(bf);  // Начинаем с main
   L->code_start = bf->code_ptr;
   /* ВАЖНОЕ ИСПРАВЛЕНИЕ: code_end указывает на ПЕРВЫЙ байт ПОСЛЕ конца кода */
   L->code_end = code_stop_ptr + 1;  // +1 чтобы указывать за пределы кода
   L->n_globals = bf->global_area_size;

   // Проверка, что main находится в пределах кода
   if (L->ip < L->code_start || L->ip >= L->code_end) {
        failure("Main entrypoint %p out of bounds [%p, %p) in %s\n"
            "Offset: %ld, Code size: %ld bytes\n",
            L->ip, L->code_start, L->code_end, fname,
            L->ip - bf->code_ptr, L->code_end - L->code_start);
   }

   void **stack_start = alloc_stack(void*, INIT_STACK_SIZE);
   if (!stack_start) {
        failure("Failed to allocate %zu bytes for stack: %s\n",
            INIT_STACK_SIZE * sizeof(void*), strerror(errno));
   }
   __gc_stack_top = set_gc_ptr(__gc_stack_bottom, stack_start + INIT_STACK_SIZE - 1);
   L->base = stack_bottom;
   L->stacksize = INIT_STACK_SIZE;
   L->stack_last = stack_bottom - L->stacksize;

   lama_CallInfo *ci_start = alloc_stack(lama_CallInfo, INIT_STACK_SIZE);
   if (!ci_start) {
       free(stack_start);
       failure("Failed to allocate %zu bytes for CallInfo after successful stack allocation: %s\n",
            INIT_STACK_SIZE * sizeof(lama_CallInfo), strerror(errno));
   }
   L->base_ci = L->ci = ci_start + INIT_STACK_SIZE - 1;
   L->size_ci = INIT_STACK_SIZE;
   L->end_ci = L->base_ci - L->size_ci;

   lama_settop(L, L->n_globals);

   L->base = stack_top;

   lama_pushnumber(L, 0);
   lama_pushnumber(L, 0);

   L->ci->n_locs = L->ci->n_args = 0;
   L->ci->base = L->base;
   lama_pushnumber(L, 0);
   lama_pushdummy(L);

   char *ret_ip = code_stop_ptr;

   for(int i = 0; i < L->n_globals; i++) {
        lama_Loc loc = {i, LOC_G};
        *loc2adr(L, loc) = cast(void*, 1);
   }

   do {
#ifdef DEBUG
        printstack(L);
        printglobals(L);
        printlocals(L);
        printargs(L);
        printf("=============\n");
#endif
        /* Проверяем, не достигли ли мы конца кода перед чтением */
        if (L->ip >= L->code_end) {
            failure("Reached end of bytecode without stop opcode\n");
        }

        check_ip_bounds(L, 1);
        //char x = read_byte(L), h = (x & 0xF0) >> 4, l = x & 0x0F;
        unsigned char x = read_byte(L);
        unsigned char h = (x & 0xF0) >> 4;
        unsigned char l = x & 0x0F;

        /* Макросы для ошибок */
        #define ERROR_AT(fmt, ...) failure("ERROR at offset %ld (0x%lx): " fmt, \
                                            (long)(L->ip - bf->code_ptr - 1), \
                                            (long)(L->ip - bf->code_ptr - 1), \
                                            ##__VA_ARGS__)

        #define OPFAIL(fmt, ...) ERROR_AT("invalid opcode %d-%d: " fmt, \
                                            (int)h, (int)l, ##__VA_ARGS__)


        switch (h) {
            case OP_HALT:
                goto stop;
            case OP_BINOP: { //BINOP
                print_debug("BINOP\n");

                int nc = cast(int, *idx2StkId(L, 1));
                if(UNBOXED(nc)) nc = UNBOX(nc);
                int nb = cast(int, *idx2StkId(L, 2));
                if(UNBOXED(nb)) nb = UNBOX(nb);
                lama_pop(L, 2);
                switch (l) {
                    case OP_ADD:    lama_pushnumber(L, lama_numadd(nb,nc)); break;
                    case OP_SUB:    lama_pushnumber(L, lama_numsub(nb,nc)); break;
                    case OP_MUL:    lama_pushnumber(L, lama_nummul(nb,nc)); break;
                    case OP_DIV:    lama_pushnumber(L, lama_numdiv(nb,nc)); break;
                    case OP_MOD:    lama_pushnumber(L, lama_nummod(nb,nc)); break;
                    case OP_LT:     lama_pushnumber(L, lama_numlt(nb,nc));  break;
                    case OP_LE:     lama_pushnumber(L, lama_numle(nb,nc));  break;
                    case OP_GT:     lama_pushnumber(L, lama_numgt(nb,nc));  break;
                    case OP_GE:     lama_pushnumber(L, lama_numge(nb,nc));  break;
                    case OP_EQ:     lama_pushnumber(L, lama_numeq(nb,nc));  break;
                    case OP_NEQ:    lama_pushnumber(L, lama_numneq(nb,nc)); break;
                    case OP_AND:    lama_pushnumber(L, lama_numand(nb,nc)); break;
                    case OP_OR:     lama_pushnumber(L, lama_numor(nb,nc));  break;
                    default:
                        OPFAIL("Invalid binary operation\n");
                }
                break;
            }
            case OP_PRIMARY:
                switch (l) {
                    case PRIMARY_CONST: //CONST
                        print_debug("CONST\n");
                        lama_pushnumber(L, read_int(L));
                        break;
                    case PRIMARY_STRING: //STRING
                        print_debug("STRING\n");
                        lama_push(L, Bstring(get_string(bf, read_int(L))));
                        break;
                    case PRIMARY_SEXP: { //SEXP
                        print_debug("SEXP\n");
                        int tag = LtagHash(get_string(bf, read_int(L)));
                        int n = read_int(L);
                        void* b = LmakeSexp(BOX(n + 1), tag);
                        for (int i = 0; i < n; i++)
                            cast(void**, b)[i] = *idx2StkId(L, n - i);
                        lama_pop(L, n);
                        lama_push(L, b);
                        break;
                    }
                    case PRIMARY_STI: //STI
                        ERROR_AT("Invalid opcode: STI\n");
                    case PRIMARY_STA: { //STA
                        print_debug("STA\n");
                        StkId v = *idx2StkId(L, 1);
                        int i = cast(int, *idx2StkId(L, 2));
                        StkId x = *idx2StkId(L, 3);
                        lama_pop(L, 3);
                        lama_push(L, Bsta(v, i, x));
                        break;
                    }
                    case PRIMARY_JMP: { //JMP
                        print_debug("JMP\n");
                        int addr = read_int(L);
                        check_jump_offset(L, addr);
                        L->ip = bf->code_ptr + addr;
                        break;
                    }
                    case PRIMARY_END: //END
                        print_debug("END\n");
                        lama_end(L);
                        break;
                    case PRIMARY_RET: //RET
                        ERROR_AT("Invalid opcode: RET\n");
                    case PRIMARY_DROP: //DROP
                        print_debug("DROP\n");
                        lama_pop(L, 1);
                        break;
                    case PRIMARY_DUP: //DUP
                        print_debug("DUP\n");
                        lama_push(L, *idx2StkId(L, 1));
                        break;
                    case PRIMARY_SWAP: { //SWAP
                        print_debug("SWAP\n");
                        swap(*idx2StkId(L, 1), *idx2StkId(L, 2));
                        break;
                    }
                    case PRIMARY_ELEM: { //ELEM
                        print_debug("ELEM\n");
                        int i = cast(int, *idx2StkId(L, 1));
                        void* p = *idx2StkId(L, 2);
                        lama_pop(L, 2);
                        lama_push(L, Belem(p, i));
                        break;
                    }
                    default:
                        OPFAIL("Invalid primary opcode\n");
                }
                break;
            case OP_LD: { //LD
                print_debug("LD");
                unsigned char loc_type = l;
                if (loc_type >= LOC_N) {  // LOC_N = 4
                    ERROR_AT("Invalid location type for LD: %d (max %d)\n",
                            loc_type, LOC_N - 1);
                }
                lama_Loc loc = {read_int(L), (char)loc_type};  // Приведение к char
                lama_push(L, *loc2adr(L, loc));
                break;
            }
            case OP_LDA: { //LDA
                print_debug("LDA\n");
                unsigned char loc_type = l;
                if (loc_type >= LOC_N) {
                    ERROR_AT("Invalid location type for LDA: %d\n", loc_type);
                }
                lama_Loc loc = {read_int(L), (char)loc_type};
                lama_push(L, loc2adr(L, loc));
                lama_pushdummy(L);
                break;
            }
            case OP_ST: { //ST
                print_debug("ST\n");
                unsigned char loc_type = l;
                if (loc_type >= LOC_N) {
                    ERROR_AT("Invalid location type for ST: %d\n", loc_type);
                }
                lama_Loc loc = {read_int(L), (char)loc_type};
                *loc2adr(L, loc) = *idx2StkId(L, 1);
                break;
            }
            case OP_CTRL:
                switch (l) {
                    case CTRL_CJMPz: { //CJMPz
                        print_debug("CJMPz\n");
                        int n = lama_tonumber(L, 1);
                        lama_pop(L, 1);
                        int addr = read_int(L);
                        check_jump_offset(L, addr);
                        if(n == 0) L->ip = bf->code_ptr + addr;
                        break;
                    }
                    case CTRL_CJMPnz: { //CJMPnz
                        print_debug("CJMPnz\n");
                        int n = lama_tonumber(L, 1);
                        lama_pop(L, 1);
                        int addr = read_int(L);
                        check_jump_offset(L, addr);
                        if(n != 0) L->ip = bf->code_ptr + addr;
                        break;
                    }
                    case CTRL_BEGIN: {
                        print_debug("BEGIN\n");

                        // Проверяем, что на стеке достаточно элементов
                        if (L->base - stack_top < 2) {
                            ERROR_AT("BEGIN: stack underflow, need 2 values, have %ld\n",
                                    (long)(L->base - stack_top));
                        }

                        int n_caps = lama_tonumber(L, 2);
                        if (n_caps != 0) {
                            void *cap_value = *idx2StkId(L, 2);
                            ERROR_AT("BEGIN: expected 0 captures for non-closure function, "
                                    "got %d (value=%p, %s)\n",
                                    n_caps, cap_value,
                                    UNBOXED(cap_value) ? "unboxed number" : "boxed value");
                        }

                        void *fun = *idx2StkId(L, 1);
                        if(lama_isdummy(L, 1)) {
                            fun = NULL;
                        // Leads to ERROR:
                        // ERROR at offset 0 (0x0): BEGIN: expected function or dummy at stack[1], got `addr` (tag=0)
                        } /* else if (!ttisfunction(fun) && fun != NULL) {
                            ERROR_AT("BEGIN: expected function or dummy at stack[1], "
                                    "got %p (tag=%d)\n",
                                    fun, !UNBOXED(fun) ? TO_DATA(fun)->tag : -1);
                        } */

                        lama_pop(L, 2);
                        int n_args = read_int(L), n_locs = read_int(L);

                        // Дополнительные проверки аргументов
                        if (n_args < 0) ERROR_AT("BEGIN: negative n_args: %d\n", n_args);
                        if (n_locs < 0) ERROR_AT("BEGIN: negative n_locs: %d\n", n_locs);

                        lama_begin(L, 0, n_args, n_locs, ret_ip, fun);
                        break;
                    }
                    case CTRL_CBEGIN: { //CBEGIN
                        print_debug("CBEGIN\n");
                        int n_caps = lama_tonumber(L, 2);
                        void *fun = *idx2StkId(L, 1);
                        if(lama_isdummy(L, 1)) fun = NULL;
                        lama_pop(L, 2);
                        int n_args = read_int(L), n_locs = read_int(L);
                        lama_begin(L, n_caps, n_args, n_locs, ret_ip, fun);
                        break;
                    }
                    case CTRL_CLOSURE: { //CLOSURE
                        print_debug("CLOSURE\n");
                        int func_offset = read_int(L);
                        check_jump_offset(L, func_offset);
                        int n_caps = read_int(L);
                        void *fun = LMakeClosure(BOX(n_caps), bf->code_ptr + func_offset);
                        for (int i = 0; i < n_caps; i++) {
                            //char tt = read_byte(L);
                            unsigned char tt_byte = read_byte(L);
                            if (tt_byte >= LOC_N) {
                                failure("Invalid location type %d\n", tt_byte);
                            }
                            char tt = (char)tt_byte;
                            int idx = read_int(L);
                            lama_Loc loc = {idx, tt};
                            cast(void**, fun)[i + 1] = *loc2adr(L, loc);
                        }
                        lama_push(L, fun);
                        break;
                    }
                    case CTRL_CALLC: {
                        print_debug("CALLC\n");
                        int n_args = read_int(L);
                        void *fun = *idx2StkId(L, n_args + 1);

                        /* Улучшенная проверка функции */
                        if (!ttisfunction(fun)) {
                            char *type = "unknown/boxed";
                            if (UNBOXED(fun)) type = "unboxed number";
                            else if (ttisstring(fun)) type = "string";
                            else if (ttisarray(fun)) type = "array";
                            else if (ttissexp(fun)) type = "sexp";

                            ERROR_AT("CALLC expected function at stack position %d, got %s (value: %p)\n",
                                    n_args + 1, type, fun);
                        }

                        for(int i = n_args; i > 0; i--)
                            *idx2StkId(L, i + 1) = *idx2StkId(L, i);
                        lama_pop(L, 1);
                        int n_caps = LEN(TO_DATA(fun)->tag) - 1;
                        lama_pushnumber(L, n_caps); //n_caps
                        lama_push(L, fun);
                        ret_ip = L->ip;
                        char *func_ptr = cast(char**, fun)[0];

                        /* Улучшенная проверка указателя функции */
                        unsigned char first_byte = (unsigned char)*func_ptr;
                        unsigned char func_h = (first_byte & 0xF0) >> 4;
                        unsigned char func_l = first_byte & 0x0F;

                        if (func_h != OP_CTRL ||
                            (func_l != CTRL_BEGIN && func_l != CTRL_CBEGIN)) {
                            ERROR_AT("Invalid function pointer in CALLC: opcode %d-%d (0x%02x) at %p, "
                                    "expected %d-{%d,%d}\n",
                                    func_h, func_l, first_byte, func_ptr,
                                    OP_CTRL, CTRL_BEGIN, CTRL_CBEGIN);
                        }

                        L->ip = func_ptr;
                        break;
                    }
                    case CTRL_CALL: { //CALL
                        print_debug("CALL\n");
                        int func_offset = read_int(L);
                        check_jump_offset(L, func_offset);
                        int n_args = read_int(L);
                        char *func_ptr = bf->code_ptr + func_offset;

                        /* Улучшенная проверка указателя функции */
                        unsigned char first_byte = (unsigned char)*func_ptr;
                        unsigned char func_h = (first_byte & 0xF0) >> 4;
                        unsigned char func_l = first_byte & 0x0F;

                        if (func_h != OP_CTRL ||
                            (func_l != CTRL_BEGIN && func_l != CTRL_CBEGIN)) {
                            ERROR_AT("Invalid function pointer in CALL at offset %d: "
                                    "opcode %d-%d (0x%02x) at %p, expected %d-{%d,%d}\n",
                                    func_offset, func_h, func_l, first_byte, func_ptr,
                                    OP_CTRL, CTRL_BEGIN, CTRL_CBEGIN);
                        }

                        lama_pushnumber(L, 0); //n_caps
                        lama_pushdummy(L);
                        ret_ip = L->ip;
                        L->ip = func_ptr;
                        break;
                    }
                    case CTRL_TAG: { //TAG
                        print_debug("TAG\n");
                        int t = LtagHash(get_string(bf, read_int(L)));
                        int n = read_int(L);
                        *idx2StkId(L, 1) = cast(void*, Btag(*idx2StkId(L, 1), t, BOX(n)));
                        break;
                    }
                    case CTRL_ARRAY: { //ARRAY
                        print_debug("ARRAY\n");
                        int n = read_int(L);
                        *idx2StkId(L, 1) = cast(void*, Barray_patt(*idx2StkId(L, 1), BOX(n)));
                        break;
                    }
                    case CTRL_FAIL: { //FAIL
                        print_debug("FAIL\n");
                        int line = read_int(L);
                        int col = read_int(L);
                        void *v = *idx2StkId(L, 1);
                        Bmatch_failure(v, fname, line, col);
                        exit(0);
                    }
                    case CTRL_LINE: { //LINE
                        int line = read_int(L);
                        print_debug("LINE %d\n", line);
                        break;
                    }
                    default:
                        OPFAIL("Invalid control opcode\n");
                }
                break;
            case OP_PATT: { //PATT
                print_debug("PATT\n");
                switch (l) {
                    case PATT_STR: //=str
                        *idx2StkId(L, 2) = cast(void*, Bstring_patt(*idx2StkId(L, 2), *idx2StkId(L, 1)));
                        lama_pop(L, 1);
                        break;
                    case PATT_STRING_TAG: //#string
                        *idx2StkId(L, 1) = cast(void*, Bstring_tag_patt(*idx2StkId(L, 1)));
                        break;
                    case PATT_ARRAY_TAG: //#array
                        *idx2StkId(L, 1) = cast(void*, Barray_tag_patt(*idx2StkId(L, 1)));
                        break;
                    case PATT_SEXP_TAG: //#sexp
                        *idx2StkId(L, 1) = cast(void*, Bsexp_tag_patt(*idx2StkId(L, 1)));
                        break;
                    case PATT_REF: //#ref
                        *idx2StkId(L, 1) = cast(void*, Bboxed_patt(*idx2StkId(L, 1)));
                        break;
                    case PATT_VAL: //#val
                        *idx2StkId(L, 1) = cast(void*, Bunboxed_patt(*idx2StkId(L, 1)));
                        break;
                    case PATT_FUN: //#fun
                        *idx2StkId(L, 1) = cast(void*, Bclosure_tag_patt(*idx2StkId(L, 1)));
                        break;
                    default:
                        OPFAIL("Invalid pattern opcode\n");
                }
                break;
            }
            case OP_BUILTIN: {
                switch (l) {
                    case BUILTIN_READ: // CALL Lread
                        print_debug("Lread\n");
                        lama_push(L, cast(void*, Lread()));
                        break;
                    case BUILTIN_WRITE: //CALL Lwrite
                        print_debug("Lwrite\n");
                        Lwrite(cast(int, *idx2StkId(L, 1)));
                        break;
                    case BUILTIN_LENGTH: //CALL Llength
                        print_debug("Llength\n");
                        *idx2StkId(L, 1) = cast(void*, Blength(*idx2StkId(L, 1)));
                        break;
                    case BUILTIN_STRING: //CALL Lstring
                        print_debug("Lstring\n");
                        *idx2StkId(L, 1) = Bstringval(*idx2StkId(L, 1));
                        break;
                    case BUILTIN_ARRAY: { //CALL Barray
                        print_debug("Barray\n");
                        int n = read_int(L);
                        void *p = LmakeArray(BOX(n));
                        for (int i = 0; i < n; i++)
                            cast(void**, p)[i] = *idx2StkId(L, n - i);
                        lama_pop(L, n);
                        lama_push(L, p);
                        break;
                    }
                    default:
                        OPFAIL("Invalid builtin opcode\n");
                }
                break;
            }
            default:
                ERROR_AT("Invalid opcode prefix: %d\n", h);
        }
    }
    while (true);
    stop:
    free(stack_start);
    free(ci_start);

    #undef ERROR_AT
    #undef OPFAIL
}

int main (int argc, char* argv[]) {
    if (argc < 2) {
        failure("Usage:\n"
                "  %s program.bc        – execute Lama bytecode\n"
                "  %s --idioms program.bc – analyze idioms\n",
		        "  %s --verify program.bc - verify bytecode\n",
                argv[0], argv[0], argv[0]);
    }

    if (strcmp(argv[1], "--verify") == 0 || strcmp(argv[1], "--verify-verbose") == 0) {
    if (argc < 3) {
        failure("Usage: %s --verify <bytecode-file>\n"
                "       %s --verify-verbose <bytecode-file>\n", 
                argv[0], argv[0]);
    }
    
    bytefile* bf = read_file(argv[2]);
    if (!bf) {
        failure("Failed to read bytecode file\n");
    }
    
    bool verbose = (strcmp(argv[1], "--verify-verbose") == 0);
    bool ok = verbose ? verify_bytecode_verbose(bf, argv[2], code_stop_ptr) :
                       verify_bytecode(bf, argv[2], code_stop_ptr);
    
    free(bf->global_ptr);
    free(bf);
    
    return ok ? 0 : 1;
}

    if (strcmp(argv[1], "--idioms") == 0) {
        if (argc < 3) failure("Usage: %s --idioms <bytecode-file>\n", argv[0]);

        bytefile* bf = read_file(argv[2]);
        if (!bf) {
            failure("Failed to read bytecode file\n");
        }

        // Собираем точки входа (все публичные символы)
        uint32_t* entrypoints = malloc((bf->public_symbols_number + 1) * sizeof(uint32_t));
        if (!entrypoints) {
            failure("Failed to allocate memory for entrypoints\n");
        }

        uint32_t entry_count = 0;

        for (int i = 0; i < bf->public_symbols_number; i++) {
            int offset = get_public_offset(bf, i);
            if (offset >= 0 && offset < (code_stop_ptr - bf->code_ptr)) {
                entrypoints[entry_count++] = (uint32_t)offset;
            }
        }

        if (entry_count == 0) {
            // Если нет публичных символов, используем 0 как точку входа
            entrypoints[entry_count++] = 0;
        }

        uint32_t code_size = (uint32_t)(code_stop_ptr - bf->code_ptr + 1);
        const uint8_t* code = (const uint8_t*)bf->code_ptr;

        // Проверяем, что размер корректен
        if (code_size == 0) {
            failure("Empty bytecode\n");
        }

        IdiomList idioms = analyze_idioms(code, code_size, entrypoints, entry_count);

        printf("=== Idiom frequency analysis ===\n");
        printf("Total idioms found: %u\n", idioms.count);
        printf("\n");

        for (uint32_t i = 0; i < idioms.count; i++) {
            if (idioms.idioms[i].occurrences == 0) continue;

            printf("%6u ×  ", idioms.idioms[i].occurrences);
            for (uint32_t j = 0; j < idioms.idioms[i].len; j++) {
                printf("%02X ", idioms.idioms[i].bytes[j]);
            }
            printf("\n");
        }

        free_idiom_list(&idioms);
        free(entrypoints);
        free(bf->global_ptr);
        free(bf);
        return 0;
    }

//    if (argc < 2) {
//        failure("Usage: %s <bytecode-file>\n", argv[0]);
//    }
//
    bytefile *f = read_file (argv[1]);
    eval (f, argv[1]);
    free(f->global_ptr);
    free(f);
    return 0;
}
