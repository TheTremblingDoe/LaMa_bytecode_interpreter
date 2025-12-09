#ifndef LVM_RUNTIME_H
#define LVM_RUNTIME_H

# define WORD_SIZE (CHAR_BIT * sizeof(int))

typedef struct {
    int tag;
    char contents[0];
} data;

typedef struct {
    int tag;
    data contents;
} sexp;

# define STRING_TAG  0x00000001
# define ARRAY_TAG   0x00000003
# define SEXP_TAG    0x00000005
# define CLOSURE_TAG 0x00000007
# define UNBOXED_TAG 0x00000009 // Not actually a tag; used to return from LkindOf

# define LEN(x) ((x & 0xFFFFFFF8) >> 3)
# define TAG(x)  (x & 0x00000007)

# define TO_DATA(x) ((data*)((char*)(x)-sizeof(int)))
# define TO_SEXP(x) ((sexp*)((char*)(x)-2*sizeof(int)))

# define UNBOXED(x)  (((int) (x)) &  0x0001)
# define UNBOX(x)    (((int) (x)) >> 1)
# define BOX(x)      ((((int) (x)) << 1) | 0x0001)


int LtagHash (char *s);
void* LmakeArray (int length);
void* LmakeSexp (int bn, int btag);
void* LMakeClosure (int bn, void *entry);
void* Bstring (void *p);
void* Bstringval (void *p);
int Btag (void *d, int t, int n);
int Barray_patt (void *d, int n);
int Bstring_patt (void *x, void *y);
int Bclosure_tag_patt (void *x);
int Bboxed_patt (void *x);
int Bunboxed_patt (void *x);
int Barray_tag_patt (void *x);
int Bstring_tag_patt (void *x);
int Bsexp_tag_patt (void *x);
void* Bsta (void *v, int i, void *x);
void Bmatch_failure (void *v, char *fname, int line, int col);
int Lread ();
int Lwrite (int n);
void* Belem (void *p, int i);
int Blength (void *p);
void printValue (void *p);

#endif //LVM_RUNTIME_H
