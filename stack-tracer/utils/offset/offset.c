// generate_offsets.c
#include <stdio.h>
#include <stddef.h>
#include <Python.h>
#include <cpython/code.h>
#include <cpython/funcobject.h>

int main() {

    printf("#define OFFSET_FUNC_CODE %zu\n",
        offsetof(PyFunctionObject, func_code));

    printf("#define OFFSET_CO_FILENAME %zu\n",
        offsetof(PyCodeObject, co_filename));

    printf("#define OFFSET_CO_NAME %zu\n",
        offsetof(PyCodeObject, co_name));

    return 0;
}