#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <hs.h>

static PyObject* hscheck_validate_pattern(PyObject *self, PyObject *args) {
  const char *pattern;
  unsigned int flags = 0;
  unsigned int mode = HS_MODE_BLOCK;
  hs_database_t *db;
  hs_compile_error_t *compile_error;
  hs_error_t error;

  if (!PyArg_ParseTuple(args, "s", &pattern)) {
    return NULL;
  }

  if (hs_compile(pattern, flags, mode, NULL, &db, &compile_error) != HS_SUCCESS) {
    PyObject* err = PyUnicode_FromString(compile_error->message);
    hs_free_compile_error(compile_error);
    return err;
  }

  hs_free_database(db);
  return PyUnicode_FromString("");
}

static PyMethodDef hscheck_methods[] = {
  {"validate_pattern",  hscheck_validate_pattern, METH_VARARGS, "Validate that a pattern is a valid hyperscan pattern"},
  {NULL, NULL, 0, NULL}
};

static struct PyModuleDef hscheck_module = {
  .m_methods = hscheck_methods,
};

PyMODINIT_FUNC PyInit_hscheck(void) {
      return PyModuleDef_Init(&hscheck_module);
}
