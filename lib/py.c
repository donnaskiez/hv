#include <Python.h>

#include "lib.h"

static PyObject*
Py_HvCliPing(PyObject* self, PyObject* args)
{
    if (!PyArg_ParseTuple(args, "")) {
        return NULL; // error
    }

    UINT32 status = HvCliPing();

    return Py_BuildValue("i", status);
}

static PyObject*
Py_HvCliTerminate(PyObject* self, PyObject* args)
{
    if (!PyArg_ParseTuple(args, "")) {
        return NULL; // error
    }

    UINT32 status = HvCliTerminate();

    return Py_BuildValue("i", status);
}

static PyObject*
Py_HvCliQueryStats(PyObject* self, PyObject* args)
{
    VCPU_STATS stats = {0};
    UINT32 status = HvCliQueryStats(&stats);

    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    if (status != HVSTATUS_SUCCESS) {
        PyErr_SetString(PyExc_RuntimeError, "QueryStats hypercall failed");
        return NULL;
    }

    PyObject* reasons_dict = Py_BuildValue(
        "{s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K}",
        "cpuid",
        stats.reasons.cpuid,
        "invd",
        stats.reasons.invd,
        "vmcall",
        stats.reasons.vmcall,
        "mov_cr",
        stats.reasons.mov_cr,
        "wbinvd",
        stats.reasons.wbinvd,
        "tpr_threshold",
        stats.reasons.tpr_threshold,
        "exception_or_nmi",
        stats.reasons.exception_or_nmi,
        "trap_flags",
        stats.reasons.trap_flags,
        "wrmsr",
        stats.reasons.wrmsr,
        "rdmsr",
        stats.reasons.rdmsr,
        "mov_dr",
        stats.reasons.mov_dr,
        "virtualised_eoi",
        stats.reasons.virtualised_eoi,
        "preemption_timer",
        stats.reasons.preemption_timer);

    PyObject* hypercall_dict = Py_BuildValue(
        "{s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K, s:K}",
        "ping",
        stats.hypercall.ping,
        "query_stats",
        stats.hypercall.query_stats,
        "terminate",
        stats.hypercall.terminate,
        "write_proc_ctls",
        stats.hypercall.write_proc_ctls,
        "write_proc_ctls2",
        stats.hypercall.write_proc_ctls2,
        "write_pin_ctls",
        stats.hypercall.write_pin_ctls,
        "write_exit_ctls",
        stats.hypercall.write_exit_ctls,
        "write_entry_ctls",
        stats.hypercall.write_entry_ctls,
        "write_exception_bitmap",
        stats.hypercall.write_exception_bitmap,
        "write_msr_bitmap",
        stats.hypercall.write_msr_bitmap,
        "read_proc_ctls",
        stats.hypercall.read_proc_ctls,
        "read_proc_ctls2",
        stats.hypercall.read_proc_ctls2,
        "read_pin_ctls",
        stats.hypercall.read_pin_ctls,
        "read_exit_ctls",
        stats.hypercall.read_exit_ctls,
        "read_entry_ctls",
        stats.hypercall.read_entry_ctls,
        "read_exception_bitmap",
        stats.hypercall.read_exception_bitmap,
        "read_msr_bitmap",
        stats.hypercall.read_msr_bitmap);

    PyObject* result = Py_BuildValue(
        "{s:K, s:O, s:O}",
        "exit_count",
        stats.exit_count,
        "reasons",
        reasons_dict,
        "hypercall",
        hypercall_dict);

    return result;
}

static PyMethodDef hvcli_methods[] = {
    {"Ping",
     Py_HvCliPing,
     METH_VARARGS,
     "Ping the hypervisor and return 32-bit status."},
    {"Terminate", Py_HvCliTerminate, METH_VARARGS, "Terminate the hypervisor."},
    {"query_stats", Py_HvCliQueryStats, METH_VARARGS, "Query VCPU stats."},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef hvcli_module =
    {PyModuleDef_HEAD_INIT, "hvcli", NULL, -1, hvcli_methods};

PyMODINIT_FUNC
PyInit_hvcli(void)
{
    return PyModule_Create(&hvcli_module);
}
