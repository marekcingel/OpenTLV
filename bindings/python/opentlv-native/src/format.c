#include "format.h"

const tlv_format_t* opentlv_python_format_for(int format_id) {
    switch (format_id) {
#if OPENTLV_FORMAT_BER
        case 1: return opentlv_python_format_ber();
#endif
#if OPENTLV_FORMAT_CER
        case 2: return opentlv_python_format_cer();
#endif
#if OPENTLV_FORMAT_DER
        case 3: return opentlv_python_format_der();
#endif
#if OPENTLV_LLDP
        case 4: return opentlv_python_format_lldp();
#endif
#if OPENTLV_EMV
        case 5: return opentlv_python_format_emv();
#endif
        default: return NULL;
    }
}

int opentlv_python_register_formats(PyObject* module) {
    if (PyModule_AddIntConstant(module, "HAS_BER", OPENTLV_FORMAT_BER) < 0) return -1;
    if (PyModule_AddIntConstant(module, "HAS_CER", OPENTLV_FORMAT_CER) < 0) return -1;
    if (PyModule_AddIntConstant(module, "HAS_DER", OPENTLV_FORMAT_DER) < 0) return -1;
    if (PyModule_AddIntConstant(module, "HAS_LLDP", OPENTLV_LLDP) < 0) return -1;
    if (PyModule_AddIntConstant(module, "HAS_EMV", OPENTLV_EMV) < 0) return -1;
    return 0;
}
