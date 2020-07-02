# fix_ppc_vtable.py - kd (@kd_tech_)
# Created for: kiwidoggie productions
#
# [+] Bound fix_ppc_vtable to Ctrl-Alt-U

import idaapi
import idc
import inspect


def fix_ppc_vtable():
    selected = idaapi.read_selection()
    curr_ea = idc.get_screen_ea()
    print "[+] Processing range: %x - %x" % (selected[1],selected[2])
    if selected[1] % 4 != 0:
        print "address start not 4 byte aligned"
        return
    
    if selected[2] % 4 != 0:
        print "address end not 4 byte aligned"
        return
    
    for ea in range(selected[1], selected[2], 1):
        #print "%x" % (ea)
        idc.MakeUnknown(ea, 1, idaapi.DOUNK_SIMPLE)
    
    for ea in range(selected[1], selected[2], 4):
        #print "%x" % (ea)
        ida_bytes.create_data(ea, FF_DWORD, 4, ida_idaapi.BADADDR)
        idaapi.op_offset(ea, 0, idaapi.REF_OFF64)

def load_hotkeys():
    info = idaapi.get_inf_structure()
    proc = info.procName.lower()
    if proc != "ppc":
        print "[-] fix_ppc_vtable not loaded: invalid proc type"
        return
    
    ENABLED_HOTKEYS = [
            ("Ctrl-Alt-U", fix_ppc_vtable)
            ]

    for func in ENABLED_HOTKEYS:
        func_name = inspect.getmembers(func[1])[-1][1]
        if idaapi.add_hotkey(func[0], func[1]):
            print "[+] Bound %s to %s" % (func_name, func[0])
        else:
            print "[-] Error: Unable to bind %s to %s" % (func_name, func[0])

load_hotkeys()
