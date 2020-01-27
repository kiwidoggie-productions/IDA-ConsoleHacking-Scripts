#!/usr/bin/env python

#
# OpenOrbis Project providing 100% free and open source development
# This script will enumerate and print out in the console all of the eventhandler_register names
# so you can use them in your own kernel scripts
# Fuck the pirates
#
# Created by: kd (@kd_tech_)
# Started on: Jan 25, 2020
#

def get_eventhandler_register():
    s_Ea = idc.BeginEA()
    for l_FunctionAddress in idautils.Functions(SegStart(s_Ea), SegEnd(s_Ea)):
        l_FunctionName = idc.GetFunctionName(l_FunctionAddress)

        # check if it's our variable
        if l_FunctionName.startswith("eventhandler_register"):
            return l_FunctionAddress
    
    return idaapi.BADADDR

if __name__ == "__main__":
    s_EventHandlerRegister = get_eventhandler_register()
    if s_EventHandlerRegister == idaapi.BADADDR:
        msg("err: could not find eventhandler_register\n")
    
    #msg("found eventhandler_register: %x\n" % s_EventHandlerRegister)
    for l_XRef in idautils.XrefsTo(s_EventHandlerRegister):
        l_XRefEA = l_XRef.frm
        
        l_XRefAddrs = idaapi.get_arg_addrs(l_XRefEA)
        if l_XRefAddrs == None:
            continue
        # eventhandler_tag eventhandler_register(struct eventhandler_list *list, const char *name, void *func, void *arg, int priority)
        #msg("len: %d\n" % len(l_XRefAddrs))

        l_Arg = l_XRefAddrs[1]
        l_NameAddress = long(idc.GetOperandValue(l_Arg, 1))
        l_Name = idc.get_strlit_contents(l_NameAddress)
        msg("%s - %s\n" % (l_Name, "0")) #
    #msg("complete\n")
