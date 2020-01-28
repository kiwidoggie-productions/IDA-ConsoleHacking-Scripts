#!/usr/bin/env python

#
# This script fixes the "you need to disable a x64 binary" when openening a x64 bin in IDA 7.2-7.4
#
# Created by: kiwidog (@kd_tech_)
# Started on: Febuary 15, 2019
#

import idaapi, idc, idautils
ida_info = idaapi.get_inf_structure()
ida_info.ostype = 0x6 # BSD
ida_info.demnames = idaapi.DEMNAM_NAME | idaapi.DEMNAM_GCC3
ida_info.cc.id = idaapi.COMP_GNU
ida_info.cc.cm = idaapi.CM_N64 | idaapi.CM_M_NN | idaapi.CM_CC_CDECL
ida_info.cc.size_b = 1
ida_info.cc.size_s = 2
ida_info.cc.size_i = 4
ida_info.cc.size_e = 4
ida_info.cc.size_l = 8
ida_info.cc.size_ll = 8
ida_info.cc.defalign = 0
idc.SetLongPrm(idc.INF_LFLAGS, idc.GetLongPrm(idc.INF_LFLAGS) | idc.LFLG_PC_FLAT | idc.LFLG_64BIT)
print("done")
