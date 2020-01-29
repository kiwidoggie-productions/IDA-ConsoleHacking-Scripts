#!/usr/bin/env python

#
# This script will create the needed structures, and label all syscalls from a FULL kernel dump
# OpenOrbis Project providing 100% free and open source development
# Fuck the pirates
#
# Created by: kiwidog (http://kiwidog.me)
# Started on: Febuary 14, 2019
#

def find_syscalls():
    """
    Automatically finds and labels all of the syscalls in a kernel dump
    :return: Nothing
    """
    # Get the sysent_t structure
    sysent_id = idaapi.get_struc_id("sysent_t")
    if sysent_id == idaapi.BADNODE:
        write_log("could not get the sysent_t structure.")
        return

    # Find the magic
    magic_offset = idaapi.find_binary(idc.MinEA(), idc.MaxEA(), "4F 52 42 49 53 20 6B 65 72 6E 65 6C 20 53 45 4C 46", 16, idc.SEARCH_DOWN)
    if magic_offset == idaapi.BADADDR:
        write_log("Could not find 'ORBIS kernel SELF' magic - sysent not found")
        return
    
    magic_offset = idaapi.get_imagebase() + magic_offset

    # Find the reference to the magic
    search_pattern = "%02X %02X %02X %02X FF FF FF FF" % (magic_offset & 0xFF , ((magic_offset >> 0x8) & 0xFF) , ((magic_offset >> 0x10) & 0xFF) , ((magic_offset >> 0x18) & 0xFF))
    print("magic_offset: %x" % magic_offset)
    print("search_pattern: %s" % search_pattern)
    ref = idaapi.find_binary(idc.MinEA(), idc.MaxEA(), search_pattern, 16, idc.SEARCH_DOWN)
    if not ref:
        write_log("could not find reference for orbis kernel self.")
        return
    
    if ref == BADADDR:
        write_log("could not find ref")
        return
        
    # Save all of the information
    sysvec = ref - 0x60
    print("sysvec: %x" % sysvec)
    result = idaapi.set_name(sysvec, "self_orbis_sysvec", idaapi.SN_NOCHECK)
    if not result:
        write_log("could not label self_orbis_sysvec.")
        return

    # Get the number of syscalls
    syscall_count = idaapi.get_qword(sysvec)
    sysent_offset = idaapi.get_qword(sysvec + 0x8)
    result = idaapi.set_name(sysent_offset, "sysent")
    if not result:
        write_log("could not label sysent.")
        return

    # Get the list of syscall names
    syscall_names = find_syscall_names(sysvec, syscall_count)

    write_log("Labeling %d syscalls." % syscall_count)
    i = 0
    while i < syscall_count:
        syscall_name = syscall_names[str(i)]
        syscall_sysent_offset = sysent_offset + (i * 0x30) # sizeof(sysent_t)
        syscall_func = idaapi.get_qword(syscall_sysent_offset + 0x8)

        # Attempt to get the current function that is at this address
        func = idaapi.get_func(syscall_func)

        # If no function exists, create one there
        if not func:
            idaapi.add_func(syscall_func)

        # Set the name at the start of the function as a repeatable comment
        result = idaapi.set_cmt(syscall_func, syscall_name, True)
        if not result:
            write_log("could not set comment on syscall func %s." % syscall_name)

        # Set the name of the function
        result = idaapi.set_name(syscall_func, syscall_name)
        if not result:
            write_log("could not set the syscall function name %s." % syscall_name)

        # This labels the syscall number
        result = idaapi.set_cmt(syscall_sysent_offset + 0x4, "#: %d" % i, True)
        if not result:
            write_log("could not set syscall number comment")

        # Creates a sysent_t structure
        result = idaapi.create_struct(syscall_sysent_offset, 0x30, sysent_id)
        if not result:
            write_log("could not create sysent_t structure for syscall %d %s." % (i, syscall_name))

        i += 1

    write_log("found kernel self")

def install_syscall_structures():
    id = idaapi.get_struc_id("sysent_t")

    # If this structure is already installed skip it
    if id != idaapi.BADNODE:
        return

    id = idaapi.add_struc(idaapi.BADADDR, "sysent_t")
    if not id:
        write_log("could not add structure.")
        return

    struct = idaapi.get_struc(id)
    if not struct:
        write_log("could not get structure.")
        return

    op_info = idaapi.opinfo_t()
    ri_info = idaapi.refinfo_t()
    ri_info.flags = idaapi.REF_OFF64
    ri_info.target = idaapi.BADADDR
    ri_info.base = 0
    ri_info.tdelta = 0
    op_info.ri = ri_info

    result = idaapi.add_struc_member(struct, "sy_narg", 0x0, idaapi.dword_flag(), None, 4)
    if result:
        write_log("Failed adding sy_narg to sysent_t struct.")

    result = idaapi.add_struc_member(struct, "sy_call", 0x8, idaapi.qword_flag() | idaapi.off_flag(), op_info, 8)
    if result:
        write_log("Failed adding sy_call to sysent_t struct.")

    result = idaapi.add_struc_member(struct, "sy_auevent", 0x10, idaapi.word_flag(), None, 2)
    if result:
        write_log("Failed adding sy_auevent to sysent_t struct.")

    result = idaapi.add_struc_member(struct, "sy_systrace_args_func", 0x18, idaapi.qword_flag() | idaapi.off_flag(), op_info, 8)
    if result:
        write_log("Failed adding sy_systrace_args_func to sysent_t struct.")

    result = idaapi.add_struc_member(struct, "sy_entry", 0x20, idaapi.dword_flag(), None, 4)
    if result:
        write_log("Failed adding sy_entry to sysent_t struct.")

    result = idaapi.add_struc_member(struct, "sy_return", 0x24, idaapi.dword_flag(), None, 4)
    if result:
        write_log("Failed adding sy_return to sysent_t struct.")

    result = idaapi.add_struc_member(struct, "sy_flags", 0x28, idaapi.dword_flag(), None, 4)
    if result:
        write_log("Failed adding sy_flags to sysent_t struct.")

    result = idaapi.add_struc_member(struct, "sy_thrcnt", 0x2C, idaapi.dword_flag(), None, 4)
    if result:
        write_log("Failed adding sy_thrcnt to sysent_t struct.")

def find_syscall_names(sysvec, syscall_count):
    # Ensure that we got a valid sysvec
    if sysvec == idaapi.BADADDR:
        return

    # Hold our syscall names
    syscall_names = { }

    # Get the syscall names offset
    syscall_names_offset = idaapi.get_qword(sysvec + 0xD0)

    # Iterate through all of the syscall names and save them
    i = 0
    while i < syscall_count:
        pos = syscall_names_offset + (0x8 * i)

        idaapi.op_offset(pos, 0, idaapi.REF_OFF64)

        name_offset = idaapi.get_qword(pos)
        name_length = idaapi.get_max_strlit_length(name_offset, idaapi.STRTYPE_C)
        syscall_name = str(idaapi.get_strlit_contents(name_offset, name_length, idaapi.STRTYPE_C))

        if syscall_name.find("#") != -1 or syscall_name.find("obs_{") != -1:
            syscall_name = ("nosys_%d" % i)
        
        #print("#define __NR_%s %d" % (syscall_name, i))
        syscall_names[str(i)] = syscall_name
        i += 1

    return syscall_names

def write_log(message):
    idaapi.msg("[OpenOrbis] %s\n" % message)

if __name__ == "__main__":
    install_syscall_structures()
    find_syscalls()
