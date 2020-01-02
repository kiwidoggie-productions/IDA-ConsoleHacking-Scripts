import idaapi

#------------------------------------------------------------------------------
# IDA Plugin
# Initial creation: Oct 27, 2019 (kd)
# Plugin port: Dec 20, 2019 (Cleanup for submission, kd)
# Fix bug: Jan 2, 2020 (kd)
# Install by placing in <IDA Root>/plugins
#------------------------------------------------------------------------------
VERSION = "v0.1"
AUTHORS = [ 'kd', '' ]

# https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/
def ReadAsciiString(ea):
    stringData = ""
    while True:
        if idaapi.get_byte(ea) != 0:
            stringData += chr(idaapi.get_byte(ea))
        else:
            break

        ea += 1
    
    return stringData

#
# Align(input address, alignment)
# Aligns the input address to the specified alignment, and returns the new value
#
def Align(inputEa, alignment):
    if (inputEa % alignment) == 0:
        return inputEa
    
    num = alignment - (inputEa % alignment)
    return inputEa + num

#
# Entry structure holding the name, and target (in executable) address
#
class SnDebugEntry:
    nameAddress = idaapi.BADADDR
    targetAddress = idaapi.BADADDR
    unknown08 = 0

    def __init__(self, parseEa):
        currentPos = 0

        self.nameAddress = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.targetAddress = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown08 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4

#
# String entry structure, holding the offset of the string, and the actual string data
#
class SnStringEntry:
    offset = 0
    stringData = ""

    def __init__(self, pOffset, pString):
        self.offset = pOffset
        self.stringData = pString

#
# The .sndebug header, this has a bunch of information I'm not fully aware of at this time
# but as we find out, will fill in the unknowns
#
class SnDebugHeader:
    def __init__(self, parseEa):
        # Keep current position for tracking
        currentPos = 0

        # Read out the magic 'SNR2'
        self.magic = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4

        idaapi.msg("info: magic: (%x)\n" % self.magic)

        # Unknown data
        self.unknown04 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown08 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown0C = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4

        # RE4 == 7409, SOCOM = ?
        # Parse out the symbol count
        self.symbolCount = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4

        # More unknowns
        self.unknown14 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown18 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown1C = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown20 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown24 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown28 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4

        # Offset to end of table, from this point on is zeros
        self.endOfTable = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        
        # More unknowns
        self.unknown30 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown34 = idaapi.get_32bit(parseEa + currentPos)
        currentPos = currentPos + 4
        self.unknown38 = idaapi.get_32bit(parseEa + currentPos)

#
# IDA Plugin implementation
#
class ps2_sndebugplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "PlayStation 2 .sndebug symbols loader"
    help = "This will parse PlayStation 2 debug symbols from the .sndebug code section"
    wanted_name = "PS2 SnDebug Symbols Loader"
    wanted_hotkey = ""

    symbolList = [ ]
    entries = [ ]

    #
    # IDA calls this on startup
    #
    def init(self):
        idaapi.msg("PlayStation 2 .sndebug symbol loader initialized\n")
        return idaapi.PLUGIN_OK
    
    #
    # This is called when the user invokes this script
    #
    def run(self, arg):
        #idaapi.msg("info: run called\n")

        info = idaapi.get_inf_structure()
        if info.is_32bit() == False:
            idaapi.msg("err: not 32-bit target\n")
            return
        
        if info.is_be():
            idaapi.msg("err: not little-endian target\n")
            return
        
        idaapi.msg("info: processor (%s)\n" % info.procName)

        # Get the required segments
        snDebugSegment = idaapi.get_segm_by_name(".sndata")
        idaapi.msg("info: .sndata segment: (0x%x)\n" % snDebugSegment.start_ea)

        textSegment = idaapi.get_segm_by_name(".text")
        idaapi.msg("info: .text segment: (0x%x)\n" % textSegment.start_ea)

        # Get the start and end ea's
        snDebugStartEa = snDebugSegment.start_ea
        snDebugEndEa = snDebugSegment.end_ea

        # Check to see if our start effective address is valid
        if snDebugStartEa is idaapi.BADADDR or snDebugEndEa is idaapi.BADADDR:
            return
        
        # read out the header
        self.header = SnDebugHeader(snDebugStartEa)
        if self.header.magic != 0x32524e53:
            idaapi.msg("err: invalid header\n")
            return
        
        # Print something useful
        symbolCount = self.header.symbolCount
        endOffset = self.header.endOfTable

        idaapi.msg("info: preparing to parse (%d) symbols... [endOffset: (%x)]\n" % (symbolCount, endOffset))
        currentPos = 60

        for _ in range(symbolCount):
            symOffset = snDebugStartEa + currentPos
            symStringData = ReadAsciiString(snDebugStartEa + currentPos)
            currentPos += len(symStringData) + 1
            #idaapi.msg("info: adding (%d) (%x) (%s)\n" % (symIndex, symOffset, symStringData))
            # Add it to our list
            self.symbolList.append(SnStringEntry(symOffset, symStringData))
        
        # Align our current position in .sndebug offset
        currentPos = Align(currentPos, 4)

        for _ in range(symbolCount):
            self.entries.append(SnDebugEntry(snDebugStartEa + currentPos))
            currentPos += 12 # skip the size of the entry
        
        for index, entry in enumerate(self.entries):
            symbol = None
            for _, sym in enumerate(self.symbolList):
                # Check if this symbol offset is equal to the symbol entry offset
                #idaapi.msg("(%x) == (%x)\n" % (sym.offset, entry.nameAddress))
                if sym.offset == entry.nameAddress:
                    #idaapi.msg("info: got sym (%x)\n" % sym.offset)
                    symbol = sym
                    break
            #
            # After we loop, check to see if we have a symbol
            if symbol is None:
                idaapi.msg("err: could not find symbol for (%d)\n" % index)
                continue
            #
            #func = idaapi.get_func(entry.targetAddress)
            #if func is None:
            #    idaapi.msg("no func (0x%x, %s)\n" % (entry.targetAddress, symbol.stringData))
            #
            #idaapi.msg("succ: set_name(0x%x, 0x%x, %s)\n" % (symbol.offset, entry.targetAddress, symbol.stringData))
            idaapi.set_name(entry.targetAddress, symbol.stringData, idaapi.SN_NOWARN)
        
        idaapi.msg("succ: label all symbols completed\n")
    
    # This is terminating the plugin
    def term(self):
        #idaapi.msg("term called\n")
        pass

#
# This is how IDA finds the entry points
#
def PLUGIN_ENTRY():
    return ps2_sndebugplugin_t()
