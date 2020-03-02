#!/usr/bin/env python

# IDA Patcher is a plugin for Hex-Ray's IDA Pro disassembler designed to
# enhance IDA's ability to patch binary files and memory. The plugin is
# useful for tasks related to malware analysis, exploit development as well
# as bug patching. IDA Patcher blends into the standard IDA user interface
# through the addition of a subview and several menu items.

IDAPATCHER_VERSION = "2.1"

# IDA libraries
import idaapi
import idautils
import idc
from idaapi import Form, Choose2, Choose, plugin_t
from keystone import *

# Python modules
import os
import shutil
import struct
import binascii

# Constants
arch_lists = {
    "X86 16-bit": (KS_ARCH_X86, KS_MODE_16),                # X86 16-bit
    "X86 32-bit": (KS_ARCH_X86, KS_MODE_32),                # X86 32-bit
    "X86 64-bit": (KS_ARCH_X86, KS_MODE_64),                # X86 64-bit
    "ARM": (KS_ARCH_ARM, KS_MODE_ARM),                      # ARM
    "ARM Thumb": (KS_ARCH_ARM, KS_MODE_THUMB),              # ARM Thumb
    "ARM64 (ARMV8)": (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN) # ARM64
}

endian_lists = {
    "Little Endian": KS_MODE_LITTLE_ENDIAN,                 # little endian
    "Big Endian": KS_MODE_BIG_ENDIAN,                       # big endian
}

syntax_lists = {
    "Intel": KS_OPT_SYNTAX_INTEL,
    "Nasm": KS_OPT_SYNTAX_NASM,
    "AT&T": KS_OPT_SYNTAX_ATT
}
    
#--------------------------------------------------------------------------
# Forms
#--------------------------------------------------------------------------
class PatchRestoreForm(Form):
    """
    Form to aid in restoring patched bytes to their original values.
    """
    def __init__(self, addr_str, fpos_str, patch_str, org_str):
        Form.__init__(self,
r"""BUTTON YES* Restore
BUTTON CANCEL Cancel
Restore patch bytes

Address        {strAddr}
File offset    {strFpos}
<:{strOrg}>
""", {
        'strAddr': Form.StringLabel(addr_str),
        'strFpos': Form.StringLabel(fpos_str),
        'strOrg': Form.MultiLineTextControl(text=org_str, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT | Form.MultiLineTextControl.TXTF_READONLY),

        })

        self.Compile()

#--------------------------------------------------------------------------
class PatchEditForm(Form):
    """
    Form to edit patched bytes.
    """
    def __init__(self, addr_str, fpos_str, patch_str, org_str):
        Form.__init__(self,
r"""Edit patch bytes

Address        {strAddr}
File offset    {strFpos}
<:{strPatch}>
""", {
        'strAddr':  Form.StringLabel(addr_str),
        'strFpos':  Form.StringLabel(fpos_str),
        'strPatch': Form.MultiLineTextControl(text=patch_str, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT),
        })

        self.Compile()

#--------------------------------------------------------------------------
class PatchApplyForm(Form):
    """
    Form to prompt for target file, backup file, and the address
    range to save patched bytes.
    """
    def __init__(self, start_ea, end_ea, org_file, bkp_file):
        Form.__init__(self,
r"""Apply patches to input file

{FormChangeCb}
<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>
<##Input file :{orgFile}>
<##Backup file:{bkpFile}>

<##Create backup:{rBackup}>
<##Restore original bytes:{rRestore}>{cGroup1}>
""", {
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),
        'orgFile': Form.FileInput(swidth=50, open=True, value=org_file),
        'bkpFile': Form.FileInput(swidth=50, open=True, value=bkp_file),
        'cGroup1': Form.ChkGroupControl(("rBackup", "rRestore")),
        'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })

        self.Compile()

    def OnFormChange(self, fid):
        # Set initial state
        if fid == -1:
            self.EnableField(self.bkpFile, False)

        # Toggle backup checkbox
        elif fid == self.rBackup.id:
            self.rBackup.checked = not self.rBackup.checked
            self.EnableField(self.bkpFile, self.rBackup.checked)

        # Toggle restore checkbox
        elif fid == self.rRestore.id:
            self.rRestore.checked = not self.rRestore.checked

        return 1

#--------------------------------------------------------------------------
class PatchFillForm(Form):
    """
    Form to fill a range of addresses with a specified byte value.
    """
    def __init__(self, start_ea, end_ea, fill_value):

        Form.__init__(self,
r"""BUTTON YES* Fill
Fill bytes

<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>
<##Value      :{intPatch}>
""", {
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),
        'intPatch': Form.NumericInput(swidth=40,tp=Form.FT_HEX,value=fill_value),
        })

        self.Compile()

#--------------------------------------------------------------------------
class PatchExportForm(Form):
    """
    Form to fill a range of addresses with a specified byte value.
    """
    def __init__(self):

        Form.__init__(self,
r"""BUTTON YES* Export
Export patches

<Export path:{expPath}>
""", {
        'expPath': Form.DirInput(swidth=50, value=os.path.dirname(get_input_file_path()))
        })

        self.Compile()

#--------------------------------------------------------------------------
class PatchImportForm(Form):
    """
    Form to fill a range of addresses with a specified byte value.
    """
    def __init__(self):
        self.chooser = EmbeddedChooser()
        self.valid_patches = []
        self.selected_idx = []
        Form.__init__(self,
r"""BUTTON YES* Done
Import patches

<Loaded patches:{cChooser}>
<Import path:{impPath}>
<Import:{btnImport}><Patch select:{btnSelPatch}><Patch all:{btnPatch}>
""", {
        'impPath': Form.FileInput(swidth=60, open=True, value=get_input_file_path()+'.idapatch'),
        'cChooser': Form.EmbeddedChooserControl(self.chooser, swidth=71),
        'btnImport': Form.ButtonInput(self.OnImportClick),
        'btnSelPatch': Form.ButtonInput(self.OnPatchClick),
        'btnPatch': Form.ButtonInput(self.OnPatchClick, code=1)
        })
        self.Compile()

    def OnImportClick(self, code):
        imp_path = self.GetControlValue(self.impPath)
        imp_data = []
        with open(imp_path, 'rb') as imp_file:
            imp_data = pickle.load(imp_file)

        # check correctness first
        view_patches = []
        for patch in imp_data:
            var_name, offset, length, patch_val, org_val, comments = patch
            if not var_name:
                print '[Warning] Unable to parse patch without symbol', patch[:3]
                continue

            var_addr = idc.get_name_ea_simple(var_name)
            if var_addr == idc.BADADDR:
                print '[Warning] Unable to find symbol', patch[:3]
                continue

            ea = var_addr + offset
            seg = SegName(ea)
            name = idc.Demangle(var_name, idc.GetLongPrm(idc.INF_SHORT_DN)) or var_name
            name = "{}: {}".format(seg, name)

            byte_str = idaapi.get_bytes(ea, length)
            org_str = struct.pack("B"*length, *org_val)
            patch_str = struct.pack("B"*length, *patch_val)

            if byte_str == org_str:
                self.valid_patches.append((ea, length, patch_val, comments))
                view_patches.append([
                    name,
                    "{:04X}".format(offset),
                    str(length),
                    " ".join(map(lambda n: "{:02X}".format(n), patch_val)),
                    " ".join(map(lambda n: "{:02X}".format(n), org_val)),
                    comments
                ])
            elif byte_str == patch_str:
                print '[Notice] Patched bytes', patch[:3]
            else:
                print '[Warning] Dropping patch with different origin value', patch[:3]

        self.chooser.SetItems(view_patches)
        self.RefreshField(self.cChooser)

    def OnPatchClick(self, code):
        patches = []

        if code == 1:
            patches = self.valid_patches
            view_patches = []
        else:
            idx = self.chooser.GetSelectedLine()
            patches = [self.valid_patches[i] for i in idx]
            view_patches = [self.chooser.items[i] for i in range(len(self.chooser.items)) if i not in idx]

        for ea, length, patch_val, comments in patches:
            idaapi.patch_many_bytes(ea, struct.pack("B"*length, *patch_val))
            MakeComm(to_var_base(ea), comments)

        self.chooser.SetItems(view_patches)
        self.RefreshField(self.cChooser)

#--------------------------------------------------------------------------
class DataImportForm(Form):
    """
    Form to import data of various types into selected area.
    """

    def __init__(self, start_ea, end_ea):
        syntax_keys = dict_to_ordered_list(syntax_lists)[0]
        syntax_id = find_idx_by_value(syntax_lists, KS_OPT_SYNTAX_INTEL)

        Form.__init__(self,
r"""BUTTON YES* Import
Import data

{FormChangeCb}
<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>

Import type:                    Patching options:
<hex string:{rHex}><##Trim to selection:{cSize}>{cGroup}>
<assembly:{rAsm}>
<string literal:{rString}>
<binary file:{rFile}>{rGroup}>

<Syntax\::{cSyntax}>
<:{strPatch}>
<##Import BIN file:{impFile}>
""", {
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),

        'cGroup': Form.ChkGroupControl(("cSize",)),
        'rGroup': Form.RadGroupControl(("rHex", "rAsm", "rString", "rFile")),
        'cSyntax': Form.DropdownListControl(
            items = syntax_keys,
            readonly = True,
            selval = syntax_id
        ),
        'strPatch': Form.MultiLineTextControl(swidth=80, flags=Form.MultiLineTextControl.TXTF_FIXEDFONT),
        'impFile': Form.FileInput(swidth=50, open=True),

        'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })
        self.arch, _ = get_hardware_mode()
        self.Compile()

    def OnFormChange(self, fid):
        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.strPatch)
            self.EnableField(self.strPatch, True)
            self.EnableField(self.impFile, False)

            if self.arch != KS_ARCH_X86:
                self.ShowField(self.cSyntax, False)
            else:
                self.EnableField(self.cSyntax, False)

        # Form OK pressed
        elif fid == -2:
            pass

        # Form from text box
        elif fid in (self.rHex.id, self.rAsm.id, self.rString.id):
            if fid == self.rAsm.id and self.arch == KS_ARCH_X86:
                self.EnableField(self.cSyntax, True)

            self.SetFocusedField(self.strPatch)
            self.EnableField(self.strPatch, True)
            self.EnableField(self.impFile, False)

        # Form import from file
        elif fid == self.rFile.id:
            self.SetFocusedField(self.rFile)
            self.EnableField(self.impFile, True)
            self.EnableField(self.strPatch, False)

        return 1

#--------------------------------------------------------------------------
class CommentEditForm(Form):
    """
    Form to edit patched bytes.
    """
    def __init__(self, comment):
        Form.__init__(self,
r"""Edit comment
<:{strComment}>
""", {  # how to set fixed width ?
        'strComment': Form.MultiLineTextControl(width=280, text=comment, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT)
        })

        self.Compile()

#--------------------------------------------------------------------------
# Helper functions
#--------------------------------------------------------------------------
def to_var_base(ea):
    return idaapi.get_item_head(ea)

def prepare_export_data(patches):
    export_data = []

    for (ea, fpos, len, patch_val, org_val, comments) in patches:
        var_name = GetFunctionName(ea) or Name(to_var_base(ea))
        base = idc.get_name_ea_simple(var_name)
        offset = ea - base

        if offset < 0:
            print '[Error] Got negative offset:', ea, fpos, len, org_val, patch_val, comments
            return None

        if var_name:
            export_data.append([var_name, offset, len, patch_val, org_val, comments])
        else:
            print '[Warning] Cannot find variable name:', ea, fpos, len, org_val, patch_val, comments

    return export_data

def dict_to_ordered_list(dictionary):
    l = sorted(list(dictionary.items()), key=lambda t: t[0], reverse=False)
    keys = [i[0] for i in l]
    values = [i[1] for i in l]

    return (keys, values)

def get_value_by_idx(dictionary, idx, default=None):
    (keys, values) = dict_to_ordered_list(dictionary)

    try:
        val = values[idx]
    except IndexError:
        val = default

    return val

def find_idx_by_value(dictionary, value, default=None):
    (keys, values) = dict_to_ordered_list(dictionary)

    try:
        idx = values.index(value)
    except:
        idx = default

    return idx
    
def check_address(address):
    try:
        if idaapi.is_mapped(address):
            return 1
        else:
            return -1
    except:
        # invalid type
        return 0

def get_hardware_mode():
    (arch, mode) = (None, None)

    # heuristically detect hardware setup
    info = idaapi.get_inf_structure()
    
    try:
        cpuname = info.procname.lower()
    except:
        cpuname = info.procName.lower()

    try:
        # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
        is_be = idaapi.cvar.inf.is_be()
    except:
        # older IDA versions
        is_be = idaapi.cvar.inf.mf
    # print("Keypatch BIG_ENDIAN = %s" %is_be)
    
    if cpuname == "metapc":
        arch = KS_ARCH_X86
        if info.is_64bit():
            mode = KS_MODE_64
        elif info.is_32bit():
            mode = KS_MODE_32
        else:
            mode = KS_MODE_16
    elif cpuname.startswith("arm"):
        # ARM or ARM64
        if info.is_64bit():
            arch = KS_ARCH_ARM64
            if is_be:
                mode = KS_MODE_BIG_ENDIAN
            else:
                mode = KS_MODE_LITTLE_ENDIAN
        else:
            arch = KS_ARCH_ARM
            # either big-endian or little-endian
            if is_be:
                mode = KS_MODE_ARM | KS_MODE_BIG_ENDIAN
            else:
                mode = KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN
    elif cpuname.startswith("sparc"):
        arch = KS_ARCH_SPARC
        if info.is_64bit():
            mode = KS_MODE_SPARC64
        else:
            mode = KS_MODE_SPARC32
        if is_be:
            mode |= KS_MODE_BIG_ENDIAN
        else:
            mode |= KS_MODE_LITTLE_ENDIAN
    elif cpuname.startswith("ppc"):
        arch = KS_ARCH_PPC
        if info.is_64bit():
            mode = KS_MODE_PPC64
        else:
            mode = KS_MODE_PPC32
        if cpuname == "ppc":
            # do not support Little Endian mode for PPC
            mode += KS_MODE_BIG_ENDIAN
    elif cpuname.startswith("mips"):
        arch = KS_ARCH_MIPS
        if info.is_64bit():
            mode = KS_MODE_MIPS64
        else:
            mode = KS_MODE_MIPS32
        if is_be:
            mode |= KS_MODE_BIG_ENDIAN
        else:
            mode |= KS_MODE_LITTLE_ENDIAN
    elif cpuname.startswith("systemz") or cpuname.startswith("s390x"):
        arch = KS_ARCH_SYSTEMZ
        mode = KS_MODE_BIG_ENDIAN

    return (arch, mode)

# return (encoding, count), or (None, 0) on failure
def assemble(assembly, address, arch, mode, syntax=None):

    # return assembly with arithmetic equation evaluated
    def eval_operand(assembly, start, stop, prefix=''):
        imm = assembly[start+1:stop]
        try:
            eval_imm = eval(imm)
            if eval_imm > 0x80000000:
                eval_imm = 0xffffffff - eval_imm
                eval_imm += 1
                eval_imm = -eval_imm
            return assembly.replace(prefix + imm, prefix + hex(eval_imm))
        except:
            return assembly

    # IDA uses different syntax from Keystone
    # sometimes, we can convert code to be consumable by Keystone
    def fix_ida_syntax(assembly):

        # return True if this insn needs to be fixed
        def check_arm_arm64_insn(arch, mnem):
            if arch == KS_ARCH_ARM:
                if mnem.startswith("ldr") or mnem.startswith("str"):
                    return True
                return False
            elif arch == KS_ARCH_ARM64:
                if mnem.startswith("ldr") or mnem.startswith("str"):
                    return True
                return mnem in ("stp")
            return False

        # return True if this insn needs to be fixed
        def check_ppc_insn(mnem):
            return mnem in ("stw")

        # replace the right most string occurred
        def rreplace(s, old, new):
            li = s.rsplit(old, 1)
            return new.join(li)

        # convert some ARM pre-UAL assembly to UAL, so Keystone can handle it
        # example: streqb --> strbeq
        def fix_arm_ual(mnem, assembly):
            # TODO: this is not an exhaustive list yet
            if len(mnem) != 6:
                return assembly

            if (mnem[-1] in ('s', 'b', 'h', 'd')):
                #print(">> 222", mnem[3:5])
                if mnem[3:5] in ("cc", "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"):
                    return assembly.replace(mnem, mnem[:3] + mnem[-1] + mnem[3:5], 1)

            return assembly

        if arch != KS_ARCH_X86:
            assembly = assembly.lower()
        else:
            # Keystone does not support immediate 0bh, but only 0Bh
            assembly = assembly.upper()

        # however, 0X must be converted to 0x
        # Keystone should fix this limitation in the future
        assembly = assembly.replace("0X", " 0x")

        _asm = assembly.partition(' ')
        mnem = _asm[0]
        if mnem == '':
            return assembly

        # for PPC, Keystone does not accept registers with 'r' prefix,
        # but only the number behind. lets try to fix that here by
        # removing the prefix 'r'.
        if arch == KS_ARCH_PPC:
            for n in range(32):
                r = " r%u," %n
                if r in assembly:
                    assembly = assembly.replace(r, " %u," %n)
            for n in range(32):
                r = "(r%u)" %n
                if r in assembly:
                    assembly = assembly.replace(r, "(%u)" %n)
            for n in range(32):
                r = ", r%u" %n
                if assembly.endswith(r):
                    assembly = rreplace(assembly, r, ", %u" %n)

        if arch == KS_ARCH_X86:
            if mnem == "RETN":
                # replace retn with ret
                return assembly.replace('RETN', 'RET', 1)
            if 'OFFSET ' in assembly:
                return assembly.replace('OFFSET ', ' ')
            if mnem in ('CALL', 'JMP') or mnem.startswith('LOOP'):
                # remove 'NEAR PTR'
                if ' NEAR PTR ' in assembly:
                    return assembly.replace(' NEAR PTR ', ' ')
            elif mnem[0] == 'J':
                # JMP instruction
                if ' SHORT ' in assembly:
                    # remove ' short '
                    return assembly.replace(' SHORT ', ' ')
        elif arch in (KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_PPC):
            # *** ARM
            # LDR     R1, [SP+rtld_fini],#4
            # STR     R2, [SP,#-4+rtld_fini]!
            # STR     R0, [SP,#fini]!
            # STR     R12, [SP,#4+var_8]!

            # *** ARM64
            # STP     X29, X30, [SP,#-0x10+var_150]!
            # STR     W0, [X29,#0x150+var_8]
            # LDR     X0, [X0,#(qword_4D6678 - 0x4D6660)]
            # TODO:
            # ADRP    X19, #interactive@PAGE

            # *** PPC
            # stw     r5, 0x120+var_108(r1)

            if arch == KS_ARCH_ARM and mode == KS_MODE_THUMB:
                assembly = assembly.replace('movt.w', 'movt')

            if arch == KS_ARCH_ARM:
                #print(">> before UAL fix: ", assembly)
                assembly = fix_arm_ual(mnem, assembly)
                #print(">> after UAL fix: ", assembly)

            if check_arm_arm64_insn(arch, mnem) or (("[" in assembly) and ("]" in assembly)):
                bang = assembly.find('#')
                bracket = assembly.find(']')
                if bang != -1 and bracket != -1 and bang < bracket:
                    return eval_operand(assembly, bang, bracket, '#')
                elif '+0x0]' in assembly:
                    return assembly.replace('+0x0]', ']')
            elif check_ppc_insn(mnem):
                start = assembly.find(', ')
                stop = assembly.find('(')
                if start != -1 and stop != -1 and start < stop:
                    return eval_operand(assembly, start, stop)
        return assembly

    def is_thumb(address):
        return get_sreg(address, 'T') == 1

    if check_address(address) == 0:
        return (None, 0)

    if arch == KS_ARCH_ARM and is_thumb(address):
        mode = KS_MODE_THUMB

    try:
        ks = Ks(arch, mode)
        if arch == KS_ARCH_X86:
            ks.syntax = syntax
        encoding, count = ks.asm(fix_ida_syntax(assembly), address)
    except KsError as e:
        # keep the below code for debugging
        #print("Keypatch Error: {0}".format(e))
        #print("Original asm: {0}".format(assembly))
        #print("Fixed up asm: {0}".format(fix_ida_syntax(assembly)))
        encoding, count = None, 0

    return (encoding, count)

#--------------------------------------------------------------------------
# Chooser
#--------------------------------------------------------------------------
class EmbeddedChooser(Choose):
    """
    Chooser class embedded in import form.
    """
    def __init__(self):
        Choose.__init__(self,
                         "Import",
                         [ ["Name",     18 | Choose2.CHCOL_PLAIN],
                           ["Offset",    5 | Choose2.CHCOL_HEX],
                           ["Size",      4 | Choose2.CHCOL_DEC],
                           ["Patched",  10 | Choose2.CHCOL_HEX],
                           ["Original", 10 | Choose2.CHCOL_HEX],
                           ["Comment",  20 | Choose2.CHCOL_PLAIN]
                         ],
                         flags = Choose2.CH_MULTI, width=30, height=18, embedded=True)

        self.icon = 47
        self.items = []
        self.selected_idx = []

    def SetItems(self, items):
        self.items = items
        self.Refresh()

    def GetSelectedLine(self):
        return self.selected_idx

    def OnGetSize(self):
        return len(self.items)

    def OnSelectionChange(self, idx):
        self.selected_idx = idx

    def OnRefresh(self, idx):
        pass

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

class PatchView(Choose2):
    """
    Chooser class to display and manage patched bytes in the database.
    """
    def __init__(self):
        Choose2.__init__(self,
                         "IDA Patcher",
                         [ ["Address",  15 | Choose2.CHCOL_HEX],
                           ["Name",     18 | Choose2.CHCOL_PLAIN],
                           ["Size",      4 | Choose2.CHCOL_DEC],
                           ["Patched",  10 | Choose2.CHCOL_HEX],
                           ["Original", 10 | Choose2.CHCOL_HEX],
                           ["Comment",  30 | Choose2.CHCOL_PLAIN]
                         ],
                         flags = Choose2.CH_MULTI_EDIT)

        self.popup_names = ["Import patches", "Delete", "Edit", "Refresh"]
        self.icon = 47

        # Items for display and corresponding data
        # NOTE: Could become desynchronized, so to avoid this
        #       refresh the view after each change.
        self.items = []
        self.items_data  = []

        # Initialize/Refresh the view
        self.refreshitems()
        self.Refresh()

        # Data members
        self.patch_file = None
        self.restore = False

        # Command callbacks
        self.cmd_apply_patches = None
        self.cmd_restore_bytes = None
        self.cmd_edit_comments = None
        self.cmd_export_patches = None

    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

        # Add extra context menu commands
        # NOTE: Make sure you check for duplicates.
        if self.cmd_apply_patches == None:
            self.cmd_apply_patches = self.AddCommand("Apply patches to input file", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_NO_SELECTION, icon=27)
        if self.cmd_restore_bytes == None:
            self.cmd_restore_bytes = self.AddCommand("Restore original byte(s)", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=139)
        if self.cmd_edit_comments == None:
            self.cmd_edit_comments = self.AddCommand("Edit comments", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=47)
        if self.cmd_export_patches == None:
            self.cmd_export_patches = self.AddCommand("Export patches", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=27)

        return True

    # Patch byte visitor callback to apply the patches
    # NOTE: Only bytes with fpos > -1 can be applied.
    def apply_patch_byte(self, ea, fpos, org_val, patch_val):
        if fpos != -1:
            self.patch_file.seek(fpos)

            if self.restore:
                self.patch_file.write(struct.pack('B', org_val))
            else:
                self.patch_file.write(struct.pack('B', patch_val))

        return 0

    # Patch byte visitor callback to collect and aggregate bytes
    def get_patch_byte(self, ea, fpos, org_val, patch_val):

        # Aggregate contiguous bytes (base ea + length)
        # NOTE: Looking at the last item [-1] is sufficient
        #       since we are dealing with sorted data.
        if len(self.items_data) and (ea - self.items_data[-1][0] == self.items_data[-1][2]):

            # Increment length
            self.items_data[-1][2] += 1
            self.items[-1][2] = str(self.items_data[-1][2])

            # Append patched bytes
            self.items_data[-1][3].append(patch_val)
            self.items[-1][3] = " ".join(["%02X" % x for x in self.items_data[-1][3]])

            # Append original bytes
            self.items_data[-1][4].append(org_val)
            self.items[-1][4] =  " ".join(["%02X" % x for x in self.items_data[-1][4]])


        # Add new patch byte to the list
        else:

            seg = SegName(ea)
            name = GetFunctionName(ea) or Name(to_var_base(ea)) or ''
            name = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN)) or name
            name = "%s: %s" % (seg, name)

            # we dont need repeated comment
            comment = Comment(ea) or ""

            # DATA STORAGE FORMAT:       address, function / fpos, len,    patched byte(s), original byte(s),  comments
            self.items.append(     ["%016X" % ea,            name, "1", "%02X" % patch_val, "%02X" % org_val,   comment])
            self.items_data.append([          ea,            fpos,   1,        [patch_val],        [org_val],   comment])

        return 0

    def refreshitems(self):
        self.items_data = []
        self.items = []
        idaapi.visit_patched_bytes(0, idaapi.BADADDR, self.get_patch_byte)

    def OnCommand(self, n, cmd_id):
        # Apply patches to a file
        if cmd_id == self.cmd_apply_patches:

            # Set initial start/end EA values
            start_ea = 0x0
            end_ea = idaapi.cvar.inf.maxEA

            # Set initial output file values
            org_file = GetInputFilePath()
            bkp_file = "%s.bak" % org_file

            # Create the form
            f = PatchApplyForm(start_ea, end_ea, org_file, bkp_file)

            # Execute the form
            ok = f.Execute()
            if ok == 1:
                # Get restore checkbox
                self.restore = f.rRestore.checked

                # Get updated ea max/min
                start_ea = f.intStartEA.value
                end_ea = f.intEndEA.value

                # Get updated file path
                new_org_file = f.orgFile.value

                # Backup the file before replacing
                if f.rBackup.checked:
                    bkp_file = f.bkpFile.value
                    shutil.copyfile(org_file, bkp_file)

                # Apply patches
                try:
                    self.patch_file = open(new_org_file,'rb+')
                except Exception, e:
                    idaapi.warning("Cannot update file '%s'" % new_org_file)
                else:
                    r = idaapi.visit_patched_bytes(start_ea, end_ea, self.apply_patch_byte)
                    self.patch_file.close()
                    self.restore = False

                    # Update db input file, so we are working
                    # with a patched version.
                    #if not org_file == new_org_file:
                    #    idaapi.set_root_filename(new_org_file)
                    #    org_file = new_org_file

            # Dispose the form
            f.Free()

        # Restore selected byte(s)
        elif cmd_id == self.cmd_restore_bytes:

            # List start/end
            if n == -2 or n ==-3:
                return

            elif not len(self.items) > 0:
                idaapi.warning("There are no patches to restore.")
                return

            # Nothing selected
            elif n == -1:
                idaapi.warning("Please select bytes to restore.")
                return

            ea = self.items_data[n][0]
            fpos =  self.items_data[n][1]
            buf = self.items_data[n][4]

            addr_str = "%#x" % ea
            fpos_str = "%#x" % fpos if fpos != -1 else "N/A"
            patch_str = self.items[n][3]
            org_str = self.items[n][4]

            # Create the form
            f = PatchRestoreForm(addr_str, fpos_str, patch_str, org_str)

            # Execute the form
            ok = f.Execute()
            if ok == 1:

                # Restore original bytes
                idaapi.patch_many_bytes(ea, struct.pack("B"*len(buf), *buf))

                # Refresh all IDA views
                self.Refresh()

            # Dispose the form
            f.Free()

        elif cmd_id == self.cmd_edit_comments:
            # List start/end
            if n == -2 or n ==-3:
                return
            elif not len(self.items) > 0:
                return
            # Nothing selected
            elif n == -1:
                return

            ea = self.items_data[n][0]
            fpos =  self.items_data[n][1]
            comment = Comment(ea)

            # Create the form
            f = CommentEditForm(comment)

            # Execute the form
            ok = f.Execute()
            if ok == 1:

                # Get edited comment value
                buf = f.strComment.value

                # make comment in the middle of instruction could fail
                # -> switch ea to the start of instruction
                MakeComm(to_var_base(ea), buf)

                # Refresh all IDA views
                self.Refresh()

            # Dispose the form
            f.Free()

        elif cmd_id == self.cmd_export_patches:
            if not len(self.items) > 0:
                return

            # Create the form
            f = PatchExportForm()

            # Execute the form
            ok = f.Execute()
            if ok == 1:
                exp_path = f.expPath.value
                if not os.path.isdir(exp_path):
                    exp_path = os.path.dirname(exp_path)

                exp_path = os.path.join(exp_path, get_root_filename() + '.idapatch')
                exp_data = prepare_export_data(self.items_data)

                if exp_data:
                    with open(exp_path, 'wb+') as exp_file:
                        pickle.dump(exp_data, exp_file)
                else:
                    print '[Error] Patch export failed'

                # Refresh all IDA views
                self.Refresh()

            # Dispose the form
            f.Free()

        return

    def OnClose(self):
        self.cmd_apply_patches = None
        self.cmd_restore_bytes = None
        self.cmd_edit_comments = None
        self.cmd_export_patches = None
        self.cmd_import_patches = None

    def OnEditLine(self, n):

        # Empty list
        if n == -1:
            return

        # Multiselect START_SEL/END_SEL protocol
        if n == -2 or n ==-3:
            return

        ea = self.items_data[n][0]
        fpos =  self.items_data[n][1]
        patch_buf = self.items_data[n][3]
        orig_buf = self.items_data[n][4]

        addr_str = "%#x" % ea
        fpos_str = "%#x" % fpos if fpos != -1 else "N/A"
        patch_str = self.items[n][3]
        org_str = self.items[n][4]

        # Create the form
        f = PatchEditForm(addr_str, fpos_str, patch_str, org_str)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Convert hex bytes to binary
            buf = f.strPatch.value
            buf = buf.replace(' ','')       # remove spaces
            buf = buf.replace('\\x','')     # remove '\x' prefixes
            buf = buf.replace('0x','')      # remove '0x' prefixes
            try:
                buf = binascii.unhexlify(buf)   # convert to bytes
            except Exception, e:
                idaapi.warning("Invalid input: %s" % e)
                f.Free()
                return

            # Restore original bytes first
            idaapi.patch_many_bytes(ea, struct.pack("B"*len(orig_buf), *orig_buf))

            # Now apply newly patched bytes
            idaapi.patch_many_bytes(ea, buf)

            # Refresh all IDA views
            self.Refresh()

        # Dispose the form
        f.Free()

    # Because the shitty design of is_chooser, we cannot invoke OnCommand while the list is empty,
    # otherwise we got python out-of-bound access Exception
    def OnInsertLine(self):
        # Create the form
        f = PatchImportForm()

        # Execute the form
        ok = f.Execute()
        self.Refresh()

        # Dispose the form
        f.Free()

    def OnSelectLine(self, n):
        idaapi.jumpto(self.items_data[n][0])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):

        # Empty list
        if not len(self.items) > 0:
            return -1

        else:
            return 47

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()

    def OnActivate(self):
        self.Refresh()


#--------------------------------------------------------------------------
# Handler
#--------------------------------------------------------------------------
class RunHandler(idaapi.action_handler_t):
    def __init__(self, func, args):
        idaapi.action_handler_t.__init__(self)
        self.func = func
        self.args = args

    def activate(self, ctx):
        self.func(*self.args)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

#--------------------------------------------------------------------------
# Manager
#--------------------------------------------------------------------------
class PatchManager():
    """ Class that manages GUI forms and patching methods of the plugin. """

    def __init__(self):
        self.addmenu_item_ctxs = list()
        self.patch_view = PatchView()
        self.arch, self.mode = get_hardware_mode()

    #--------------------------------------------------------------------------
    # Menu Items
    #--------------------------------------------------------------------------
    def add_menu_item_helper(self, action_name, menupath, text, hotkey, flags, pyfunc, args):

        action = idaapi.action_desc_t(
            action_name,                # The action name. This acts like an ID and must be unique
            text,                       # The action text.
            RunHandler(pyfunc, args),   # The action handler.
            hotkey,                     # Optional: the action shortcut
            None                        # Optional: the action tooltip (available in menus/toolbar)
        )
        idaapi.register_action(action)
        check = idaapi.attach_action_to_menu(
            menupath,                # The relative path of where to add the action
            action_name,             # The action ID
            flags)

        if check is None:
            return 1
        else:
            self.addmenu_item_ctxs.append((menupath, action_name))
            return 0

    def add_menu_items(self):

        if self.add_menu_item_helper("idapatcher:patches", "View/Open subviews/", "Patched bytes view", "Ctrl-Alt-P", 1, self.show_patches_view, []):
            return 1
        if self.add_menu_item_helper("idapatcher:edit", "Edit/Patch program/", "Edit selection...", "", 0, self.show_edit_form, []):
            return 1
        if self.add_menu_item_helper("idapatcher:fill", "Edit/Patch program/", "Fill selection...", "", 0, self.show_fill_form, []):
            return 1
        if self.add_menu_item_helper("idapatcher:import", "Edit/Patch program/", "Import data...", "Shift-I", 1, self.show_import_form, []):
            return 1

        return 0

    def del_menu_items(self):
        for menupath, action_name in self.addmenu_item_ctxs:
            idaapi.detach_action_from_menu(menupath, action_name)

    #--------------------------------------------------------------------------
    # View Callbacks
    #--------------------------------------------------------------------------

    # Patches View
    def show_patches_view(self):
        self.patch_view.show()

    # Patches Edit Dialog
    def show_edit_form(self):
        selection, start_ea, end_ea = idaapi.read_selection()

        if not selection:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        buf_len = end_ea - start_ea
        buf = idaapi.get_many_bytes(start_ea, buf_len) or "\xFF"*buf_len
        buf_str = " ".join(["%02X" % ord(x) for x in buf])

        fpos = idaapi.get_fileregion_offset(start_ea)

        addr_str = "%#x" % start_ea
        fpos_str = "%#x" % fpos if fpos != -1 else "N/A"

        f = PatchEditForm(addr_str, fpos_str, buf_str, buf_str)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Convert hex bytes to binary
            buf = f.strPatch.value
            buf = buf.replace(' ','')       # remove spaces
            buf = buf.replace('\\x','')     # remove '\x' prefixes
            buf = buf.replace('0x','')      # remove '0x' prefixes
            try:
                buf = binascii.unhexlify(buf)   # convert to bytes
            except Exception, e:
                idaapi.warning("Invalid input: %s" % e)
                f.Free()
                return

            # Now apply newly patched bytes
            idaapi.patch_many_bytes(start_ea, buf)

            # Refresh all IDA views
            self.patch_view.Refresh()

        # Dispose the form
        f.Free()

    # Fill range with a value form
    def show_fill_form(self):
        selection, start_ea, end_ea = idaapi.read_selection()

        if not selection:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        # Default fill value
        fill_value = 0x00

        # Create the form
        f = PatchFillForm(start_ea, end_ea, fill_value)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Get updated values
            start_ea = f.intStartEA.value
            end_ea = f.intEndEA.value
            fill_value = f.intPatch.value

            # Now apply newly patched bytes
            # NOTE: fill_value is expected to be one byte
            #       so if a user provides a larger patch_byte()
            #       will trim the value as expected.


            for ea in range(start_ea, end_ea):
                idaapi.patch_byte(ea, fill_value)

            # Refresh all IDA views
            self.patch_view.Refresh()

        # Dispose the form
        f.Free()

    # Import data form
    def show_import_form(self):
        selection, start_ea, end_ea = idaapi.read_selection()

        if not selection:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        # Create the form
        f = DataImportForm(start_ea, end_ea);

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            start_ea = f.intStartEA.value
            end_ea = f.intEndEA.value

            if f.rFile.selected:
                imp_file = f.impFile.value

                try:
                    f_imp_file = open(imp_file,'rb')
                except Exception, e:
                    idaapi.warning("File I/O error({0}): {1}".format(e.errno, e.strerror))
                    return
                else:
                    buf = f_imp_file.read()
                    f_imp_file.close()

            elif f.rAsm.selected:
                assembly = f.strPatch.value
                syntax = get_value_by_idx(syntax_lists, f.cSyntax.value)

                output, count = assemble(assembly, start_ea, self.arch, self.mode, syntax)              
                if not (output and count):
                    idaapi.warning("Compilation failed.")
                    f.Free()
                    return

                buf = struct.pack("B"*len(output), *output)

            else:
                buf = f.strPatch.value

                # Hex values, unlike string literal, needs additional processing
                if f.rHex.selected:
                    buf = buf.replace(' ','')       # remove spaces
                    buf = buf.replace('\\x','')     # remove '\x' prefixes
                    buf = buf.replace('0x','')      # remove '0x' prefixes
                    try:
                        buf = binascii.unhexlify(buf)   # convert to bytes
                    except Exception, e:
                        idaapi.warning("Invalid input: %s" % e)
                        f.Free()
                        return

            if not len(buf):
                idaapi.warning("There was nothing to import.")
                f.Free()
                return

            # Trim to selection if needed:
            if f.cSize.checked:
                buf_size = end_ea - start_ea
                buf = buf[0:buf_size]

            # Now apply newly patched bytes
            try:
                idaapi.patch_many_bytes(start_ea, buf)
            except Exception:
                print 'Patch failure'
                pass
                
            # Refresh all IDA views
            self.patch_view.Refresh()

        # Dispose the form
        f.Free()

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class idapatcher_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "Enhances manipulation and application of patched bytes."
    help = "Enhances manipulation and application of patched bytes."
    wanted_name = "IDA Patcher"
    wanted_hotkey = ""

    def init(self):
        global idapatcher_manager

        # Check if already initialized
        if not 'idapatcher_manager' in globals():

            idapatcher_manager = PatchManager()
            if idapatcher_manager.add_menu_items():
                print "Failed to initialize IDA Patcher."
                idapatcher_manager.del_menu_items()
                del idapatcher_manager
                return idaapi.PLUGIN_SKIP
            else:
                print("Initialized IDA Patcher v%s" % IDAPATCHER_VERSION)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global idapatcher_manager
        idapatcher_manager.show_patches_view()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return idapatcher_t()

#--------------------------------------------------------------------------
# Script / Testing
#--------------------------------------------------------------------------
def idapatcher_main():
    global idapatcher_manager

    if 'idapatcher_manager' in globals():
        idapatcher_manager.del_menu_items()
        del idapatcher_manager

    idapatcher_manager = PatchManager()
    idapatcher_manager.add_menu_items()
    idapatcher_manager.show_patches_view()

if __name__ == '__main__':
    #idapatcher_main()
    pass
