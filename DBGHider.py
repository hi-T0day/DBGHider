#---------------------------------------------------------------------
# IDA Windows Debuger Hider
#
# Auther: iweizime
#
# This IDA plugin aims to hide IDA Windows Debuger from the
# processes being debugged.
#
#---------------------------------------------------------------------

import idaapi
import idc
import keystone
import os
import __main__

NtClose_inline_hook_code_32 = """
    mov eax, [esp + 4]
    cmp eax, 0x1000
    jl jmp_back
    xor eax, eax
    ret 4
jmp_back:
"""

NtQueryInformationProcess_inline_hook_code_32 = """
    mov eax, [esp + 8]
    cmp eax, 7
    je debug_port
    cmp eax, 30
    je debug_object_handle
    jmp jmp_back
debug_port:
    mov eax, [esp + 12]
    xor edx, edx
    mov [eax], edx
    xor eax, eax
    ret 20
debug_object_handle:
    mov eax, [esp + 12]
    xor edx, edx
    mov [eax], edx
    mov edx, 4
    mov eax, [esp + 20]
    mov [eax], edx
    xor eax, eax
    ret 20
jmp_back:
"""

NtClose_bpt_cond_hook_code_32 = """
import idautils
import idaapi
handle = idaapi.get_dword(idautils.cpu.esp + 4)
if handle >= 0x1000:
    ret_addr = idaapi.get_dword(idautils.cpu.esp)
    idautils.cpu.eax = 0
    idautils.cpu.esp = idautils.cpu.esp + 8
    idautils.cpu.eip = ret_addr
return False
"""

NtQueryInformationProcess_bpt_cond_hook_code_32 = """
import idautils
import idaapi
import idc

ret_addr = idaapi.get_dword(cpu.esp)
process_handle = idaapi.get_dword(cpu.esp + 4)
process_information_class = idaapi.get_dword(cpu.esp + 8)
process_information = idaapi.get_dword(cpu.esp + 12)
process_information_length = idaapi.get_dword(cpu.esp + 16)
return_length = idaapi.get_dword(cpu.esp + 20)

if process_information_class == 7:
    idc.patch_dword(process_information, 0)

    idautils.cpu.eax = 0
    idautils.cpu.esp = idautils.cpu.esp + 24
    idautils.cpu.eip = ret_addr
elif process_information_class == 30:
    idc.patch_dword(process_information, 0)
    idc.patch_dword(return_length, 4)

    idautils.cpu.eax = 0
    idautils.cpu.esp = idautils.cpu.esp + 24
    idautils.cpu.eip = ret_addr
return False
"""

def assemble(code, addr = 0, mode = keystone.KS_MODE_32):
    """
    assemble asm code for inline hook
    """

    ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
    encoding, count = ks.asm(code, addr)
    buf = ''.join(chr(c) for c in encoding)
    return buf, count

class FuncHook():
    def __init__(self, name, inline_hook_code, bpt_cond_hook_code):
        self.name = name
        self.inline_hook_code = inline_hook_code
        self.bpt_cond_hook_code = bpt_cond_hook_code

    def hook(self, hook_addr = 0):
        """
        Args:
            hook_addr(int): address for inline hook code, 0 indicates bpt hook.

        Returns:
            memory size in bytes used for inline hook.
        """

        self.hook_addr = hook_addr
        self.func_addr = idc.get_name_ea_simple(self.name)

        if self.func_addr == 0:
            return 0

        print("Hooking %s at 0x%x" % (self.name, self.func_addr))
        if self.hook_addr == 0:
            idc.add_bpt(self.func_addr)
            idc.set_bpt_cond(self.func_addr, self.bpt_cond_hook_code)
            return 0
        else:
            # assemble jmp code
            jmp_code = "jmp 0x%x" % self.hook_addr
            jmp_buf, _ = assemble(jmp_code, self.func_addr)

            # read function prologue according to jmp code length
            # NOTE: instructions like 'call $+5' in prologue will
            # cause problems.
            insn = idaapi.insn_t()
            move_length = 0
            while move_length < len(jmp_buf):
                idaapi.decode_insn(insn, self.func_addr + move_length)
                move_length += insn.size
            prologue = idaapi.get_bytes(self.func_addr, move_length)

            # write jmp code
            idaapi.patch_bytes(self.func_addr, jmp_buf)

            # assmble hook code
            hook_buf, _ = assemble(self.inline_hook_code, self.hook_addr)
            hook_buf += prologue
            jmp_back_code = 'jmp 0x%x' % (self.func_addr + move_length)
            jmp_back_buf, _ = assemble(jmp_back_code, self.hook_addr + len(hook_buf))
            hook_buf += jmp_back_buf

            # wirte hook code
            idaapi.patch_bytes(self.hook_addr, hook_buf)
            return len(hook_buf)

    def unhook(self):
        """
        Remove breakpoint for bpt hook.
        """

        idc.del_bpt(self.func_addr)

class DllHook():
    def __init__(self, name, funcs=None):
        self.name = name
        if funcs == None:
            self.funcs = []
        self.loaded = False
        self.hooked = False

    def add_func(self, func):
        self.funcs.append(func)

    def hook(self, hook_base = 0):
        """
        Args:
            hook_base(int): address for inline hook code, 0 indicates bpt hook.
        Returns:
            memory size in bytes used for inline hook.
        """

        self.hook_base = hook_base

        used_bytes = 0
        for func in self.funcs:
            used_bytes += func.hook(self.hook_base + used_bytes)
        self.hooked = True
        return used_bytes

    def unhook(self):
        if self.hooked:
            for func in self.funcs:
                func.unhook()

bpt_hook = False

if bpt_hook:
    print("[DBGHider] using break point hook")
else:
    print("[DBGHider] using inline hook")

class MyDbgHook(idaapi.DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):

        self.mem_for_inline_hooks = 0
        self.virtualalloc = 0

        ntdll = DllHook('ntdll.dll')
        ntdll.add_func( FuncHook('ntdll_NtClose', NtClose_inline_hook_code_32, NtClose_bpt_cond_hook_code_32) )
        ntdll.add_func( FuncHook('ntdll_NtQueryInformationProcess', NtQueryInformationProcess_inline_hook_code_32, NtQueryInformationProcess_bpt_cond_hook_code_32) )

        self.dlls = [ntdll]


        # IDA creates a segment named "TIB[XXXXXXXX]", which points to
        # wow_peb64 antually. We can get peb from wow_peb64 with 0x1000 offset.
        #               peb_addr = wow_peb64_addr + 0x1000
        # Note: IDA has not created segment "TIB[XXXXXXXX]" at this point.

        # tid = get_current_thread()
        # tib_segm_name = "TIB[%08X]" % tid
        # print tib_segm_name
        # tib_segm = get_segm_by_name(tib_segm_name)
        # wow_peb64 = tib_segm.start_ea
        # peb = tib_segm.start_ea + 0x1000

        # on debugging start, ebx points to peb
        # get addrs of peb and wow_peb64
        ebx = idc.get_reg_value("ebx")
        peb = ebx
        wow_peb64 = peb - 0x1000

        # patch peb->BeingDebugged
        # solving peb->NtGlobalFlag and "Heap Magic" anti-debug method
        # at the same time.
        idc.patch_byte(peb + 2, 0)
        idc.patch_byte(wow_peb64 + 2, 0)


        # patching peb process paramters
        peb_process_parameters = idaapi.get_dword(peb + 0x10)
        flag = idaapi.get_dword(peb_process_parameters + 0x8)
        idc.patch_dword(peb_process_parameters + 0x8, flag | 0x4000)

        # patching peb64 process paramters
        peb64_process_parameters = idaapi.get_qword(wow_peb64 + 0x20)
        flag = idaapi.get_dword(peb64_process_parameters + 0x8)
        idc.patch_dword(peb64_process_parameters + 0x8, flag | 0x4000)

    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

        if bpt_hook:
            for dll in self.dlls:
                dll.unhook()


    def dbg_library_load(self, pid, tid, ea, name, base, size):
        idc.refresh_debugger_memory()
        base_lib_name = os.path.basename(name)

        for dll in self.dlls:
            if base_lib_name == dll.name:
                dll.loaded = True

        if bpt_hook:
            for dll in self.dlls:
                if  dll.loaded and not dll.hooked:
                    self.mem_for_inline_hooks += dll.hook(self.mem_for_inline_hooks)
        else:
            if base_lib_name == 'kernel32.dll':
                self.virtualalloc = idaapi.Appcall.proto("kernel32_VirtualAlloc", \
                    "int __stdcall VirtualAlloc(int addr, SIZE_T sz, DWORD alloctype, DWORD protect);")

            if self.virtualalloc and not self.mem_for_inline_hooks:
                try:
                    self.mem_for_inline_hooks = self.virtualalloc(0, 0x1000, 0x1000, 0x40)
                    idc.refresh_debugger_memory()
                    print("Allocated memory for hook: 0x%x" % self.mem_for_inline_hooks)
                except:
                    pass

            if self.mem_for_inline_hooks:
                for dll in self.dlls:
                    if  dll.loaded and not dll.hooked:
                        self.mem_for_inline_hooks += dll.hook(self.mem_for_inline_hooks)



class debugger_hider_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "DBGHider aims to hide debugger from processes"
    help = "Change global variable bpt_hook to choose the hooking methond"
    wanted_name = "DBGHider"
    wanted_hotkey = "Alt-F8"

    def init(self):
        print("[DBGHider] plugin init")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("[DBGHider] plugin run")
        idc.load_and_run_plugin('python', 3)
        try:
            if __main__.DBG_HOOK:
                print("[DBGHider] Removing previous hook ...")
                __main__.DBG_HOOK.unhook()
        except:
            pass
        print("[DBGHider] enable hooking ...")
        __main__.DBG_HOOK = MyDbgHook()
        __main__.DBG_HOOK.hook()

    def term(self):
        print("[DBGHider] plugin term")

def PLUGIN_ENTRY():
    return debugger_hider_plugin_t()
