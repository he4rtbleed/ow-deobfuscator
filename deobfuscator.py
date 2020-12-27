import idaapi

def run():
    now = here()
    print('[+] CurPos: ' + hex(now))
    cur_func = get_name_ea_simple(get_func_name(here()))
    print('[+] CurFunc: ' + hex(cur_func))
    func_start = idc.get_func_attr(now, FUNCATTR_START)
    func_end = idc.get_func_attr(now, FUNCATTR_END)
    print('[+] FuncStart: ' + hex(func_start))
    print('[+] FuncEnd: ' + hex(func_end))
    
    curr_addr = func_start
    while curr_addr < func_end:
        disasm = generate_disasm_line(curr_addr, 1)
        print(hex(curr_addr) + '\t' + disasm)
        
        is_obfuscated = False
            
        #Obfuscated Pattern Start
        if ('short near ptr' in disasm):
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if not 'nop' in next_disasm:
                if disasm[0] == 'j':
                    is_obfuscated = True
        elif (', cs:dword' in disasm):
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if 'add' in next_disasm:
                next_disasm = generate_disasm_line(next_head(next_head(next_head(curr_addr))), 1)
                if 'cmp' in next_disasm:
                    start_addr = curr_addr
                    end_addr = 0
                    while end_addr == 0:
                        disasm = generate_disasm_line(start_addr, 1)
                        print(hex(start_addr) + ' - ' + disasm)
                        if ('short' in disasm) and (disasm[0] == 'j'):
                            end_addr = start_addr
                            break
                        start_addr = next_head(start_addr)
                    if end_addr:
                        for i in range(curr_addr, end_addr):
                            idc.patch_byte(i, 0x90)
                        curr_addr = end_addr
                        is_obfuscated = True
        elif ('jz' in disasm):
            prev_disasm = generate_disasm_line(prev_head(curr_addr), 1)
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if not 'nop' in next_disasm:
                if 'cmp' in prev_disasm:
                    if get_operand_value(prev_head(curr_addr), 1) == 0xE8:
                        is_obfuscated = True
        #Obfuscated Pattern End
        
        if (is_obfuscated):
            jmp_addr = get_operand_value(curr_addr,0)
            jmp_next = next_head(jmp_addr)
            print('[!] Found obfuscated jmp at ' + hex(curr_addr) + ' to ' + hex(jmp_addr))
            for i in range(curr_addr, jmp_addr):
                idc.patch_byte(i, 0x90)
            break
        curr_addr = next_head(curr_addr)

idaapi.compile_idc_text('static fn1() { RunPythonStatement("run()"); }')

add_idc_hotkey("F1", 'fn1')