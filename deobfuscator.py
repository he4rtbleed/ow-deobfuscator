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
        if ('short near ptr' in disasm) or ('jnb     short' in disasm):
            prev_disasm = generate_disasm_line(prev_head(curr_addr), 1)
            if not 'nop' in generate_disasm_line(next_head(curr_addr), 1):
                if 'nop     dword ptr' in prev_disasm:
                    is_obfuscated = True
                elif 'nop     word ptr' in prev_disasm:
                    is_obfuscated = True
                elif 'xchg' in prev_disasm:
                    is_obfuscated = True
                elif 'mov     ah, ah' in prev_disasm:
                    is_obfuscated = True
                elif 'sar' in prev_disasm:
                    is_obfuscated = True
                elif 'sal' in prev_disasm:
                    is_obfuscated = True
        elif ('jz' in disasm):
            prev_disasm = generate_disasm_line(prev_head(curr_addr), 1)
            if not 'nop' in generate_disasm_line(next_head(curr_addr), 1):
                if 'cmp' in prev_disasm:
                    if get_operand_value(prev_head(curr_addr), 1) == 0xE8:
                        is_obfuscated = True
        #Obfuscated Pattern End
            
        if (is_obfuscated):
            jmp_addr = get_operand_value(curr_addr,0)
            jmp_next = next_head(jmp_addr)
            print('[!] Found obfuscated jmp at ' + hex(curr_addr) + ' to ' + hex(jmp_addr))
            for i in range(next_head(curr_addr), jmp_addr):
                idc.patch_byte(i, 0x90)
            break
        curr_addr = next_head(curr_addr)

idaapi.compile_idc_text('static fn1() { RunPythonStatement("run()"); }')

add_idc_hotkey("F1", 'fn1')