import idautils
import idc
import idaapi
import json
import os

def get_arm_raw_hex_smart(ea, max_size=16):
    """
    Mengambil hex ARM, tapi otomatis BERHENTI jika menemukan 
    instruksi ret (ARM64) atau bx lr (ARM32) yang disebutkan Grok.
    """
    sig_parts = []
    is_64bit = idaapi.get_inf_attr(idaapi.INF_LFLAGS) & idaapi.LFLG_64BIT
    
    for i in range(0, max_size, 4):
        # Ambil 4 byte (1 instruksi ARM)
        b1 = idc.get_wide_byte(ea + i)
        b2 = idc.get_wide_byte(ea + i + 1)
        b3 = idc.get_wide_byte(ea + i + 2)
        b4 = idc.get_wide_byte(ea + i + 3)
        
        sig_parts.extend([f"{b1:02X}", f"{b2:02X}", f"{b3:02X}", f"{b4:02X}"])
        
        # JIKA MENEMUKAN KODE RET/BX LR DARI GROK, STOP BACA AGAR TIDAK BOCOR KE FUNGSI LAIN
        if is_64bit and b1 == 0xC0 and b2 == 0x03 and b3 == 0x5F and b4 == 0xD6:
            break
        if not is_64bit and b1 == 0x1E and b2 == 0xFF and b3 == 0x2F and b4 == 0xE1:
            break
            
    return " ".join(sig_parts[:max_size]) + " "

def main():
    # Menampilkan kotak input dengan nilai bawaan 16 byte (Paling aman untuk Android)
    max_size = idc.ask_long(16, "Masukkan MAKSIMAL size signature dalam byte:\n(Rekomendasi tetap: 16 atau 12)")
    
    if max_size is None or max_size <= 0:
        print("[-] Ekstraksi dibatalkan.")
        return

    output_data = []
    image_base = idaapi.get_imagebase()

    print(f"[*] Memulai ekstraksi signature ARM...")

    for func_ea in idautils.Functions():
        mangled_name = idc.get_func_name(func_ea)
        demangled = idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        final_name = demangled if demangled else mangled_name
        
        relative_offset = func_ea - image_base

        func_info = {
            "classfuncname": final_name,
            "classhash": 0,
            "classname": "",
            "cpp_name": "",
            "mangledname": mangled_name,
            "demangledname": final_name,
            "isclass": 1 if demangled else 0,
            "isvirtual": 0,
            "offset": relative_offset,
            "refoffset": 1,
            "refsize": 4,
            "signature": get_arm_raw_hex_smart(func_ea, max_size=max_size),
            "symbol": mangled_name,
            "type": 3,
            "voffset": -1
        }
        output_data.append(func_info)

    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    output_file = os.path.join(desktop_path, "arm_hex_signatures.json")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4)

    print(f"[+] SELESAI! File JSON sukses disimpan di Desktop: {output_file}")

if __name__ == "__main__":
    main()
