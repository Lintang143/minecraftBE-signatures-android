#include <idc.idc>

// Fungsi sederhana untuk escape karakter backslash dan tanda kutip ganda 
// agar tidak merusak struktur JSON
static escape_json_str(str) {
    auto result = "";
    auto i;
    auto len = strlen(str);
    for (i = 0; i < len; i++) {
        auto c = substr(str, i, i+1);
        if (c == "\"") {
            result = result + "\\\"";
        } else if (c == "\\") {
            result = result + "\\\\";
        } else {
            result = result + c;
        }
    }
    return result;
}

static get_arm_raw_hex_smart(ea, max_size, is_64bit) {
    auto sig = "";
    auto i = 0;
    auto b1, b2, b3, b4;

    while (i < max_size) {
        // Ambil 4 byte (1 instruksi ARM)
        b1 = get_wide_byte(ea + i);
        b2 = get_wide_byte(ea + i + 1);
        b3 = get_wide_byte(ea + i + 2);
        b4 = get_wide_byte(ea + i + 3);

        // Tambahkan ke signature tapi batasi output sesuai dengan max_size
        if (i < max_size)     sig = sig + sprintf("%02X ", b1);
        if (i+1 < max_size)   sig = sig + sprintf("%02X ", b2);
        if (i+2 < max_size)   sig = sig + sprintf("%02X ", b3);
        if (i+3 < max_size)   sig = sig + sprintf("%02X ", b4);

        // JIKA MENEMUKAN KODE RET/BX LR, STOP BACA AGAR TIDAK BOCOR KE FUNGSI LAIN
        if (is_64bit && b1 == 0xC0 && b2 == 0x03 && b3 == 0x5F && b4 == 0xD6) break;
        if (!is_64bit && b1 == 0x1E && b2 == 0xFF && b3 == 0x2F && b4 == 0xE1) break;

        i = i + 4;
    }
    return sig;
}

static main() {
    // Menampilkan kotak input
    auto max_size = ask_long(16, "Masukkan MAKSIMAL size signature dalam byte:\n(Rekomendasi tetap: 16 atau 12)");
    
    if (max_size <= 0) {
        msg("[-] Ekstraksi dibatalkan.\n");
        return;
    }

    // Meminta user memilih lokasi dan nama file penyimpanan
    auto output_file = ask_file(1, "arm_hex_signatures.json", "Simpan JSON file di mana?");
    if (output_file == "") {
        msg("[-] Dibatalkan. Tidak ada lokasi penyimpanan yang dipilih.\n");
        return;
    }

    auto f = fopen(output_file, "w");
    if (f == 0) {
        msg("[-] Gagal membuka atau membuat file di: %s\n", output_file);
        return;
    }

    auto image_base = get_imagebase();
    auto is_64bit = get_inf_attr(INF_LFLAGS) & LFLG_64BIT;

    msg("[*] Memulai ekstraksi signature ARM...\n");

    // Memulai array JSON
    fprintf(f, "[\n");

    auto ea = get_next_func(0);
    auto is_first = 1;

    while (ea != BADADDR) {
        auto mangled_name = get_func_name(ea);
        auto demangled = demangle_name(mangled_name, get_inf_attr(INF_SHORT_DN));
        
        auto final_name = demangled;
        auto isclass = 1;

        // Jika gagal demangle (bisa mereturn string kosong atau angka 0)
        if (demangled == "" || demangled == 0) {
            final_name = mangled_name;
            isclass = 0;
        }

        auto relative_offset = ea - image_base;
        auto sig = get_arm_raw_hex_smart(ea, max_size, is_64bit);

        // Escape string sebelum memasukkannya ke template JSON
        auto esc_final_name = escape_json_str(final_name);
        auto esc_mangled_name = escape_json_str(mangled_name);

        if (!is_first) {
            fprintf(f, ",\n"); // pisahkan antar object dengan koma
        }
        
        // Cetak JSON Object
        fprintf(f, "    {\n");
        fprintf(f, "        \"classfuncname\": \"%s\",\n", esc_final_name);
        fprintf(f, "        \"classhash\": 0,\n");
        fprintf(f, "        \"classname\": \"\",\n");
        fprintf(f, "        \"cpp_name\": \"\",\n");
        fprintf(f, "        \"mangledname\": \"%s\",\n", esc_mangled_name);
        fprintf(f, "        \"demangledname\": \"%s\",\n", esc_final_name);
        fprintf(f, "        \"isclass\": %d,\n", isclass);
        fprintf(f, "        \"isvirtual\": 0,\n");
        fprintf(f, "        \"offset\": %u,\n", relative_offset);
        fprintf(f, "        \"refoffset\": 1,\n");
        fprintf(f, "        \"refsize\": 4,\n");
        fprintf(f, "        \"signature\": \"%s\",\n", sig);
        fprintf(f, "        \"symbol\": \"%s\",\n", esc_mangled_name);
        fprintf(f, "        \"type\": 3,\n");
        fprintf(f, "        \"voffset\": -1\n");
        fprintf(f, "    }");

        is_first = 0;
        ea = get_next_func(ea);
    }

    // Tutup Array JSON
    fprintf(f, "\n]\n");
    fclose(f);

    msg("[+] SELESAI! File JSON sukses disimpan di: %s\n", output_file);
}
