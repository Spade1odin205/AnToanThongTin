def rc4_mini_step_by_step(input_bytes, K, S_init, plaintext):
    N = len(S_init)
    S = list(S_init)
    key_len = len(K)

    print("\n")
    print("GIAI ĐOẠN 1: TRỘN MẢNG S (KSA - Key-Scheduling Algorithm)")
    print(f"{'i':<3} | {'K[i%4]':<6} | {'Tính toán j':<25} | {'Hoán vị':<15} | {'Mảng S hiện tại'}")
    print("-" * 80)
    
    j = 0
    for i in range(N):
        k_val = K[i % key_len]
        j_new = (j + S[i] + k_val) % N
        
        # Lưu lại chuỗi để in ra cho đẹp
        calc_str = f"({j} + {S[i]} + {k_val}) % {N} = {j_new}"
        swap_str = f"S[{i}] <-> S[{j_new}]"
        
        # Cập nhật j và hoán vị
        j = j_new
        S[i], S[j] = S[j], S[i]
        
        # In từng bước KSA
        print(f"{i:<3} | {k_val:<6} | {calc_str:<25} | {swap_str:<15} | {S}")

    print("\n")
    print("GIAI ĐOẠN 2: SINH KHÓA & MÃ HÓA (PRGA)")
    print(f"{'Ký tự':<6} | {'ASCII':<6} | {'i':<3} | {'j':<3} | {'t':<3} | {'Khóa k':<7} | {'Bản mã C':<9} | {'Mảng S hiện tại'}")
    print("-" * 80)

    i = 0
    j = 0
    keystream = []
    output_bytes = []

    for idx, byte in enumerate(input_bytes):
        # Lấy ký tự tương ứng để hiển thị (từ chuỗi plaintext ban đầu)
        char = plaintext[idx]
        
        i = (i + 1) % N
        j = (j + S[i]) % N
        S[i], S[j] = S[j], S[i]
        
        t = (S[i] + S[j]) % N
        k = S[t]
        keystream.append(k)
        
        # XOR byte đầu vào với dòng khóa
        c = byte ^ k
        output_bytes.append(c)

        # In từng bước PRGA
        print(f"'{char}'   | {byte:<6} | {i:<3} | {j:<3} | {t:<3} | {k:<7} | {c:<9} | {S}")

    return keystream, output_bytes

# KHỞI CHẠY CHƯƠNG TRÌNH
S_original = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
K = [2, 4, 1, 7]
plaintext = "cybersecurity"

# Chuyển chuỗi thành mảng ASCII
m = [ord(c) for c in plaintext]

# Gọi hàm mã hóa với chế độ in chi tiết
keystream_enc, ciphertext_bytes = rc4_mini_step_by_step(m, K, S_original, plaintext)

print("\n")
print("KẾT QUẢ CUỐI CÙNG")
print(f"Dòng khóa sinh ra (Keystream) : {keystream_enc}")
print(f"Bản mã C(t) (Dạng số nguyên)  : {ciphertext_bytes}")

ciphertext_chars = "".join([chr(c) for c in ciphertext_bytes])
print(f"Bản mã C(t) (Dạng ký tự)      : '{ciphertext_chars}'")