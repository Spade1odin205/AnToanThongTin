def poly_div(a, b):
    if b == 0:
        raise ZeroDivisionError
    q = 0
    while True:
        deg_a = a.bit_length() - 1
        deg_b = b.bit_length() - 1
        if deg_a < deg_b:
            break
        shift = deg_a - deg_b
        q ^= (1 << shift)
        a ^= (b << shift)
    return q, a

def poly_mul(a, b):
    p = 0
    while b > 0:
        if b & 1:
            p ^= a
        a <<= 1
        b >>= 1
    return p

def extended_euclidean_gf2(a, m):
    print(f"--- Tìm phần tử nghịch đảo của {a} ---\n")
    
    r1, r2 = m, a
    t1, t2 = 0, 1
    
    print(f"{'Bước':<5} | {'Q':<5} | {'R1':<5} | {'R2':<5} | {'Dư R':<5} | {'T1':<5} | {'T2':<5} | {'T':<5}")
    print("-" * 65)
    
    step = 1
    while r2 > 0:
        q, r = poly_div(r1, r2)
        
        qt2 = poly_mul(q, t2)
        t = t1 ^ qt2
        
        print(f"{step:<5} | {q:<5} | {r1:<5} | {r2:<5} | {r:<5} | {t1:<5} | {t2:<5} | {t:<5}")
        
        r1, r2 = r2, r
        t1, t2 = t2, t
        step += 1
        
    print("-" * 65)
    print(f"Kết thúc với R1 = {r1}, T1 = {t1}")
    if r1 == 1:
        print(f"Nghịch đảo nhân của {a} là: {t1}\n")
        return t1
    else:
        print(f"{a} không có nghịch đảo nhân.\n")
        return None

if __name__ == "__main__":
    # Đa thức tối giản m(x) = x^10 + x^3 + 1 (biểu diễn dạng số nguyên: 2^10 + 2^3 + 2^0 = 1033)
    m = (1 << 10) | (1 << 3) | 1 
    
    # Test vector
    a = 523
    b = 1015
    
    extended_euclidean_gf2(a, m)
    extended_euclidean_gf2(b, m)
