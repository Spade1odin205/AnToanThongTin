import re


ALPHABET_25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Playfair: gộp I/J, bỏ J


def _normalize_letters(text: str) -> str:
	"""Chỉ giữ A-Z, in hoa, đổi J -> I."""
	text = re.sub(r"[^A-Za-z]", "", text).upper()
	return text.replace("J", "I")


def build_key_square(key: str):
	"""Tạo bảng khóa 5x5 và map vị trí ký tự.

	Trả về: (square, pos)
	  - square: list[list[str]] kích thước 5x5
	  - pos: dict[str, tuple[int,int]] ánh xạ ký tự -> (row, col)
	"""
	key = _normalize_letters(key)

	seen = set()
	key_stream = []
	for ch in key:
		if ch in ALPHABET_25 and ch not in seen:
			seen.add(ch)
			key_stream.append(ch)

	for ch in ALPHABET_25:
		if ch not in seen:
			seen.add(ch)
			key_stream.append(ch)

	square = [key_stream[i * 5 : (i + 1) * 5] for i in range(5)]
	pos = {square[r][c]: (r, c) for r in range(5) for c in range(5)}
	return square, pos


def prepare_plaintext(plaintext: str) -> list[tuple[str, str]]:
	"""Chuẩn hóa và tách plaintext thành các cặp theo quy tắc Playfair.

	- Bỏ ký tự không phải chữ cái, in hoa, J->I
	- Nếu 2 chữ trong 1 cặp giống nhau: chèn 'X' sau chữ đầu
	- Nếu độ dài lẻ: thêm 'X' ở cuối
	"""
	text = _normalize_letters(plaintext)

	pairs: list[tuple[str, str]] = []
	i = 0
	while i < len(text):
		a = text[i]
		b = text[i + 1] if i + 1 < len(text) else "X"

		if a == b:
			pairs.append((a, "X"))
			i += 1
		else:
			pairs.append((a, b))
			i += 2
	return pairs


def encrypt_playfair(plaintext: str, key: str) -> str:
	"""Mã hóa Playfair (gộp I/J)."""
	square, pos = build_key_square(key)
	pairs = prepare_plaintext(plaintext)

	out = []
	for a, b in pairs:
		ra, ca = pos[a]
		rb, cb = pos[b]

		if ra == rb:
			# cùng hàng: dịch phải
			out.append(square[ra][(ca + 1) % 5])
			out.append(square[rb][(cb + 1) % 5])
		elif ca == cb:
			# cùng cột: dịch xuống
			out.append(square[(ra + 1) % 5][ca])
			out.append(square[(rb + 1) % 5][cb])
		else:
			# hình chữ nhật: đổi cột
			out.append(square[ra][cb])
			out.append(square[rb][ca])

	return "".join(out)


if __name__ == "__main__":
	key = input("Nhập khóa (key): ").strip()
	plaintext = input("Nhập bản rõ (plaintext): ").strip()
	print("Ciphertext:", encrypt_playfair(plaintext, key))

