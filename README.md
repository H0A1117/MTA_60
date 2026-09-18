# BeatMe - Writeup

## Bước 1: Phân tích tĩnh với Detect It Easy (DIE)

Trong bước phân tích tĩnh ban đầu, mình dùng Detect It Easy (DIE) để xác định thông tin cơ bản của file `chall.exe` trước khi tiến hành reverse engineering.

<img width="1106" height="818" alt="image" src="https://github.com/user-attachments/assets/15a2397f-b792-4005-8994-ad75b233561c" />

File được biên dịch bằng MSVC (Visual Studio 2022), viết bằng C++, dạng console application 64-bit. Đáng chú ý, DIE cảnh báo section `.text` có entropy cao, cho thấy khả năng binary đã bị pack/nén. Đây là dấu hiệu cần lưu ý trước khi đưa file vào IDA để phân tích sâu, vì có thể cần unpack trước thì mới thấy được code thật bên trong.

---

## Bước 2: Xác nhận không bị pack – Mở IDA kiểm tra Import Table

<img width="1433" height="825" alt="image" src="https://github.com/user-attachments/assets/9bed1669-6749-4a36-acc5-838ee3e72e3d" />

Mở file trong IDA và kiểm tra Import Table. Danh sách API rất đầy đủ — có hàng trăm hàm từ nhiều thư viện khác nhau. Nếu binary bị pack thì Import Table thường gần như trống (chỉ còn `LoadLibrary`, `GetProcAddress`). Kết luận: **binary không bị pack**, entropy cao là do dữ liệu lookup table (S-box) được nhúng trực tiếp vào section `.text` — sẽ giải thích rõ hơn ở bước sau.

---

## Bước 3: Tìm entry point và trace đến logic chính

Dùng `Ctrl+E` trong IDA để nhảy đến entry point.

<img width="1433" height="825" alt="image" src="https://github.com/user-attachments/assets/1cdefa32-ff9a-423b-bd0c-61aed1c662fd" />

Entry point (`start`) chỉ làm 2 việc: gọi `__security_init_cookie` rồi `jmp` vào `sub_140A49730`. Đây là **CRT Startup Routine** của MSVC — không phải `main()` của challenge.

<img width="1433" height="1017" alt="image" src="https://github.com/user-attachments/assets/efc44fe8-176f-4d6f-a44a-afdf00a45dd9" />

Bên trong `sub_140A49730` (CRT startup), sau khi khởi tạo heap, locale, TLS, nó gọi `_initterm` để chạy toàn bộ **global constructors** — trong đó có một global ctor cài đặt VEH/SEH (sẽ đề cập ở bước sau). Cuối cùng nó gọi `wmain`:

```
sub_140A49730  →  _initterm (global ctors)  →  sub_1400010D0 (wmain)
```

Hàm `sub_140A49730` return `v11 = sub_1400010D0(*v10, v9, v8)` — tức là gọi `wmain(argc, argv, envp)`.

<img width="1424" height="486" alt="image" src="https://github.com/user-attachments/assets/05a1c67f-5326-43b5-b949-68d8bf110d82" />

Phân tích `sub_1400010D0` (wmain): hàm dùng `ExpandEnvironmentStringsA` để tạo đường dẫn `%USERPROFILE%\Desktop\target`, kiểm tra thư mục đó có tồn tại không, rồi lần lượt gọi 3 hàm:

- `sub_140036ED0()` — Key Schedule
- `sub_140001170(Dst)` — Scan thư mục và mã hóa file
- `sub_140001270(Dst)` — Dọn dẹp sau khi mã hóa

---

## Bước 4: Phân tích `sub_140036ED0` — Key Schedule

<img width="1440" height="1094" alt="image" src="https://github.com/user-attachments/assets/f73ecc42-d6fc-4c3c-b10c-99edcf90c854" />
<img width="1440" height="1094" alt="image" src="https://github.com/user-attachments/assets/443272f3-900c-496d-a95a-d0b4f9c16923" />
<img width="1440" height="1094" alt="image" src="https://github.com/user-attachments/assets/014362ce-e537-4d4f-9312-4e1cbacc64ff" />

Hàm này là wrapper, gọi thẳng vào `sub_140036EF0(a1, a2)` với 2 tham số:

<img width="612" height="82" alt="image" src="https://github.com/user-attachments/assets/cba3bc97-929a-4f7e-b36e-a672565bdf2a" />

**`a1`** — key 32 bytes nhúng tĩnh trong binary tại `0x140ABD4E0`:

<img width="1028" height="320" alt="image" src="https://github.com/user-attachments/assets/417d9ec5-18b1-4cf3-a978-42ea7e1b3ce7" />

```
"MSEC_UNWINDCRYPT" + deadbeefcafebabe1337c0deabcdef12
```

**`a2`** — output buffer `DWORD W[60]` tại `0x140ACCD80`, trống trước khi hàm chạy:

<img width="1036" height="554" alt="image" src="https://github.com/user-attachments/assets/8a8f18c8-d46b-4900-915e-f4cf7ddc9591" />

`a2` là mảng 60 DWORD (240 bytes) — nơi lưu **15 round keys**, mỗi round key 16 bytes (4 DWORD liên tiếp).

### Loop 1 — Nạp key vào W[0..7]

<img width="1096" height="60" alt="image" src="https://github.com/user-attachments/assets/67e62383-5080-49e6-9a7f-c1e679be4739" />
<img width="1096" height="33" alt="image" src="https://github.com/user-attachments/assets/4f1ed0e1-2419-4c71-beef-2be890229931" />

Vòng lặp chạy `i = 0..7`. Phần lớn bên trong là **junk code** — `FindFirstFileW("C", ...)` luôn thất bại nên toàn bộ `if`-block bị skip, `RegOpenKeyExW("SOFTWARE\\ObfJunk\\XYZ", ...)` cũng không tồn tại. Dòng duy nhất có tác dụng ở cuối mỗi iteration:

```c
W[i] = (key[4i] << 24) | (key[4i+1] << 16) | (key[4i+2] << 8) | key[4i+3]
// → copy 32 bytes key vào W[0..7] theo thứ tự big-endian
```

### Loop 2 — AES-256 Key Expansion W[8..59]

<img width="893" height="248" alt="image" src="https://github.com/user-attachments/assets/474655da-2d3b-4fee-b6d5-ff7d4be16d3c" />

Vòng lặp chạy `k = 8..59`, rẽ 3 nhánh:

**Nhánh 1 — `k % 8 == 0`** (k = 8, 16, 24, 32, 40, 48, 56):

<img width="1166" height="76" alt="image" src="https://github.com/user-attachments/assets/f2b70384-bd17-4a35-994d-82fdb01281f5" />

```
v7   = Rcon[k/8-1] ^ SubWord(RotWord(W[k-1]))
W[k] = v7 ^ W[k-8]
```
- `RotWord` = `HIBYTE(v7) | (v7 << 8)` = xoay trái 8 bit
- `SubWord` = tra AES S-box tại `0x140ACC000` cho từng byte
- `Rcon` = round constant table tại `0x140ABD510`

**Nhánh 2 — `k % 8 == 4`** (k = 12, 20, 28, 36, 44, 52):

<img width="594" height="142" alt="image" src="https://github.com/user-attachments/assets/3c45fcfa-b77d-4315-8e18-f37e38e88bca" />
<img width="1058" height="481" alt="image" src="https://github.com/user-attachments/assets/405012fe-4a8b-4426-b632-6bb4a8f9ea66" />

```
v7   = SubWord(W[k-1])    // chỉ SubWord, không RotWord, không Rcon
W[k] = v7 ^ W[k-8]
```

**Nhánh 3 — còn lại** (`k % 8 = 1,2,3,5,6,7`):
```
W[k] = W[k-1] ^ W[k-8]
```

**Kết luận:** Đây là **AES-256 Key Schedule** chuẩn. Kết quả là 15 round keys `W[0..59]` lưu tại `0x140ACCD80`, dùng cho block cipher ở các bước sau.

---

## Bước 5: Phân tích `sub_140001170` — Scan thư mục và mã hóa

<img width="962" height="553" alt="image" src="https://github.com/user-attachments/assets/7e052b97-332a-4b0b-9e89-6d75e24b840d" />

Hàm nhận đường dẫn thư mục `target`, dùng `FindFirstFileA` / `FindNextFileA` để duyệt qua toàn bộ file bên trong. Với mỗi file, kiểm tra extension qua `sub_140001340`:

<img width="962" height="361" alt="image" src="https://github.com/user-attachments/assets/0919dbb1-8aa4-4091-92a7-054ba7c20d2d" />
<img width="856" height="180" alt="image" src="https://github.com/user-attachments/assets/0c0161ae-c79c-45e4-9e4b-a1d2af4d0714" />

Hàm `sub_140001340` tra bảng extension gồm `.txt`, `.jpg`, `.docx`. Nếu khớp thì gọi `sub_1400013E0` để mã hóa file đó, nếu không khớp thì bỏ qua.

### `sub_1400013E0` — Mã hóa một file

<img width="972" height="906" alt="image" src="https://github.com/user-attachments/assets/06a0d07a-1781-4455-87aa-1fda3199b131" />

Hàm thực hiện theo thứ tự:

1. Đọc toàn bộ nội dung file vào RAM
2. Padding lên bội số 16 (AES block size)
3. Sinh **IV 16 bytes ngẫu nhiên** bằng `CryptGenRandom`
4. Gọi `sub_140001760(plaintext, ciphertext_out, size, IV)` để mã hóa
5. Đóng gói thành file `.rnwd` với cấu trúc header:

```
┌──────────┬───────────┬──────────────────┬──────────┬──────────────────┐
│  "RWDT"  │ orig_size │       IV         │ 00 * 8   │   ciphertext     │
│  4 bytes │  4 bytes  │    16 bytes      │ 8 bytes  │   N bytes        │
└──────────┴───────────┴──────────────────┴──────────┴──────────────────┘
 offset 0   offset 4    offset 8           offset 24   offset 32
```

6. Ghi file `<tên gốc>.rnwd` rồi xóa file gốc bằng `DeleteFileA`

### `sub_140001760` — CBC Encrypt Loop

<img width="1028" height="721" alt="image" src="https://github.com/user-attachments/assets/49446be3-7f10-498b-808b-07491f822932" />

Hàm nhận `(plaintext, ciphertext_out, size, IV)`. Trước loop, `v11:v12` được khởi tạo từ IV (2 QWORD = 16 bytes). Mỗi vòng lặp xử lý 1 block 16 bytes:

- `v8` (8 bytes) và `v9` (8 bytes ngay liền sau trên stack) tạo thành 1 block 16 bytes liên tục
- XOR từng byte của block với `v11:v12` (IV hoặc ciphertext block trước)
- Gọi `sub_140001910(&v8, &unk_140ACCD80)` để encrypt block
- Cập nhật `v11:v12 = v8:v9` (ciphertext vừa tạo, dùng cho block tiếp theo)

Đây là **CBC mode**:
```
CT[0] = encrypt(PT[0] XOR IV)
CT[i] = encrypt(PT[i] XOR CT[i-1])
```

<img width="1028" height="721" alt="image" src="https://github.com/user-attachments/assets/6e66b2cb-09a4-44c3-a8f0-f427de34b81e" />

### `sub_140001910` — Block Cipher

Hàm nhận:
- `a1 = &v8` — pointer đến block 16 bytes cần mã hóa
- `a2 = &unk_140ACCD80` — pointer đến round key buffer W[0..59]

Cấu trúc bên trong là **AES-256** với 14 rounds:

```
Load(input → state[4][4])
AddRoundKey(RK[0])
for i = 1..14:
    SubBytes     ← có INT3 exception, VEH/SEH can thiệp S-box
    ShiftRows
    MixColumns   ← chỉ round 1..13, bỏ qua round 14
    AddRoundKey(RK[i])
Store(state[4][4] → output)
```

Điểm đặc biệt: bên trong SubBytes có lệnh `__debugbreak()` (INT3 tại `0x1400019CA`). Khi exception xảy ra, **Vectored Exception Handler (VEH)** và **SEH frame handler** được cài sẵn từ trước sẽ can thiệp, thay đổi S-box lookup table theo từng round — đây là cơ chế obfuscate chính của bài.

---

## Kết luận

Toàn bộ luồng mã hóa:

```
chall.exe khởi động
    │
    ├─ _initterm → global ctor → cài VEH + patch SEH frame handler
    │
    └─ wmain
         ├─ sub_140036ED0  →  AES-256 Key Schedule  →  W[0..59] tại 0x140ACCD80
         │
         └─ sub_140001170  →  scan target\
              └─ với mỗi .txt/.jpg/.docx:
                   sub_1400013E0
                        ├─ đọc file
                        ├─ padding đến bội số 16
                        ├─ sinh IV ngẫu nhiên 16 bytes
                        ├─ sub_140001760  →  CBC encrypt
                        │       └─ sub_140001910  →  AES-256 block cipher
                        │                                (SubBytes qua VEH/SEH)
                        ├─ đóng gói: RWDT|orig_size|IV|zeros|ciphertext
                        └─ ghi .rnwd, xóa file gốc
```

Để giải mã `flag.txt.rnwd`, cần:
1. Đọc IV từ offset 0x08 của file `.rnwd`
2. Lấy round keys từ `0x140ACCD80` (dump lúc runtime)
3. Giải mã CBC ngược lại với block cipher tương ứng
