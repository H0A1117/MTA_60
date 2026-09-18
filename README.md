# BeatMe - Writeup
Bước 1: Trong bước phân tích tĩnh ban đầu, mình dùng Detect It Easy (DIE) để xác định thông tin cơ bản của file chall.exe trước khi tiến hành reverse engineering
<img width="1106" height="818" alt="image" src="https://github.com/user-attachments/assets/15a2397f-b792-4005-8994-ad75b233561c" />
File được biên dịch bằng MSVC (Visual Studio 2022), viết bằng C++, dạng console application 64-bit. Đáng chú ý, DIE cảnh báo section .text có entropy cao, cho thấy khả năng binary đã bị pack/nén. Đây là dấu hiệu cần lưu ý trước khi đưa file vào IDA/Ghidra để phân tích sâu, vì có thể cần unpack trước thì mới thấy được code thật bên trong

Bước 2: Giải thích entropy cao – Mở IDA để xác nhận
<img width="1433" height="825" alt="image" src="https://github.com/user-attachments/assets/9bed1669-6749-4a36-acc5-838ee3e72e3d" />

Danh sách API khá đầy đủ không có dấu hiệu bị pack

Bước 3: Tìm entrypoint (ctrl + E) xác định hành động tiếp theo của chương trình
<img width="1433" height="825" alt="image" src="https://github.com/user-attachments/assets/1cdefa32-ff9a-423b-bd0c-61aed1c662fd" />

Sau khi tìm được entrypoint ta thấy hàm return về sub_140A49730(). Ta đoán đây là hàm CRT Startup Routine MSVC
<img width="1433" height="1017" alt="image" src="https://github.com/user-attachments/assets/efc44fe8-176f-4d6f-a44a-afdf00a45dd9" />
Hàm trên return v16 = sub_1400010D0(*v15, v13, v11)

<img width="1424" height="486" alt="image" src="https://github.com/user-attachments/assets/05a1c67f-5326-43b5-b949-68d8bf110d82" />


Phân tích hàm sub_1400010D0 thì tiêp theo nó sẽ gọi 3 hàm sub_140036ED0(), sub_140001170(Dst) và sub_140001270(Dst)

sub_140036ED0():
<img width="1440" height="1094" alt="image" src="https://github.com/user-attachments/assets/f73ecc42-d6fc-4c3c-b10c-99edcf90c854" />
<img width="1440" height="1094" alt="image" src="https://github.com/user-attachments/assets/443272f3-900c-496d-a95a-d0b4f9c16923" />
<img width="1440" height="1094" alt="image" src="https://github.com/user-attachments/assets/014362ce-e537-4d4f-9312-4e1cbacc64ff" />
Ta để ý hàm có 2 tham số a1, a2
<img width="612" height="82" alt="image" src="https://github.com/user-attachments/assets/cba3bc97-929a-4f7e-b36e-a672565bdf2a" />
a1 là 1 key 32 bytes
<img width="1028" height="320" alt="image" src="https://github.com/user-attachments/assets/417d9ec5-18b1-4cf3-a978-42ea7e1b3ce7" />

a2 là 1 khoảng rỗng
<img width="1036" height="554" alt="image" src="https://github.com/user-attachments/assets/8a8f18c8-d46b-4900-915e-f4cf7ddc9591" />
Đi sâu vào hàm sub_140036ED0() ta thấy có 
<img width="1096" height="60" alt="image" src="https://github.com/user-attachments/assets/67e62383-5080-49e6-9a7f-c1e679be4739" />
<img width="1096" height="33" alt="image" src="https://github.com/user-attachments/assets/4f1ed0e1-2419-4c71-beef-2be890229931" />
Ta có thể thấy a2 là chỗ để lưu round key 16 bit. Vòng for đầu tiên chạy từ 0 đến 7 và có 8 round key
<img width="893" height="248" alt="image" src="https://github.com/user-attachments/assets/474655da-2d3b-4fee-b6d5-ff7d4be16d3c" />
Vòng lặp 2 chạy từ 8 đến 59 và rẽ nhánh 3 điều kiện
DK1: Nếu k chia 89 dư 4 thì a2(k-1) = sub_14003ABA0(v7) và a2(k) = SubWord(a2(k-1)) ^ a2(k-8)
<img width="594" height="142" alt="image" src="https://github.com/user-attachments/assets/3c45fcfa-b77d-4315-8e18-f37e38e88bca" />
<img width="1058" height="481" alt="image" src="https://github.com/user-attachments/assets/405012fe-4a8b-4426-b632-6bb4a8f9ea66" />

DK2: Nếu k chia hết cho 8 thì a2(k-1) = dword_140ABD510[k / 8 - 1] ^ sub_14003ABA0(HIBYTE(v7) | (v7 << 8)) và a2(k) = Rcon[k/8-1] ^ SubWord(RotWord(a(k-1)))
<img width="1166" height="76" alt="image" src="https://github.com/user-attachments/assets/f2b70384-bd17-4a35-994d-82fdb01281f5" />

DK3: Còn lại thì a2(k) = a2(k-1) ^ a2(k-8)
sub_140001170(Dst):
<img width="962" height="553" alt="image" src="https://github.com/user-attachments/assets/7e052b97-332a-4b0b-9e89-6d75e24b840d" />
Đầu tiên nó check đuôi file tại hàm sub_140001340
<img width="962" height="361" alt="image" src="https://github.com/user-attachments/assets/0919dbb1-8aa4-4091-92a7-054ba7c20d2d" />
<img width="856" height="180" alt="image" src="https://github.com/user-attachments/assets/0c0161ae-c79c-45e4-9e4b-a1d2af4d0714" />
Nó check xem có phải file .txt, .jpg, .docx hay không nếu null thì close nếu có thì gọi hàm sub_1400013E0

