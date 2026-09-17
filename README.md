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

