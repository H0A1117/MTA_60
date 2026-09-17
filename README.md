# BeatMe - Writeup
Bước 1: Trong bước phân tích tĩnh ban đầu, mình dùng Detect It Easy (DIE) để xác định thông tin cơ bản của file chall.exe trước khi tiến hành reverse engineering
<img width="1106" height="818" alt="image" src="https://github.com/user-attachments/assets/15a2397f-b792-4005-8994-ad75b233561c" />
File được biên dịch bằng MSVC (Visual Studio 2022), viết bằng C++, dạng console application 64-bit. Đáng chú ý, DIE cảnh báo section .text có entropy cao, cho thấy khả năng binary đã bị pack/nén. Đây là dấu hiệu cần lưu ý trước khi đưa file vào IDA/Ghidra để phân tích sâu, vì có thể cần unpack trước thì mới thấy được code thật bên trong
Bước 2: Giải thích entropy cao – Mở IDA để xác nhận
![Uploading image.png…]()
Danh sách API khá đầy đủ không có dấu hiệu bị pack
Bước 3: Tìm entrypoint xác định hành động tiếp theo của chương trình

