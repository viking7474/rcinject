# Phân tích và Hướng dẫn sử dụng InjectRC

## 1. Tác dụng thực tế của mã nguồn (Mục đích)

**InjectRC** là một công cụ dành cho thiết bị Android (yêu cầu quyền root, Android 11 trở lên), dùng để **tiêm (inject) các file cấu hình init (.rc) trực tiếp vào tiến trình `init` của Android đang chạy** mà không cần phải khởi động lại máy hoặc sửa đổi phân vùng hệ thống (system partition).

**Tác dụng thực tế:**
* **Chỉnh sửa hệ thống "On-the-fly" (Trực tiếp):** Cho phép các nhà phát triển, người can thiệp hệ thống (modder) thêm các dịch vụ (services) mới, hoặc các hành động (actions) vào hệ thống (như tự động chạy script khi một thuộc tính property thay đổi) ngay lập tức.
* **Vượt qua giới hạn Read-only:** Các phân vùng hệ thống Android thường là chỉ đọc (read-only) và việc sửa `init.rc` gốc rất khó khăn (có thể làm brick thiết bị hoặc bị kẹt bootloop). Công cụ này nạp mã cấu hình vào bộ nhớ tiến trình `init` đang chạy, giúp tạo các tinh chỉnh tạm thời (sẽ mất sau khi khởi động lại) hoặc tích hợp vào các công cụ root như Magisk/KernelSU.

## 2. Cơ chế hoạt động

Cơ chế hoạt động của InjectRC kết hợp nhiều kỹ thuật phức tạp trong môi trường Linux/Android:

1. **Gắn kết (Attach) vào tiến trình init:**
   * Công cụ sử dụng hệ thống gọi `ptrace` (Process Trace) để đính kèm (attach) và tạm dừng tiến trình `init` (PID = 1) của Android.

2. **Dừng tại Syscall an toàn:**
   * Nó đợi tiến trình `init` thực hiện một syscall an toàn (`__NR_epoll_pwait` - do `init` thường dùng cái này để đợi sự kiện) để tiến hành chèn mã mà không làm hỏng trạng thái hiện tại của nó.

3. **Tạo và tải thư viện động (Payload):**
   * Công cụ tạo một "file ẩn" trong bộ nhớ bằng `memfd_create`.
   * Nó sao chép payload (là một thư viện động `.so`, có chứa mã `Entry()`) vào file ẩn này.
   * Thông qua `ptrace`, InjectRC ép tiến trình `init` gọi hàm `dlopen` (mở thư viện động) từ Android linker để tải thư viện payload này vào vùng nhớ của `init`.

4. **Thực thi Payload trong init (`payload.cpp`):**
   * Khi payload được nạp, nó sẽ tìm kiếm địa chỉ các hàm nội bộ của `init` (bằng cách phân tích tệp thực thi `/system/bin/init` trong bộ nhớ thông qua `maps_scan` và `elf_parser`). Các hàm bị nhắm mục tiêu là `CreateParser`, `ParseConfig`, `ActionManager::GetInstance` và `ServiceList::GetInstance`.
   * Nó dùng `memfd_create` để tạo một tệp tạm thời khác.
   * `injector` (bên ngoài) sẽ "lắng nghe" và ghi nội dung của tệp `.rc` mà bạn muốn tiêm vào tệp tạm này thông qua `ptrace`.
   * Payload gọi `Parser::ParseConfig` của chính `init` để phân tích cú pháp tệp `.rc` vừa ghi vào bộ nhớ. Lúc này, `init` sẽ tiếp nhận các service/action mới giống như lúc nó đọc các file `.rc` khi khởi động.

5. **Gỡ gắn kết (Detach):**
   * Sau khi tiêm hoàn tất, `dlclose` được gọi để dọn dẹp thư viện động, khôi phục lại thanh ghi hệ thống cho `init` và gọi `ptrace(PTRACE_DETACH)` để `init` tiếp tục hoạt động bình thường.

## 3. Cách sử dụng sau khi Build

Để sử dụng công cụ này, bạn cần có thiết bị Android đã **root** (có ADB shell với quyền `su`).

### Bước 1: Build (Biên dịch mã nguồn)
Như trong `README.md` đã hướng dẫn, máy bạn cần cài đặt Android NDK và Python 3.

* Để build và xuất ra thư mục `output/`:
  ```bash
  python build.py build -t release injectrc
  ```
* Để build và đẩy trực tiếp vào thiết bị qua ADB (vào `/data/local/tmp`):
  ```bash
  python build.py deploy -t release injectrc
  ```

### Bước 2: Chuẩn bị tệp script `.rc`
Tạo một tệp `custom.rc` với nội dung bạn muốn tiêm. Ví dụ:
```rc
# custom.rc
on property:sys.test_inject=1
    setprop sys.test_result "Inject thanh cong!"
```
Đẩy tệp này vào thiết bị:
```bash
adb push custom.rc /data/local/tmp/
```

### Bước 3: Tiêm nội dung vào init
Vào shell của thiết bị và lấy quyền root:
```bash
adb shell
su
```

Cấp quyền thực thi cho `injectrc` và chạy nó để tiêm tệp `custom.rc`:
```bash
cd /data/local/tmp/
chmod +x injectrc
./injectrc custom.rc
```

### Bước 4: Kiểm tra kết quả
Kích hoạt thử trigger vừa tiêm ở trong tệp `custom.rc`:
```bash
# Thay đổi property để kích hoạt hành động
setprop sys.test_inject 1

# Kiểm tra xem hành động đã được init thực thi chưa
getprop sys.test_result
# Nếu in ra "Inject thanh cong!" tức là mã rc đã được nhúng vào init thành công.
```

**Lưu ý:**
* Chỉ hỗ trợ thiết bị chạy Android 11 trở lên (do cấu trúc động liên kết của init).
* Phải chạy bằng quyền **root**.
* Những thay đổi này là tạm thời trên RAM. Nếu khởi động lại thiết bị (Reboot), hệ thống sẽ trở về trạng thái gốc.
