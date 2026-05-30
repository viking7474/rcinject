# Phân tích và Hướng dẫn sử dụng InjectRC

## 1. Tác dụng thực tế của mã nguồn (Mục đích)

**InjectRC** là một công cụ dành cho thiết bị Android (yêu cầu quyền root, Android 11 trở lên), dùng để **tiêm (inject) các file cấu hình init (.rc) trực tiếp vào tiến trình `init` của Android đang chạy** mà không cần phải khởi động lại máy hoặc sửa đổi phân vùng hệ thống (system partition).

**Tác dụng thực tế:**
* **Chỉnh sửa hệ thống "On-the-fly" (Trực tiếp):** Cho phép các nhà phát triển, người can thiệp hệ thống (modder) thêm các dịch vụ (services) mới, hoặc các hành động (actions) vào hệ thống (như tự động chạy script khi một thuộc tính property thay đổi) ngay lập tức.
* **Vượt qua giới hạn Read-only:** Các phân vùng hệ thống Android thường là chỉ đọc (read-only) và việc sửa `init.rc` gốc rất khó khăn (có thể làm brick thiết bị hoặc bị kẹt bootloop). Công cụ này nạp mã cấu hình vào bộ nhớ tiến trình `init` đang chạy, giúp tạo các tinh chỉnh tạm thời (sẽ mất sau khi khởi động lại).

**Một số ứng dụng thực tế cụ thể:**
1. **Chạy Service tàng hình (Stealth Service):** Bạn có thể khởi tạo một tiến trình chạy ngầm qua `init` với đầy đủ quyền hạn (context) của hệ thống mà không để lại vết lưu trên phân vùng boot/system. Hữu ích cho các ứng dụng giám sát hoặc cheat game.
2. **Khởi động ứng dụng/script từ xa:** Chèn một action chạy tự động (ví dụ: `on property:sys.my_trigger=1 \n start my_service`) để có thể điều khiển chạy một nhị phân đặc quyền bất cứ lúc nào thông qua `setprop`.
3. **Sửa lỗi hệ thống tạm thời:** Tiêm cấu hình `.rc` thay đổi quyền (chown/chmod) hoặc khởi động lại các daemon bị kẹt mà không cần phải mount lại phân vùng.

## 2. Cơ chế hoạt động

Cơ chế hoạt động của InjectRC kết hợp nhiều kỹ thuật phức tạp trong môi trường Linux/Android:

1. **Gắn kết (Attach) vào tiến trình init:**
   * Công cụ sử dụng hệ thống gọi `ptrace` (Process Trace) để đính kèm (attach) và tạm dừng tiến trình `init` (PID = 1) của Android.

2. **Dừng tại Syscall an toàn:**
   * Nó đợi tiến trình `init` thực hiện một syscall an toàn (`__NR_epoll_pwait`) để tiến hành chèn mã mà không làm hỏng trạng thái hiện tại.

3. **Tạo và tải thư viện động (Payload):**
   * Công cụ tạo một "file ẩn" trong bộ nhớ bằng `memfd_create`.
   * Nó sao chép payload (là một thư viện động `.so`, có chứa mã `Entry()`) vào file ẩn này.
   * Thông qua `ptrace`, InjectRC ép tiến trình `init` gọi hàm `dlopen` từ Android linker để tải thư viện payload này vào vùng nhớ của `init`.

4. **Thực thi Payload trong init (`payload.cpp`):**
   * Khi payload được nạp, nó sẽ tìm kiếm địa chỉ các hàm nội bộ của `init` (bằng cách phân tích `/system/bin/init` trong bộ nhớ qua `maps_scan` và `elf_parser`). Các hàm bị nhắm mục tiêu là `CreateParser`, `ParseConfig`, `ActionManager::GetInstance` và `ServiceList::GetInstance`.
   * Nó dùng `memfd_create` để tạo một tệp tạm thời khác (ẩn trong RAM).
   * `injector` (bên ngoài) sẽ ghi nội dung tệp `.rc` vào tệp tạm này thông qua `ptrace`.
   * Payload gọi `Parser::ParseConfig` của `init` để phân tích cú pháp tệp `.rc` vừa ghi vào bộ nhớ. Lúc này, `init` sẽ tiếp nhận các service/action mới.

5. **Gỡ gắn kết (Detach):**
   * Sau khi tiêm hoàn tất, `dlclose` được gọi để dọn dẹp thư viện động và gọi `ptrace(PTRACE_DETACH)` để `init` tiếp tục hoạt động.

## 3. Không cần ghi file RC ra bộ nhớ vật lý (Disk)

Bạn hoàn toàn **KHÔNG CẦN** phải tạo một file `.rc` lưu trên bộ nhớ đệm hoặc ổ đĩa cứng của thiết bị (disk).

Mã nguồn của `InjectRC` hiện tại sử dụng `memfd_create` (tạo một tệp ảo hoàn toàn nằm trên RAM - bộ nhớ chính) để qua mặt hệ thống. Dữ liệu cấu hình `.rc` sẽ được truyền thẳng từ công cụ chèn vào không gian RAM của `init`.

Nếu muốn **tích hợp sẵn mã RC thẳng vào mã nguồn (Hardcode/Embed)**:
Bạn có thể bỏ qua việc truyền file từ bên ngoài, và ghi trực tiếp nội dung chuỗi vào `init_injector/payload.cpp`. Nhìn vào file `payload.cpp`, tác giả đã để sẵn một đoạn code bị comment:

```cpp
/*
static const char kInjectedRc[] = ""
"on property:sys.aaa=*\n"
"    setprop sys.bbb 11111\n"
"\n"
;*/
```
Bạn có thể bỏ comment, điền nội dung `init` bạn muốn vào chuỗi này, sau đó ở phía dưới hàm `Entry()`, bật lại dòng ghi nội dung:
```cpp
    if (!write_fully(fd, kInjectedRc, sizeof(kInjectedRc) - 1)) {
        LOGE("not fully written");
        return 3;
    }
```
Lúc này bạn chỉ cần chạy `./injectrc` mà không cần truyền thêm bất kỳ file `.rc` nào từ disk, mọi thứ đã được biên dịch cùng với mã nguồn payload.

## 4. Tích hợp và chạy cùng Magisk hoặc KernelSU

Một trong những ứng dụng phổ biến nhất là nhúng `injectrc` vào module của **Magisk** hoặc **KernelSU** để hệ thống tự động tiêm mã vào `init` mỗi khi thiết bị khởi động ở giai đoạn late_start hoặc post-fs-data.

### Cấu trúc Module Magisk/KernelSU cơ bản:
```text
module.zip
│
├── META-INF/
│   └── com/google/android/update-binary, updater-script
├── customize.sh
├── module.prop
├── post-fs-data.sh      <-- Chạy ở giai đoạn sớm
├── service.sh           <-- Chạy ở giai đoạn trễ (late_start)
└── system/
    └── bin/
        └── injectrc     <-- Binary đã build (copy vào đây)
```

### Mẫu file `service.sh` hoặc `post-fs-data.sh`:

Cách 1: Nếu bạn sử dụng file RC đi kèm:
```bash
#!/system/bin/sh
MODDIR=${0%/*}

# Đợi hệ thống khởi động ổn định một chút (tuỳ chọn)
sleep 2

# Chạy injectrc để nạp file rc đi kèm
$MODDIR/system/bin/injectrc $MODDIR/my_custom.rc
```

Cách 2: (Khuyên dùng) Nếu bạn đã nhúng cứng mã `.rc` vào source C++ (như phần 3):
```bash
#!/system/bin/sh
MODDIR=${0%/*}

# Chạy binary injectrc đã được hardcode nội dung rc bên trong mà không cần file ngoài
$MODDIR/system/bin/injectrc
```

Sau khi máy khởi động lại và module Magisk/KernelSU được nạp, cấu hình ẩn của bạn sẽ tự động được tiêm thẳng vào quá trình hệ thống đang chạy.
