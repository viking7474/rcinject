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

## 5. Khả năng can thiệp Zygote / System_server để thay thế thư viện (.so)

**Câu hỏi:** *Cơ chế này có dùng được khi `system_server` hoặc `zygote` dùng `System.loadLibrary` để load một file `.so` không? Có thể thay thế file `.so` đó bằng file khác không?*

**Trả lời:** **Về mặt kỹ thuật cốt lõi là CÓ, nhưng bạn cần phải tự viết lại phần Payload.**

* **Cơ chế Injector dùng chung được:** Quá trình đính kèm (`ptrace`), tạo file ẩn (`memfd_create`), và ép tiến trình đích gọi `dlopen` (những gì `init_injector/injector.cpp` làm) là một kỹ thuật tiêm mã (code injection) dùng chung. Công cụ này hoàn toàn có thể nhắm mục tiêu vào PID của `zygote` hoặc `system_server` (thay vì PID 1 của `init`).
* **Tại sao cần viết lại Payload:** File `payload.cpp` hiện tại được viết *chỉ dành riêng* cho cấu trúc nội bộ của tiến trình `init` (tìm các hàm `ActionManager`, `ServiceList`). Nếu bạn tiêm nó vào `zygote`, nó sẽ lỗi vì `zygote` không chứa các hàm đó.
* **Giải pháp thay thế `.so` thực tế:**
  1. Bạn giữ nguyên `injector.cpp`.
  2. Bạn viết một `payload.cpp` mới chứa mã nhúng Hooking (ví dụ sử dụng thư viện Dobby, xhook, hoặc riru/zygisk core code).
  3. Khi tiêm payload mới này vào `zygote`/`system_server`, payload sẽ thực hiện **Hook hàm `dlopen` (hoặc `android_dlopen_ext`)** hoặc các hàm JNI liên quan.
  4. Mỗi khi Java gọi `System.loadLibrary("libA.so")`, hàm hook của bạn trên RAM sẽ can thiệp và ép hệ thống chuyển hướng tải file `libB.so` (file bạn muốn thay thế) thay cho `libA.so`.

## 6. Vô hiệu hóa script (.rc) của hệ thống mà không cần sửa đổi file

**Câu hỏi:** *Có một script rc nằm ở `/system`, tôi không muốn xoá/edit file vật lý nhưng muốn vô hiệu hóa nó, mã này có phương án không?*

**Trả lời:** **CÓ THỂ, thông qua việc thao tác trực tiếp trên bộ nhớ (RAM) bằng C++ trong `payload.cpp`.**

Khi Android khởi động, tiến trình `init` đọc tất cả các file `.rc` ở `/system` và nạp vào bộ nhớ RAM. Các thông tin này được lưu giữ dưới dạng các đối tượng C++ trong 2 danh sách chính quản lý bởi `init`:
* `ActionManager`: Chứa các hành động (như `on property:...`)
* `ServiceList`: Chứa các dịch vụ (như `service ...`)

Nhìn vào `payload.cpp`, mã nguồn này **đã lấy được quyền truy cập trực tiếp (con trỏ tham chiếu)** vào 2 danh sách này trên RAM:
```cpp
FIND_SYM(ServiceList::GetInstance_fn, kServiceListGetInstance)
FIND_SYM(ActionManager::GetInstance_fn, kActionManagerGetInstance)

auto& action_manager = ActionManager::GetInstance_fn();
auto& service_list = ServiceList::GetInstance_fn();
```

**Phương án vô hiệu hóa (Không chạm vào file):**
Thay vì dùng mã này để thêm (Inject) cấu hình mới bằng `ParseConfig`, bạn có thể sửa trực tiếp mã C++ của `payload.cpp` trong hàm `Entry()` để **xóa hoặc vô hiệu hóa cấu hình đang có sẵn trên RAM**:

1. **Với Service:** Bạn có thể lặp (loop) qua `service_list`, lấy tên của từng service. Nếu tên trùng với service nằm trong tệp `/system` mà bạn muốn tắt, bạn thay đổi các thuộc tính trạng thái (flags) của nó thành vô hiệu hóa (disabled), hoặc gọi hàm nội bộ để gỡ nó khỏi danh sách. Vì `init` quản lý service trên RAM, khi xóa khỏi RAM, service đó coi như "chết" mặc dù file chữ trên `/system/etc/init/` vẫn còn nguyên.
2. **Với Action/Trigger:** Bạn có thể lặp qua `action_manager`, tìm chuỗi trigger mà bạn không mong muốn, rồi xóa bỏ danh sách các lệnh (commands) bên trong action đó.

*Tóm lại, InjectRC là "chìa khóa" đưa code C++ của bạn vào giữa "đầu não" `init`. Một khi đã vào được (như file `payload.cpp`), bạn có toàn quyền thao tác với các biến quản lý service/action của Android trên RAM mà không cần động đến bất kỳ file vật lý nào.*

## 7. Thay thế một hàm của một file `.so` ngay trong giai đoạn init

**Câu hỏi:** *Dựa vào mã này có thể inject để thay thế 1 hàm của 1 file `.so` ở giai đoạn `init` hay không?*

**Trả lời:** **CÓ, hoàn toàn có thể.**

Mã nguồn `InjectRC` hiện tại đã bao gồm **90%** những thành phần cốt lõi mạnh mẽ nhất cần thiết để thực hiện việc thay thế (hooking) một hàm của bất kỳ file `.so` nào đang được nạp bởi tiến trình `init` (hoặc bất kỳ tiến trình nào khác).

**Tại sao nó làm được?**
Hãy nhìn vào các thư viện đi kèm trong mã nguồn:
1. `injector.cpp` (ptrace, memfd, dlopen): Đã giải quyết được bài toán khó nhất là làm sao "bơm" (inject) code C++ của bạn vào một tiến trình đang chạy (kể cả `init` với đặc quyền cao nhất) mà không làm sập nó.
2. `maps_scan`: Thư viện này cho phép duyệt `/proc/PID/maps` để tìm chính xác địa chỉ cơ sở (base address) mà file `.so` mục tiêu đang được nạp trên RAM.
3. `elf_parser`: Thư viện này phân tích bảng symbol (bảng tên hàm) của file thực thi hoặc file `.so`, giúp bạn dịch từ tên hàm (ví dụ: `my_target_function`) ra một địa chỉ bộ nhớ tuyệt đối.

*(Thực tế, `payload.cpp` đang dùng chính 3 thứ trên để tìm và gọi hàm `ParseConfig` của `init`. Việc thay thế hàm cũng làm y hệt vậy).*

**Cách triển khai (Những gì bạn cần code thêm):**

Nếu bạn muốn thay thế hàm `check_security()` của file `libcrypto.so` bên trong `init`:

**Bước 1: Viết hàm thay thế trong `payload.cpp`**
```cpp
// Đây là hàm giả mạo của bạn
int my_fake_check_security() {
    LOGI("Hacked security check!");
    return 1; // Luôn trả về pass
}
```

**Bước 2: Tìm địa chỉ hàm gốc**
Sử dụng `maps_scan` và `elf_parser` (như cách `Entry()` đang làm) để tìm địa chỉ của `check_security` trong RAM:
```cpp
// ... (code maps_scan tìm base address của libcrypto.so) ...
// ... (code elf_parser tìm offset của check_security) ...
void* target_func_addr = (void*) elf.getSymbAddress("check_security");
```

**Bước 3: Thực hiện thay thế (Inline Hooking)**
Đây là bước duy nhất mà `InjectRC` chưa có sẵn. Để thay thế hàm tại địa chỉ `target_func_addr` bằng `my_fake_check_security`, bạn cần tích hợp thêm một thư viện Inline Hooking nhẹ (phổ biến nhất trên Android C/C++ là **Dobby** hoặc **xhook**).

Chỉ cần gọi hàm hook của thư viện đó ngay trong `Entry()` của `payload.cpp`:
```cpp
#include <dobby.h>

// Hook hàm
DobbyHook(target_func_addr, (void*)my_fake_check_security, (void**)&original_check_security);
```

**Kết luận:**
Bạn dùng `injector` để bắn `payload.so` vào `init`. Khi `payload.so` được kích hoạt, nó tự tìm hàm mục tiêu bằng `elf_parser` và dùng `Dobby` đè mã máy (machine code) của hàm gốc để ép nó chạy sang hàm C++ giả mạo của bạn. Tất cả diễn ra trên RAM (On-the-fly) ngay trong lúc `init` đang chạy.

## 8. Khả năng thay thế Zygisk để hook Zygote

**Câu hỏi:** *Mã này có thể thay thế các chức năng của Zygisk để hook Zygote hay không?*

**Trả lời:** **Về lý thuyết nền tảng là CÓ (dùng làm công cụ chèn mã), nhưng trong thực tế thì KHÔNG THỂ THAY THẾ HOÀN TOÀN trừ khi bạn tự viết thêm một lượng code khổng lồ.**

Để hiểu rõ, chúng ta cần phân biệt giữa một **"Công cụ tiêm mã" (Injector - như mã nguồn này)** và một **"Bộ khung tích hợp" (Framework - như Zygisk)**.

**Điểm tương đồng (Nơi InjectRC có thể thay thế Zygisk):**
Bước đầu tiên của Zygisk là làm sao để đưa được mã của nó vào trong tiến trình `zygote` khi máy vừa khởi động. Mã nguồn `injector.cpp` của bạn (dùng `ptrace`, `memfd`, `dlopen`) hoàn toàn thực hiện xuất sắc nhiệm vụ này. Nó đủ sức đẩy một file `.so` của bạn vào `zygote`.

**Tại sao InjectRC KHÔNG THỂ thay thế Zygisk ngay lập tức?**

Nếu bạn chỉ dùng mã này tiêm một file `.so` vào `zygote`, bạn sẽ thiếu những tính năng cực kỳ quan trọng mà Zygisk đã mất nhiều năm để hoàn thiện:

1. **Quản lý vòng đời App (App Specialize Hooking):**
   * Zygote là tiến trình mẹ. Khi bạn mở một ứng dụng (ví dụ: Facebook), Zygote sẽ nhân bản (fork) chính nó ra để tạo thành Facebook.
   * **Zygisk** hook sâu vào các hàm `nativePreAppSpecialize` và `nativePostAppSpecialize` của Zygote. Nhờ đó, Zygisk biết chính xác lúc nào App được sinh ra, tên gói (package name) là gì, để quyết định có load module của bạn vào App đó hay không.
   * **InjectRC** chỉ thả cục payload của bạn vào Zygote. Để theo dõi App mở lên, payload của bạn sẽ phải tự tìm và tự hook các hàm `fork` này.

2. **Vượt rào SELinux (SELinux Bypass/Context):**
   * Khi Zygote fork thành App, quyền hạn của nó bị giảm xuống (chuyển sang untrusted_app context) và bị SELinux kiểm soát gắt gao.
   * Nếu payload của bạn (tiêm bằng InjectRC) cố gắng mở một file trong `/data/local/tmp` hoặc thực thi code trái phép sau khi fork, App sẽ crash ngay lập tức do bị SELinux chặn (avc denied).
   * **Zygisk** tự động cung cấp bộ API để lấy file descriptor an toàn và dọn dẹp các quy tắc SELinux tinh vi để module chạy mượt mà.

3. **Cơ chế ẩn mình (Hide/Denylist/Unmount):**
   * **Zygisk** tự động gỡ (unmount) các dấu vết của nó và module khỏi các không gian tên (mount namespace) của các ứng dụng ngân hàng, game để chống phát hiện (anti-cheat).
   * Dùng InjectRC, thư viện `.so` của bạn sẽ nằm tơ hơ trong `/proc/PID/maps` của App, và sẽ bị app ngân hàng phát hiện ngay lập tức.

4. **Hệ sinh thái API:**
   * Zygisk định nghĩa một bộ `api.h` chuẩn mực. Hàng ngàn lập trình viên chỉ việc viết `RegisterModule` là xong. Với InjectRC, bạn phải tự thao tác thủ công từng con trỏ bộ nhớ một.

**Tóm lại:**
Mã nguồn `InjectRC` giống như **"một mũi kim tiêm"**, còn **Zygisk** là **"cả một hệ thống y tế"**. Bạn hoàn toàn có thể dùng `InjectRC` làm công cụ nền tảng (bước đầu tiên) để chui vào `Zygote`. Nhưng sau khi chui vào xong, file `payload.cpp` của bạn sẽ phải gánh vác việc tự viết lại logic hook `fork()`, tự xử lý SELinux, và tự xóa dấu vết – những thứ mà Zygisk đã làm sẵn cho bạn.
