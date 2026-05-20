# InjectRC

向运行时的 Android init 进程注入 [init rc 脚本](https://android.googlesource.com/platform/system/core/+/a3b721a32242006b59cb12bd62c9133632af3a2d/init/README.md)

目前只支持动态链接的 init ，即 Android 版本大于等于 11

## 用法

```
./injectrc <rc 脚本路径>
```

## 构建

需要安装 Android NDK ，构建脚本需要 Python3

```
# 构建，输出到 output 目录
python build.py build [-t release] injectrc
# 直接通过 adb 安装到设备上的 /data/local/tmp
python build.py deploy [-t release] injectrc
```
