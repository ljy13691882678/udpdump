# UDP 监听（UdpMonitor）

手机热点 UDP 实时监听 App。运行在已 **root** 的 Android 手机上，通过 `su` + `tcpdump`
对经过手机热点的 UDP 下行流量（目标 App 服务器 -> 客户端）进行被动抓包，
**实时显示**「源IP:端口 -> 目的IP:端口」及负载内容（hex + ascii），并把抓到的包**保存为日志文件**。

## 功能
- 实时显示抓到的 UDP 包（地址端口、长度、hex / ascii 负载）
- 可选按端口过滤
- 每次点击“开始”会新建一个日志文件，保存所有抓到的包
- 清屏 / 停止

## 抓包原理与权限
- 需要 **root** 手机（Magisk 等），且系统里需要有 `tcpdump`。
- App 通过 `su -c "tcpdump ..."` 被动抓包，手机作为热点网关能看到所有经过的下行 UDP。
- 日志保存在 App 私有外部目录：
  `/storage/emulated/0/Android/data/com.udpmonitor/files/udp_capture_*.log`

## 如何得到 APK（云端 CI 编译）
本仓库不在本地编译，而是推到 GitHub 后由 **GitHub Actions** 自动编译：

1. 把工程推到你自己的 GitHub 仓库
   ```bash
   git init
   git add .
   git commit -m "init"
   git branch -M main
   git remote add origin https://github.com/<你的用户名>/<仓库名>.git
   git push -u origin main
   ```
2. 打开 GitHub 对应仓库 → **Actions** 页 → “Build APK” 工作流运行
3. 运行完成后，在运行结果底部的 **Artifacts** 里下载
   `udp-monitor-debug-apk`（调试版）即可安装。

> 手动重编：Actions 页左侧选中 “Build APK” → 右侧 “Run workflow” 下拉里选 main 分支 → Run。

## 部署需要 root 前置
- 手机已 **root**（如 Magisk）——被动抓取热点上其它设备的下行 UDP，系统强制要求 root，无法免除
- tcpdump 已内置在 APK 里：CI 会用 Android NDK 从源码交叉编译 arm64 静态 `tcpdump`，App 启动时自动解压到私有目录运行，**无需单独安装 tcpdump**

## 本地开发（可选）
已安装 Android SDK 时可本地编译：
```bash
cd udp_monitor_app
./gradlew assembleDebug
```
产物：`app/build/outputs/apk/debug/app-debug.apk`