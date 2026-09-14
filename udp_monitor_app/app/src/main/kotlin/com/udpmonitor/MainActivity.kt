package com.udpmonitor

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.method.ScrollingMovementMethod
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.regex.Pattern

/**
 * UDP 实时监听器
 *
 * 抓包方案：需要 root（已 root 的手机 / Magisk）。
 * 通过 su 调用系统里的 tcpdump 对 "热点下的 UDP 下行流量" 进行被动抓包，
 * 实时显示「源IP:端口 -> 目的IP:端口」及负载（hex + ascii），并把每条包写入日志文件。
 */
class MainActivity : Activity() {

    private lateinit var tvLog: TextView
    private lateinit var etPort: EditText
    private lateinit var btnToggle: Button
    private lateinit var btnClear: Button
    private lateinit var tvStatus: TextView

    private val ui = Handler(Looper.getMainLooper())
    private val bufferLines = StringBuilder()   // 界面上的文本（带条数上限）
    private var writer: BufferedWriter? = null  // 日志文件写入
    private var logFile: File? = null
    private var process: Process? = null
    private var captureThread: Thread? = null
    private var running = false
    private var packetCount = 0

    // 单屏最多显示的行数，防止内存无限增长
    private val maxLines = 800

    // tcpdump 行解析
    private val pktRe = Pattern.compile(
        "^\\S+\\s+IP\\s+([0-9.]+)\\.(\\d+)\\s+>\\s+([0-9.]+)\\.(\\d+).*?\\bUDP(.*)\$"
    )
    private val lenRe = Pattern.compile("\\blength (\\d+)")
    private val hexlineRe = Pattern.compile("^\\s*0x[0-9a-fA-F]+:\\s+(.*)\$")
    private val hexTokenRe = Pattern.compile("[0-9a-fA-F]{2}")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvLog = findViewById(R.id.tvLog)
        etPort = findViewById(R.id.etPort)
        btnToggle = findViewById(R.id.btnToggle)
        btnClear = findViewById(R.id.btnClear)
        tvStatus = findViewById(R.id.tvStatus)

        tvLog.movementMethod = ScrollingMovementMethod()

        btnToggle.setOnClickListener {
            if (running) stopCapture() else startCapture()
        }
        btnClear.setOnClickListener { clearLog() }

        tvStatus.text = "未开始 · 需要 root"
    }

    // ---- 生命周期 ----
    override fun onStop() {
        super.onStop()
        // 离开界面时停止抓包，避免后台持续占用
        if (running) stopCapture()
    }

    override fun onDestroy() {
        closeWriter()
        super.onDestroy()
    }

    // -------------------------------------------------------------
    // 抓包控制
    // -------------------------------------------------------------
    private fun startCapture() {
        if (!isRooted()) {
            toast("未检测到 root 权限，被动抓包需要 root 手机")
            return
        }

        val portFilter = etPort.text.toString().trim()
        val bpf = if (portFilter.isEmpty()) "udp" else "udp and port $portFilter"

        // 解压内置的 arm64 tcpdump 到私有目录（如果还没有）
        val tcpdumpPath = extractBundledTcpdump()
        if (tcpdumpPath == null) {
            toast("内置 tcpdump 解压失败")
            return
        }

        // 初始化日志文件
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val dir = getExternalFilesDir(null) ?: filesDir
        logFile = File(dir, "udp_capture_$ts.log")
        try {
            writer = BufferedWriter(FileWriter(logFile))
        } catch (e: Exception) {
            toast("无法创建日志文件: ${e.message}")
            return
        }

        // 用 root(su) 运行内置 tcpdump
        val cmd = "\"$tcpdumpPath\" -i any -l -n -X \"$bpf\""
        try {
            process = ProcessBuilder("su", "-c", cmd).start()
        } catch (e: Exception) {
            toast("启动 tcpdump 失败（su 不可用？）: ${e.message}")
            closeWriter()
            return
        }

        running = true
        packetCount = 0
        bufferLines.setLength(0)
        tvLog.text = ""

        appendLine("== 开始抓包，过滤: $bpf ==")
        appendLine("== 保存至: ${logFile!!.absolutePath} ==")
        ui.post { btnToggle.text = "停止"; tvStatus.text = "抓包中…" }

        captureThread = Thread(CaptureRunnable(process!!), "capture").also { it.start() }

        // 监听进程意外退出
        Thread {
            try {
                process!!.waitFor()
                if (running) {
                    ui.post {
                        toast("tcpdump 已退出（$cmd）")
                        running = false
                        btnToggle.text = "开始"; tvStatus.text = "已停止（tcpdump 退出）"
                    }
                    closeWriter()
                }
            } catch (_: InterruptedException) {
            }
        }.start()
    }

    private fun stopCapture() {
        running = false
        appendLine("== 抓包已停止，共捕获 $packetCount 个 UDP 包 ==")
        try {
            process?.destroy()
        } catch (_: Exception) {
        }
        closeWriter()
        ui.post {
            btnToggle.text = "开始"
            tvStatus.text = "已停止 · 日志: ${logFile?.name ?: "-"}"
        }
    }

    private fun closeWriter() {
        try {
            writer?.flush()
            writer?.close()
        } catch (_: Exception) {
        }
        writer = null
    }

    private fun clearLog() {
        bufferLines.setLength(0)
        tvLog.text = ""
    }

    // -------------------------------------------------------------
    // 抓取循环（后台线程），解析 tcpdump -l -X 输出
    // -------------------------------------------------------------
    private inner class CaptureRunnable(proc: Process) : Runnable {
        private val reader = BufferedReader(InputStreamReader(proc.inputStream))

        override fun run() {
            // 当前正在累积的包
            var curTime = ""
            var curSrc = ""
            var curSport = 0
            var curDst = ""
            var curDport = 0
            var curLen = 0
            var curHex = StringBuilder()

            fun commit() {
                if (curHex.isNotEmpty() || curLen > 0) {
                    val pktText = formatPacket(
                        curTime, curSrc, curSport, curDst, curDport, curLen, curHex.toString()
                    )
                    appendLine(pktText)
                    packetCount++
                }
                curHex = StringBuilder()
            }

            while (running) {
                val text = reader.readLine() ?: break
                val m = pktRe.matcher(text)
                if (m.matches()) {
                    commit()
                    curTime = text.substringBefore(" ")
                    curSrc = m.group(1)
                    curSport = m.group(2).toInt()
                    curDst = m.group(3)
                    curDport = m.group(4).toInt()
                    val detail = m.group(5) ?: ""
                    val lm = lenRe.matcher(detail)
                    curLen = if (lm.find()) lm.group(1).toIntOrNull() ?: 0 else 0
                    continue
                }
                val hm = hexlineRe.matcher(text)
                if (hm.matches()) {
                    val tokens = hm.group(1).split(" ").filter { hexTokenRe.matcher(it).matches() }
                    if (tokens.isNotEmpty()) curHex.append(tokens.joinToString(" ")).append(' ')
                }
            }
            if (running) commit()
        }
    }

    // -------------------------------------------------------------
    // 格式化 / 显示
    // -------------------------------------------------------------
    private fun formatPacket(
        time: String, src: String, sport: Int,
        dst: String, dport: Int, len: Int, hex: String
    ): String {
        val sb = StringBuilder()
        sb.append("[$time] $src:$sport -> $dst:$dport  len=$len\n")
        val ascii = toAscii(hex)
        if (ascii.isNotEmpty()) sb.append("  ascii: $ascii\n")
        if (hex.isNotEmpty()) {
            val hexLine = if (hex.length > 160) hex.take(160) + "..." else hex
            sb.append("  hex  : $hexLine\n")
        }
        return sb.toString()
    }

    private fun toAscii(hex: String): String {
        if (hex.isBlank()) return ""
        val tokens = if (hex.contains(" ")) hex.trim().split(" ")
        else hex.chunked(2)
        val sb = StringBuilder()
        for (t in tokens) {
            val b = t.trim().toIntOrNull(16) ?: continue
            sb.append(if (b in 0x20..0x7E) b.toChar() else '.')
        }
        return sb.toString()
    }

    /** 追加一行到界面与日志文件（线程安全：写入用同步 + UI 回调） */
    private fun appendLine(text: String) {
        // 写入日志文件
        try {
            synchronized(this) {
                writer?.let { w -> w.write(text); w.write("\n"); w.flush() }
            }
        } catch (_: Exception) {
        }
        // 更新界面
        ui.post {
            bufferLines.append(text).append('\n')
            // 裁剪过长的行数
            while (bufferLines.toString().lines().size > maxLines) {
                val idx = bufferLines.indexOf("\n")
                if (idx < 0) break
                bufferLines.delete(0, idx + 1)
            }
            tvLog.text = bufferLines.toString()
            // 自动滚到底部
            tvLog.post {
                val lineCount = tvLog.layout.takeIf { it != null }?.let { tvLog.layout.lineCount } ?: 0
                tvLog.scrollY = (lineCount * tvLog.lineHeight)
            }
        }
    }

    // -------------------------------------------------------------
    // 工具
    // -------------------------------------------------------------

    /** 把内置在 assets 里的 arm64 tcpdump 解压到私有目录并加可执行权限，返回路径 */
    private fun extractBundledTcpdump(): String? {
        return try {
            val target = File(filesDir, "tcpdump")
            if (!target.exists() || target.length() == 0L) {
                assets.open("tcpdump").use { input ->
                    target.outputStream().use { out -> input.copyTo(out) }
                }
            }
            // 置为可执行
            Runtime.getRuntime().exec(arrayOf("chmod", "0755", target.absolutePath)).waitFor()
            if (target.exists() && target.canExecute()) target.absolutePath else null
        } catch (e: Exception) {
            null
        }
    }

    private fun isRooted(): Boolean {
        for (binary in listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk")) {
            if (File(binary).exists()) return true
        }
        return try {
            val p = ProcessBuilder("su", "-c", "id").start()
            val r = BufferedReader(InputStreamReader(p.inputStream))
            val first = r.readLine()
            p.destroy()
            first != null && first.contains("uid=0")
        } catch (_: Exception) {
            false
        }
    }

    private fun toast(msg: String) =
        ui.post { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
}