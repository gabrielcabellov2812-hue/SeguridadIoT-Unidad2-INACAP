package com.inacap.seguridadiot

import android.graphics.Color
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.util.Base64
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.slider.Slider
import com.google.android.material.switchmaterial.SwitchMaterial
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {

    private val PORT = 8888
    private var serverSocket: ServerSocket? = null
    private var isServerRunning = false
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    // Semilla de sesión ingresada por el operador en el login (sin claves AES fijas en código)
    private lateinit var sessionPassphrase: String

    private lateinit var tvLocalIp: TextView
    private lateinit var etTargetIp: EditText
    private lateinit var tvConnectionStatus: TextView
    private lateinit var tvMonitorAlertState: TextView
    private lateinit var tvMonitorDetails: TextView
    private lateinit var tvMonitorLog: TextView

    private lateinit var swPirTrigger: SwitchMaterial
    private lateinit var swLightActuator: SwitchMaterial
    private lateinit var sliderDuration: Slider
    private lateinit var tvSliderLabel: TextView
    private lateinit var rgOperationMode: RadioGroup
    private lateinit var etCustomCommand: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val operator = intent.getStringExtra("OPERATOR_USER") ?: "admin"
        sessionPassphrase = intent.getStringExtra("SESSION_PASSPHRASE") ?: "iot2026"

        findViewById<TextView>(R.id.tvHeaderOperator).text =
            "Operador: $operator | Cifrado ISO/OT AES-256-GCM + PBKDF2 Activo"

        tvLocalIp = findViewById(R.id.tvLocalIp)
        etTargetIp = findViewById(R.id.etTargetIp)
        tvConnectionStatus = findViewById(R.id.tvConnectionStatus)
        tvMonitorAlertState = findViewById(R.id.tvMonitorAlertState)
        tvMonitorDetails = findViewById(R.id.tvMonitorDetails)
        tvMonitorLog = findViewById(R.id.tvMonitorLog)
        tvMonitorLog.movementMethod = ScrollingMovementMethod()

        swPirTrigger = findViewById(R.id.swPirTrigger)
        swLightActuator = findViewById(R.id.swLightActuator)
        sliderDuration = findViewById(R.id.sliderDuration)
        tvSliderLabel = findViewById(R.id.tvSliderLabel)
        rgOperationMode = findViewById(R.id.rgOperationMode)
        etCustomCommand = findViewById(R.id.etCustomCommand)

        val btnStartServer = findViewById<MaterialButton>(R.id.btnStartServer)
        val btnPingTest = findViewById<MaterialButton>(R.id.btnPingTest)
        val btnSendCommand = findViewById<MaterialButton>(R.id.btnSendCommand)

        val localIp = getLocalIpAddress()
        tvLocalIp.text = "Mi IP Local: $localIp (Puerto TCP: $PORT)"
        etTargetIp.setText(localIp)

        startServerSocket()

        btnStartServer.setOnClickListener {
            if (!isServerRunning) {
                startServerSocket()
            } else {
                Toast.makeText(this, "El servidor receptor ya está activo en el puerto $PORT", Toast.LENGTH_SHORT).show()
            }
        }

        sliderDuration.addOnChangeListener { _, value, _ ->
            tvSliderLabel.text = "Tiempo de Retardo / Intensidad Actuador: ${value.toInt()} seg"
        }

        swPirTrigger.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                swLightActuator.isChecked = true
            }
            sendIoTPacket("EVENTO_PIR")
        }

        btnPingTest.setOnClickListener {
            sendIoTPacket("PING_TEST")
        }

        btnSendCommand.setOnClickListener {
            sendIoTPacket("CONTROL_MANUAL")
        }
    }

    private fun startServerSocket() {
        scope.launch(Dispatchers.IO) {
            try {
                serverSocket = ServerSocket(PORT)
                isServerRunning = true
                withContext(Dispatchers.Main) {
                    tvConnectionStatus.text = "Estado de Red: Receptor ACTIVO escuchando en puerto $PORT"
                    appendLog("Servidor TCP iniciado con seguridad AES-256-GCM y PBKDF2.")
                }

                while (isServerRunning) {
                    val clientSocket = serverSocket?.accept() ?: break
                    val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
                    val encryptedPayload = reader.readLine()
                    clientSocket.close()

                    if (!encryptedPayload.isNullOrEmpty()) {
                        val decryptedMessage = decryptAESGCM(encryptedPayload)
                        withContext(Dispatchers.Main) {
                            processIncomingPacket(decryptedMessage)
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    tvConnectionStatus.text = "Estado de Red: Servidor detenido (${e.localizedMessage})"
                }
            }
        }
    }

    private fun sendIoTPacket(packetType: String) {
        val targetIp = etTargetIp.text.toString().trim()
        if (targetIp.isEmpty()) {
            Toast.makeText(this, "Ingrese la dirección IP del dispositivo destino", Toast.LENGTH_SHORT).show()
            return
        }

        val pirActive = if (swPirTrigger.isChecked) "MOVIMIENTO" else "NORMAL"
        val lightState = if (swLightActuator.isChecked) "ENCENDIDA" else "APAGADA"
        val duration = sliderDuration.value.toInt()
        val selectedMode = when (rgOperationMode.checkedRadioButtonId) {
            R.id.rbAutoDeterrence -> "Disuasion Automatica"
            R.id.rbNightWatch -> "Vigilancia Nocturna"
            else -> "Modo Silencioso"
        }
        val customNote = etCustomCommand.text.toString().trim().ifEmpty { "Sin nota adicional" }
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())

        val rawPayload = "$packetType|$pirActive|$lightState|$duration|$selectedMode|$customNote|$timestamp"
        val startTime = System.currentTimeMillis()

        scope.launch(Dispatchers.IO) {
            try {
                val encryptedPayload = encryptAESGCM(rawPayload)
                val socket = Socket()
                socket.connect(InetSocketAddress(targetIp, PORT), 5000)
                val writer = PrintWriter(socket.getOutputStream(), true)
                writer.println(encryptedPayload)
                socket.close()

                val latency = System.currentTimeMillis() - startTime
                withContext(Dispatchers.Main) {
                    tvConnectionStatus.text = "Último envío exitoso a $targetIp (Latencia: ${latency} ms)"
                    appendLog("TX [AES-GCM] -> [$packetType] a $targetIp (${latency}ms)")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    tvConnectionStatus.text = "Error de conexión con $targetIp: Verifique IP/Wi-Fi"
                    appendLog("ERROR TX -> Fallo al conectar con $targetIp (${e.javaClass.simpleName})")
                    Toast.makeText(this@MainActivity, "Error al enviar: revise IP destino", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun processIncomingPacket(decryptedMessage: String) {
        val parts = decryptedMessage.split("|")
        if (parts.size < 7) {
            appendLog("ALERTA OT: Trama descartada por integridad GCM o clave inválida.")
            return
        }

        val type = parts[0]
        val pirStatus = parts[1]
        val lightStatus = parts[2]
        val duration = parts[3]
        val mode = parts[4]
        val note = parts[5]
        val time = parts[6]

        if (type == "PING_TEST") {
            appendLog("[$time] PRUEBA DE ENLACE GCM RECIBIDA OK - Canal Estable.")
            Toast.makeText(this, "Prueba de interconexión recibida con éxito", Toast.LENGTH_SHORT).show()
            return
        }

        if (pirStatus == "MOVIMIENTO") {
            tvMonitorAlertState.text = "⚠️ ALERTA PATIO: MOVIMIENTO DETECTADO"
            tvMonitorAlertState.setBackgroundColor(Color.parseColor("#FFEBEE"))
            tvMonitorAlertState.setTextColor(Color.parseColor("#C62828"))
        } else {
            tvMonitorAlertState.text = "✅ ESTADO NODO PATIO: SIN MOVIMIENTO"
            tvMonitorAlertState.setBackgroundColor(Color.parseColor("#E8F5E9"))
            tvMonitorAlertState.setTextColor(Color.parseColor("#2E7D32"))
        }

        tvMonitorDetails.text = "Luz Habitación: $lightStatus | Retardo: $duration seg\n" +
                "Modo OT: $mode\nMensaje Operador: $note"

        appendLog("[$time] RX [GCM-OK] <- PIR:$pirStatus | Luz:$lightStatus (${duration}s) | $mode")
    }

    private fun appendLog(entry: String) {
        val current = tvMonitorLog.text.toString()
        tvMonitorLog.text = "$entry\n$current"
    }

    // Deriva una clave AES de 256 bits mediante PBKDF2WithHmacSHA256
    private fun deriveKeyPBKDF2(passphrase: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, 10_000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    // Cifrado autenticado AES/GCM/NoPadding con Salt (16B) e IV (12B) aleatorios por mensaje
    private fun encryptAESGCM(plainText: String): String {
        val random = SecureRandom()
        val salt = ByteArray(16)
        val iv = ByteArray(12) // Estándar NIST para GCM: 96 bits (12 bytes)
        random.nextBytes(salt)
        random.nextBytes(iv)

        val secretKey = deriveKeyPBKDF2(sessionPassphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv) // Tag de autenticación de 128 bits
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        val saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP)
        val ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        val cipherB64 = Base64.encodeToString(cipherText, Base64.NO_WRAP)

        // Formato de trama segura: SALT:IV:CIPHERTEXT
        return "$saltB64:$ivB64:$cipherB64"
    }

    private fun decryptAESGCM(encryptedPayload: String): String {
        return try {
            val parts = encryptedPayload.split(":")
            if (parts.size != 3) return "ERROR_FORMATO_GCM"

            val salt = Base64.decode(parts[0], Base64.NO_WRAP)
            val iv = Base64.decode(parts[1], Base64.NO_WRAP)
            val cipherText = Base64.decode(parts[2], Base64.NO_WRAP)

            val secretKey = deriveKeyPBKDF2(sessionPassphrase, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            String(cipher.doFinal(cipherText), Charsets.UTF_8)
        } catch (e: Exception) {
            "ERROR_DESCIFRADO_GCM"
        }
    }

    private fun getLocalIpAddress(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            for (intf in Collections.list(interfaces)) {
                for (addr in Collections.list(intf.inetAddresses)) {
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        return addr.hostAddress ?: "127.0.0.1"
                    }
                }
            }
        } catch (_: Exception) { }
        return "127.0.0.1"
    }

    override fun onDestroy() {
        super.onDestroy()
        isServerRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        scope.cancel()
    }
}