package com.inacap.seguridadiot

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Base64
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class LoginActivity : AppCompatActivity() {

    private val maxAttempts = 3
    private val lockoutDurationMs = 30_000L // 30 segundos de bloqueo
    private val prefsName = "SeguridadIoT_AuthPrefs"
    private val keyFailedAttempts = "failed_attempts"
    private val keyLockoutUntil = "lockout_until"

    private lateinit var dbHelper: UserDatabaseHelper
    private var lockoutTimer: CountDownTimer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        dbHelper = UserDatabaseHelper(this)
        val prefs = getSharedPreferences(prefsName, Context.MODE_PRIVATE)

        val etUsername = findViewById<TextInputEditText>(R.id.etUsername)
        val etPassword = findViewById<TextInputEditText>(R.id.etPassword)
        val btnLogin = findViewById<MaterialButton>(R.id.btnLogin)
        val tvLoginStatus = findViewById<TextView>(R.id.tvLoginStatus)

        // Verificar al abrir la app si existe un bloqueo activo
        checkAndApplyLockout(prefs, btnLogin, tvLoginStatus)

        btnLogin.setOnClickListener {
            val now = System.currentTimeMillis()
            val lockoutUntil = prefs.getLong(keyLockoutUntil, 0L)

            if (now < lockoutUntil) {
                checkAndApplyLockout(prefs, btnLogin, tvLoginStatus)
                return@setOnClickListener
            }

            val user = etUsername.text.toString().trim()
            val pass = etPassword.text.toString().trim()

            if (user.isEmpty() || pass.isEmpty()) {
                Toast.makeText(this, "Complete usuario y contraseña", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (dbHelper.validateCredentials(user, pass)) {
                // Login exitoso: limpiar intentos y bloqueo en SharedPreferences
                prefs.edit()
                    .putInt(keyFailedAttempts, 0)
                    .putLong(keyLockoutUntil, 0L)
                    .apply()

                Toast.makeText(this, "Autenticación exitosa. Bienvenido $user", Toast.LENGTH_SHORT).show()
                val intent = Intent(this, MainActivity::class.java)
                intent.putExtra("OPERATOR_USER", user)
                // Pasamos el código de sesión para derivar la clave AES/GCM en MainActivity
                intent.putExtra("SESSION_PASSPHRASE", pass)
                startActivity(intent)
                finish()
            } else {
                val currentFailures = prefs.getInt(keyFailedAttempts, 0) + 1
                if (currentFailures >= maxAttempts) {
                    val newLockoutUntil = System.currentTimeMillis() + lockoutDurationMs
                    prefs.edit()
                        .putInt(keyFailedAttempts, 0) // Reinicia el contador para después del castigo
                        .putLong(keyLockoutUntil, newLockoutUntil)
                        .apply()

                    Toast.makeText(this, "Acceso bloqueado por 30 segundos", Toast.LENGTH_LONG).show()
                    checkAndApplyLockout(prefs, btnLogin, tvLoginStatus)
                } else {
                    prefs.edit().putInt(keyFailedAttempts, currentFailures).apply()
                    val restantes = maxAttempts - currentFailures
                    tvLoginStatus.text = "Credenciales inválidas (PBKDF2/SQLite). Intentos restantes: $restantes"
                    Toast.makeText(this, "Error de autenticación", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun checkAndApplyLockout(
        prefs: android.content.SharedPreferences,
        btnLogin: MaterialButton,
        tvLoginStatus: TextView
    ) {
        val remainingMs = prefs.getLong(keyLockoutUntil, 0L) - System.currentTimeMillis()
        if (remainingMs > 0) {
            btnLogin.isEnabled = false
            lockoutTimer?.cancel()
            lockoutTimer = object : CountDownTimer(remainingMs, 1000) {
                override fun onTick(millisUntilFinished: Long) {
                    val sec = (millisUntilFinished / 1000) + 1
                    tvLoginStatus.text = "BLOQUEADO ISO 27001: Reintente en ${sec}s"
                }

                override fun onFinish() {
                    btnLogin.isEnabled = true
                    tvLoginStatus.text = "Tiempo de bloqueo finalizado. Puede reintentar."
                }
            }.start()
        } else {
            btnLogin.isEnabled = true
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        lockoutTimer?.cancel()
    }
}

class UserDatabaseHelper(context: Context) : SQLiteOpenHelper(context, "SeguridadIoT_Users.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                salt_b64 TEXT NOT NULL,
                hash_b64 TEXT NOT NULL
            )
            """.trimIndent()
        )
        // Usuarios iniciales precargados con sal aleatoria única y PBKDF2
        insertUserWithPBKDF2(db, "admin", "iot2026")
        insertUserWithPBKDF2(db, "operador", "ot2026")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS users")
        onCreate(db)
    }

    private fun insertUserWithPBKDF2(db: SQLiteDatabase, username: String, plainPass: String) {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        val hash = pbkdf2(plainPass, salt)

        val values = ContentValues().apply {
            put("username", username)
            put("salt_b64", Base64.encodeToString(salt, Base64.NO_WRAP))
            put("hash_b64", Base64.encodeToString(hash, Base64.NO_WRAP))
        }
        db.insert("users", null, values)
    }

    fun validateCredentials(username: String, plainPass: String): Boolean {
        val db = readableDatabase
        val cursor = db.rawQuery(
            "SELECT salt_b64, hash_b64 FROM users WHERE username = ?",
            arrayOf(username)
        )
        cursor.use {
            if (!it.moveToFirst()) return false
            val salt = Base64.decode(it.getString(0), Base64.NO_WRAP)
            val expectedHash = Base64.decode(it.getString(1), Base64.NO_WRAP)
            val candidateHash = pbkdf2(plainPass, salt)
            return MessageDigest.isEqual(expectedHash, candidateHash)
        }
    }

    private fun pbkdf2(password: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, 10_000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }
}