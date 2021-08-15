package br.com.amorim.crypto.crypto

import android.util.Base64

class Base64Wrapper {
    fun decode(message: String): ByteArray = Base64.decode(message, Base64.DEFAULT)
    fun encodeToString(data: ByteArray?): String = Base64.encodeToString(data, Base64.NO_WRAP)
}