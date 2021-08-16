package br.com.amorim.crypto.crypto

import android.content.Context
import android.util.Base64
import br.com.amorim.crypto.keys.RSAKey
import java.io.ByteArrayOutputStream
import java.security.Signature
import javax.crypto.Cipher

class RSACrypto(
    context: Context
) {
    private val rsaKey = RSAKey(context).apply {
        initAndGenerateKeyPair()
    }

    private val base64Wrapper: Base64Wrapper = Base64Wrapper()

    private val encryptCipher: Cipher by lazy {
        Cipher.getInstance(CIPHER_RSA_ENCRYPT_MODE).apply {
            init(Cipher.ENCRYPT_MODE, rsaKey.getPrivateKey())
        }
    }

    private val decryptCipher: Cipher by lazy {
        Cipher.getInstance(CIPHER_RSA_ENCRYPT_MODE).apply {
            init(Cipher.DECRYPT_MODE, rsaKey.getPublicKey())
        }
    }

    fun encrypt(value: String): String {
        val originalMessage = value.toByteArray()
        return if (originalMessage.size > CIPHER_BLOCK_SIZE) {
            encryptLargeText(encryptCipher, originalMessage)
        } else {
            Base64.encodeToString(encryptCipher.doFinal(value.toByteArray()), Base64.DEFAULT)
        }
    }

    fun decrypt(value: String): String {
        val encrypted = Base64.decode(value, Base64.DEFAULT)
        return if (encrypted.size > CIPHER_BLOCK_SIZE)
            decryptLargeText(decryptCipher, encrypted)
        else {
            String(decryptCipher.doFinal(Base64.decode(value, Base64.DEFAULT)))
        }
    }

    fun sign(value: String): String {
        val signature = Signature.getInstance(ALGORITHM)
        signature.initSign(rsaKey.getPrivateKey())
        signature.update(base64Wrapper.decode(value))
        return base64Wrapper.encodeToString(signature.sign())
    }

    fun verify(signValue: String, originalValue: String): Boolean {
        val signature = Signature.getInstance(ALGORITHM)
        signature.initVerify(rsaKey.getPublicKey())
        signature.update(base64Wrapper.decode(originalValue))
        return signature.verify(base64Wrapper.decode(signValue))
    }

    private fun encryptLargeText(cipher: Cipher, message: ByteArray): String {
        // k - 11 octets (k is the octet length of the RSA modulus) k -> KeySize/8
        var limit: Int = (RSAKey.RSA_KEY_SIZE / 8) - 11
        var position = 0

        val byteArrayOutputStream = ByteArrayOutputStream()
        while (position < message.size) {
            if (message.size - position < limit) limit = message.size - position
            val res = cipher.doFinal(message, position, limit)
            byteArrayOutputStream.write(res)
            position += limit
        }

        return Base64.encodeToString(byteArrayOutputStream.toByteArray(), Base64.DEFAULT)
    }

    private fun decryptLargeText(cipher: Cipher, encryptedMessage: ByteArray): String {
        var limit = RSAKey.RSA_KEY_SIZE / 8
        var position = 0

        val byteArrayOutputStream = ByteArrayOutputStream()
        while (position < encryptedMessage.size) {
            if (encryptedMessage.size - position < limit) {
                limit = encryptedMessage.size - position
            }
            val result = cipher.doFinal(encryptedMessage, position, limit)
            byteArrayOutputStream.write(result)
            position += limit
        }

        return String(byteArrayOutputStream.toByteArray())
    }

    private companion object {
        const val CIPHER_RSA_ENCRYPT_MODE = "RSA/ECB/PKCS1Padding"
        const val CIPHER_BLOCK_SIZE = 256
        const val ALGORITHM = "SHA256withRSA"
    }
}
