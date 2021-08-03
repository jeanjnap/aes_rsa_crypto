package br.com.amorim.crypto.crypto

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import javax.crypto.IllegalBlockSizeException
import kotlin.jvm.Throws

class RSACryptoTest {
    private lateinit var rsaCrypto: RSACrypto

    @Before
    fun setup() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        rsaCrypto = RSACrypto(appContext)
    }

    @Test
    fun encryptWithPrivateKey_andDecryptWithPublicKey() {
        val encrypted = rsaCrypto.encrypt("test", true)
        val decrypted = rsaCrypto.decrypt(encrypted, true)
        assertEquals(decrypted, "test")
    }

    @Test
    fun encryptWithPpublicKey_andDecryptWithPrivateKey() {
        val encrypted = rsaCrypto.encrypt("test", false)
        val decrypted = rsaCrypto.decrypt(encrypted, false)
        assertEquals(decrypted, "test")
    }

    @Test(expected = Exception::class)
    fun encryptAndDecryptWithPrivateKey_shouldThrowException() {
        val encrypted = rsaCrypto.encrypt("test", true)
        val decrypted = rsaCrypto.decrypt(encrypted, false)
    }

    @Test(expected = Exception::class)
    fun encryptAndDecryptWithPublicKey_shouldThrowException() {
        val encrypted = rsaCrypto.encrypt("test", false)
        val decrypted = rsaCrypto.decrypt(encrypted, true)
    }
}