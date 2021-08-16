package br.com.amorim.crypto.crypto

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RSACryptoTest {
    private lateinit var rsaCrypto: RSACrypto

    @Before
    fun setup() {
        rsaCrypto = RSACrypto(ApplicationProvider.getApplicationContext())
    }

    @Test
    fun sign_withValidSignature_shouldReturnsTrue() {
        val signValue = rsaCrypto.sign("test")
        assertTrue(rsaCrypto.verify(signValue, "test"))
    }

    @Test
    fun sign_withInvalidSignature_shouldReturnsFalse() {
        assertFalse(rsaCrypto.verify("abc123==", "test"))
    }
}