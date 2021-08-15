package br.com.amorim.crypto

import androidx.test.core.app.ApplicationProvider
import br.com.amorim.crypto.crypto.RSACrypto
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
    fun sign() {
        val signiedText = rsaCrypto.sign("test")
        assertTrue(rsaCrypto.verify(signiedText, "test"))
    }
}