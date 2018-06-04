package cn.kq.zp.keystore.seedmanager

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import cn.kq.zp.keystore.KeyStoreUtil
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.Cipher


/**
 * Created by zhaopan on 2018/5/30.
 */
object SeedManager{





}


private val TAG = "keystore"
private val ANDROID_KEY_STORE = "AndroidKeyStore"
private val TRANSFORMATION = "AES/GCM/NoPadding"

object KeyStoreUtil {
    private var keyStore: KeyStore

    init {
        keyStore = KeyStoreUtil.getKeyStore()
    }

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class)
    fun getKeyStore(): KeyStore {
        if (null == keyStore) {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore.load(null)
        }
        return keyStore
    }

    /**
     * @param alias 密钥别名.
     * @param pwdseed 用户的密码byte数组.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    fun createSecretKey(alias: String, pwdseed: ByteArray): SecretKey {
        //创建新的密钥.
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        val pspec = KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()

        val sr = SecureRandom.getInstance("SHA1PRNG", "Crypto")
        sr.setSeed(pwdseed)
        keyGenerator.init(pspec, sr)

        return keyGenerator.generateKey()
    }

    fun getSecretKey(alias: String): SecretKey?{
        if (keyStore.containsAlias(alias)){
            return (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
        }
        return null
    }


    /**
     * @param alias 密钥别名
     * @param content 待加密的数据, 例如seed[]数组的序列化.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    fun encrypt(alias: String, pwdseed: ByteArray, content: String): ByteArray {
        //val skeySpec = SecretKeySpec(raw, "AES")
        val cipher = Cipher.getInstance(TRANSFORMATION)

        //cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(alias), IvParameterSpec(ByteArray(cipher.blockSize)))
        val sr = SecureRandom.getInstance("SHA1PRNG", "Crypto")
        sr.setSeed(pwdseed)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(alias),  sr)
        //cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(alias))

        // 获取本次加密时使用的初始向量。初始向量属于加密算法使用的一组参数。
        // 使用不同的加密算法时，需要保存的参数不完全相同。Cipher会提供相应的API
        //val iv = cipher.iv
        val encryption = cipher.doFinal(content.toByteArray(Charsets.UTF_8))
        return encryption
    }
}