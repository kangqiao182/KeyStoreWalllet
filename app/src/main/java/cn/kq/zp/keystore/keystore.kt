package cn.kq.zp.keystore

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.util.Base64
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal

/**
 * Created by zhaopan on 2018/5/16.
 */
private val TAG = "keystore"
private val ANDROID_KEY_STORE = "AndroidKeyStore"
private val TRANSFORMATION = "AES/GCM/NoPadding"

class Encryptor {
    private var encryption: ByteArray? = null
    private var iv: ByteArray? = null

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(UnrecoverableEntryException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class, NoSuchPaddingException::class, InvalidKeyException::class, IOException::class, InvalidAlgorithmParameterException::class, SignatureException::class, BadPaddingException::class, IllegalBlockSizeException::class)
    fun encryptText(alias: String, textToEncrypt: String): ByteArray? {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, KeyStoreUtil.initSecretKey(alias))

        // 获取本次加密时使用的初始向量。初始向量属于加密算法使用的一组参数。使用不同的加密算法时，需要保存的参数不完全相同。Cipher会提供相应的API
        iv = cipher.iv
        encryption = cipher.doFinal(textToEncrypt.toByteArray(Charsets.UTF_8))
        return encryption
    }

    fun getEncryption(): ByteArray? {
        return encryption
    }

    fun getIv(): ByteArray? {
        return iv
    }
}


class Decryptor {

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Throws(UnrecoverableEntryException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class, NoSuchPaddingException::class, InvalidKeyException::class, IOException::class, BadPaddingException::class, IllegalBlockSizeException::class, InvalidAlgorithmParameterException::class)
    fun decryptData(alias: String, encryptedData: ByteArray, encryptionIv: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(128, encryptionIv)
        //解密时，需要把加密后的数据，密钥和初始向量发给解密方。
        cipher.init(Cipher.DECRYPT_MODE, KeyStoreUtil.getSecretKey(alias), spec)

        return String(cipher.doFinal(encryptedData), Charsets.UTF_8)
    }
}


object KeyStoreUtil {
    private var keyStore: KeyStore

    init {
        keyStore = getKeyStore()
    }

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class)
    fun getKeyStore(): KeyStore {
        if (null == keyStore) {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore!!.load(null)
        }
        return keyStore!!
    }

    @Throws(NoSuchAlgorithmException::class, UnrecoverableEntryException::class, KeyStoreException::class)
    fun getSecretKey(alias: String): SecretKey {
        return (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    fun initSecretKey(alias: String): SecretKey {
        if (KeyStoreUtil.getKeyStore().containsAlias(alias)) return getSecretKey(alias)
        //创建新的密钥.
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        keyGenerator.init(KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setUserAuthenticationRequired(true)

                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build())

        return keyGenerator.generateKey()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun encryptString(alias: String, content: String): Encryptor{
        val encryptor = Encryptor()
        encryptor.encryptText(alias, content)
        return encryptor
    }

    fun decryptString(alias: String, encryptedData: ByteArray, encryptionIv: ByteArray): String{
        val decryptor = Decryptor()
        try {
            return decryptor.decryptData(alias, encryptedData, encryptionIv)
        } catch (e: Exception){

        }
        return "parse failed"
    }

    fun getAliasesKeys(): List<String> {
        val keyAliases = ArrayList<String>()
        try {
            val aliases = getKeyStore().aliases()
            while (aliases.hasMoreElements()) {
                keyAliases.add(aliases.nextElement())
            }
        } catch (e: Exception) {
        }
        return keyAliases
    }

    fun deleteKey(alias: String){
        keyStore.deleteEntry(alias)
    }

    fun bytesToBase64(bytes: ByteArray): String{
        return Base64.encodeToString(bytes, Base64.DEFAULT)
    }

    fun base64ToBytes(base64: String): ByteArray{
        return Base64.decode(base64, Base64.DEFAULT)
    }
}


object KeyStoreUtil2 {
    const val ANDROID_KEY_STORE = "AndroidKeyStore"
    const val TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    const val PROVIDER = "AndroidOpenSSL"
    private var keyStore: KeyStore

    init {
        keyStore = getKeyStore()
    }

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class)
    fun getKeyStore(): KeyStore {
        if (null == keyStore) {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore!!.load(null)
        }
        return keyStore!!
    }

    fun initSecretKey(context: Context, alias: String): KeyPair? {
        if (keyStore.containsAlias(alias)) {
            //return getPrivateKey(alias)
            return null
        }

        // Create new key if needed
        try {
            val start = Calendar.getInstance()
            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 1)
            val spec = KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(X500Principal("CN=Sample Name, O=Android Authority"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()

            val generator = KeyPairGenerator.getInstance(/*"RSA"*/KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            generator.initialize(spec)
            val keyPair = generator.generateKeyPair()
            return keyPair
        } catch (e: Exception) {
            Log.e(TAG, Log.getStackTraceString(e))
        }
        return null
    }

    /*fun getPrivateKey(alias: String): PrivateKey?{
        if (keyStore.containsAlias(alias)) {
            return keyStore
        }
    }*/

    fun encryptString(alias: String, content: String): ByteArray? {
        try {
            val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            val publicKey = privateKeyEntry.certificate.publicKey as RSAPublicKey


            val cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)

            val outputStream = ByteArrayOutputStream()
            val cipherOutputStream = CipherOutputStream(outputStream, cipher)
            cipherOutputStream.write(content.toByteArray(Charsets.UTF_8))
            cipherOutputStream.close()

            val vals = outputStream.toByteArray()
            return vals
            //Base64.encodeToString(vals, Base64.DEFAULT)
        } catch (e: Exception) {
            Log.e(TAG, Log.getStackTraceString(e))
        }
        return null
    }


    fun decryptString(alias: String, cipherText: String): String? {
        try {
            val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            val privateKey = privateKeyEntry.privateKey as RSAPrivateKey

            val cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)

            val cipherInputStream = CipherInputStream(ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), cipher)
            val values = ArrayList<Byte>()
            var nextByte: Int = cipherInputStream.read()
            while ((nextByte) != -1) {
                values.add(nextByte.toByte())
                nextByte = cipherInputStream.read()
            }

            val bytes = ByteArray(values.size)
            for (i in bytes.indices) {
                bytes[i] = values[i]
            }

            val finalText = String(bytes, 0, bytes.size, Charsets.UTF_8)
            return finalText
        } catch (e: Exception) {
            Log.e(API19Activity.TAG, Log.getStackTraceString(e))
        }
        return null
    }

    fun getAliasesKeys(): List<String> {
        val keyAliases = ArrayList<String>()
        try {
            val aliases =  keyStore.aliases()
            while (aliases.hasMoreElements()) {
                keyAliases.add(aliases.nextElement())
            }
        } catch (e: Exception) {
        }
        return keyAliases
    }

    fun deleteKey(alias: String) {
        keyStore.deleteEntry(alias)
    }
}




