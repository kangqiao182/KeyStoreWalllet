package cn.kq.zp.keystore

import android.content.Context
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyProperties
import android.support.v7.app.AlertDialog
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.security.auth.x500.X500Principal

class API19Activity : AppCompatActivity() {

    companion object {
        val TAG = "SimpleKeystoreApp"
        val CIPHER_TYPE = "RSA/ECB/PKCS1Padding"
        val CIPHER_PROVIDER = "AndroidOpenSSL"
    }


    lateinit var etAlias: EditText
    lateinit var etStartText: EditText
    lateinit var etDecryptedText: EditText
    lateinit var etEncryptedText: EditText
    lateinit var keyAliases: MutableList<String>
    lateinit var listView: ListView
    var listAdapter: KeyRecyclerAdapter? = null

    lateinit var keyStore: KeyStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)


        setContentView(R.layout.act_api_19)
        val lvheader: View = layoutInflater.inflate(R.layout.view_keystore_header, null, false)
        etAlias = lvheader.findViewById(R.id.et_alias)
        etStartText = lvheader.findViewById(R.id.et_content)
        etDecryptedText = lvheader.findViewById(R.id.et_decrypted_txt)
        etEncryptedText = lvheader.findViewById(R.id.et_encrypted_txt)

        listView = findViewById(R.id.listView) as ListView
        listView.addHeaderView(lvheader)
        listAdapter = KeyRecyclerAdapter(this, R.id.tv_alias)
        refreshKeys()
        listView.adapter = listAdapter

        keyStore = KeyStoreUtil2.getKeyStore()
    }

    private fun refreshKeys() {
        keyAliases = ArrayList()
        try {
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                keyAliases.add(aliases.nextElement())
            }
        } catch (e: Exception) {
        }

        if (listAdapter != null)
            listAdapter?.notifyDataSetChanged()
    }

    fun createNewKeys(view: View) {
        val alias = etAlias.text.toString()
        try {
            // Create new key if needed
            if (!keyStore.containsAlias(alias)) {
                val start = Calendar.getInstance()
                val end = Calendar.getInstance()
                end.add(Calendar.YEAR, 1)
                val spec = KeyPairGeneratorSpec.Builder(this)
                        .setAlias(alias)
                        .setSubject(X500Principal("CN=Sample Name, O=Android Authority"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.time)
                        .setEndDate(end.time)
                        .build()

                val generator = KeyPairGenerator.getInstance(/*"RSA"*/KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
                generator.initialize(spec)

                val keyPair = generator.generateKeyPair()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Exception " + e.message + " occured", Toast.LENGTH_LONG).show()
            Log.e(TAG, Log.getStackTraceString(e))
        }

        refreshKeys()
    }

    fun deleteKey(alias: String) {
        val alertDialog = AlertDialog.Builder(this)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"$alias\" from the keystore?")
                .setPositiveButton("Yes") { dialog, which ->
                    try {
                        keyStore.deleteEntry(alias)
                        refreshKeys()
                    } catch (e: KeyStoreException) {
                        Toast.makeText(this@API19Activity,
                                "Exception " + e.message + " occured",
                                Toast.LENGTH_LONG).show()
                        Log.e(TAG, Log.getStackTraceString(e))
                    }

                    dialog.dismiss()
                }
                .setNegativeButton("No") { dialog, which -> dialog.dismiss() }
                .create()
        alertDialog.show()
    }

    fun encryptString(alias: String) {
        try {
            val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            val publicKey = privateKeyEntry.certificate.publicKey as RSAPublicKey

            val initialText = etStartText.text.toString()
            if (initialText.isEmpty()) {
                Toast.makeText(this, "Enter text in the 'Initial Text' widget", Toast.LENGTH_LONG).show()
                return
            }

            val inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL")
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey)

            val outputStream = ByteArrayOutputStream()
            val cipherOutputStream = CipherOutputStream(
                    outputStream, inCipher)
            cipherOutputStream.write(initialText.toByteArray(Charsets.UTF_8))
            cipherOutputStream.close()

            val vals = outputStream.toByteArray()
            etEncryptedText.setText(Base64.encodeToString(vals, Base64.DEFAULT))
        } catch (e: Exception) {
            Toast.makeText(this, "Exception " + e.message + " occured", Toast.LENGTH_LONG).show()
            Log.e(TAG, Log.getStackTraceString(e))
        }

    }

    fun decryptString(alias: String) {
        try {
            val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            val privateKey = privateKeyEntry.privateKey as RSAPrivateKey

            val output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL")
            output.init(Cipher.DECRYPT_MODE, privateKey)

            val cipherText = etEncryptedText.text.toString()
            val cipherInputStream = CipherInputStream(
                    ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output)
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
            etDecryptedText.setText(finalText)

        } catch (e: Exception) {
            Toast.makeText(this, "Exception " + e.message + " occured", Toast.LENGTH_LONG).show()
            Log.e(TAG, Log.getStackTraceString(e))
        }

    }

    inner class KeyRecyclerAdapter(context: Context, textView: Int) : ArrayAdapter<String>(context, textView) {

        override fun getCount(): Int {
            return keyAliases.size
        }

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val itemView = LayoutInflater.from(parent.context).inflate(R.layout.adapter_list_keystore_opt, parent, false)

            val keyAlias = itemView.findViewById(R.id.tv_alias) as TextView
            keyAlias.text = keyAliases[position]
            val encryptButton = itemView.findViewById(R.id.btn_encrypt) as Button
            encryptButton.setOnClickListener { encryptString(keyAlias.text.toString()) }
            val decryptButton = itemView.findViewById(R.id.btn_decrypt) as Button
            decryptButton.setOnClickListener { decryptString(keyAlias.text.toString()) }
            val deleteButton = itemView.findViewById(R.id.btn_del) as Button
            deleteButton.setOnClickListener { deleteKey(keyAlias.text.toString()) }

            return itemView
        }

        override fun getItem(position: Int): String? {
            return keyAliases[position]
        }

    }

}
