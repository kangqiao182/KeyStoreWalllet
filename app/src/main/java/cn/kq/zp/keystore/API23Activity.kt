package cn.kq.zp.keystore

import android.content.Context
import android.os.Build
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.support.annotation.RequiresApi
import android.support.v7.app.AlertDialog
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import java.security.KeyStoreException

class API23Activity : AppCompatActivity() {

    companion object {
        val TAG = "SimpleKeystoreApp"
        val CIPHER_TYPE = "RSA/ECB/PKCS1Padding"
        val CIPHER_PROVIDER = "AndroidOpenSSL"
    }


    lateinit var aliasText: EditText
    lateinit var startText: EditText
    lateinit var decryptedText: EditText
    lateinit var encryptedText: EditText
    lateinit var listView: ListView
    var keyAliases: List<String>? = null
    var listAdapter: KeyRecyclerAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.act_api_19)
        refreshKeys()
        val lvheader: View = layoutInflater.inflate(R.layout.view_keystore_header, null, false)
        aliasText = lvheader.findViewById(R.id.et_alias)
        startText = lvheader.findViewById(R.id.et_content)
        decryptedText = lvheader.findViewById(R.id.et_decrypted_txt)
        encryptedText = lvheader.findViewById(R.id.et_encrypted_txt)

        listView = findViewById(R.id.listView) as ListView
        listView.addHeaderView(lvheader)
        listAdapter = KeyRecyclerAdapter(this, R.id.tv_alias)
        listView.adapter = listAdapter

    }

    private fun refreshKeys() {
        keyAliases = KeyStoreUtil.getAliasesKeys()
        if (listAdapter != null)
            listAdapter?.notifyDataSetChanged()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun createNewKeys(view: View) {
        val alias = aliasText.text.toString()
        KeyStoreUtil.initSecretKey(alias)
        refreshKeys()
    }

    fun deleteKey(alias: String) {
        val alertDialog = AlertDialog.Builder(this)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"$alias\" from the keystore?")
                .setPositiveButton("Yes") { dialog, which ->
                    try {
                        KeyStoreUtil.deleteKey(alias)
                        refreshKeys()
                    } catch (e: KeyStoreException) {
                        Toast.makeText(this@API23Activity,
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

    var encryptor : Encryptor? = null
    @RequiresApi(Build.VERSION_CODES.M)
    fun encryptString(alias: String) {
        val initialText = startText.text.toString()
        encryptor = KeyStoreUtil.encryptString(alias, initialText)
        encryptedText.setText(KeyStoreUtil.bytesToBase64(encryptor?.getEncryption()!!))
    }

    fun decryptString(alias: String) {
        val cipherText = encryptedText.text.toString()
        val decryptText = KeyStoreUtil.decryptString(alias, KeyStoreUtil.base64ToBytes(cipherText), encryptor?.getIv()!!)
        decryptedText.setText(decryptText)
    }

    inner class KeyRecyclerAdapter(context: Context, textView: Int) : ArrayAdapter<String>(context, textView) {

        override fun getCount(): Int {
            return keyAliases!!.size
        }

        @RequiresApi(Build.VERSION_CODES.M)
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val itemView = LayoutInflater.from(parent.context).inflate(R.layout.adapter_list_keystore_opt, parent, false)

            val keyAlias = itemView.findViewById(R.id.tv_alias) as TextView
            keyAlias.text = keyAliases!![position]
            val encryptButton = itemView.findViewById(R.id.btn_encrypt) as Button
            encryptButton.setOnClickListener { encryptString(keyAlias.text.toString()) }
            val decryptButton = itemView.findViewById(R.id.btn_decrypt) as Button
            decryptButton.setOnClickListener { decryptString(keyAlias.text.toString()) }
            val deleteButton = itemView.findViewById(R.id.btn_del) as Button
            deleteButton.setOnClickListener { deleteKey(keyAlias.text.toString()) }

            return itemView
        }

        override fun getItem(position: Int): String? {
            return keyAliases!![position]
        }

    }

}
