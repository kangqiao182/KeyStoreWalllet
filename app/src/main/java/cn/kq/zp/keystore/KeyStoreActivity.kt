package cn.kq.zp.keystore

import android.content.Context
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import android.widget.TextView
//import cn.kq.zp.keystore.v2.CipherStorage
//import cn.kq.zp.keystore.v2.CipherStorageFactory
import cn.kq.zp.keystore.v3.keystorex.CipherStorage
import cn.kq.zp.keystore.v3.keystorex.CipherStorageFactory
import java.util.ArrayList


/**
 * Created by zhaopan on 2018/5/30.
 */
class KeyStoreActivity : AppCompatActivity() {

    lateinit var etAlias: EditText
    lateinit var etContent: EditText
    lateinit var etPassword: EditText
    lateinit var etDecryptedText: EditText
    lateinit var etEncryptedText: EditText

    lateinit var listView: ListView
    var listAdapter: KeyRecyclerAdapter? = null
    private lateinit var cipherStorage: CipherStorage


    fun getAliasesKeys(): List<String> {
        val keyAliases = ArrayList<String>()
        try {
            val aliases = KeyStoreUtil.getKeyStore().aliases()
            while (aliases.hasMoreElements()) {
                keyAliases.add(aliases.nextElement())
            }
        } catch (e: Exception) {
        }
        return keyAliases
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.act_key_store)

        etAlias = findViewById(R.id.et_alias)
        etContent = findViewById(R.id.et_content)
        etPassword = findViewById(R.id.et_password)
        etEncryptedText = findViewById(R.id.et_encrypted_txt)
        etDecryptedText = findViewById(R.id.et_decrypted_txt)

        etAlias.setText("zpKey")
        etContent.setText("助记词字串")
        etPassword.setText("123456")

        cipherStorage = CipherStorageFactory.newInstance(this)
        listView = findViewById(R.id.listview)
        listAdapter = KeyRecyclerAdapter(this, R.layout.adapter_list_keystore_opt)
        listAdapter?.setDataList(getAliasesKeys())
        listView.adapter = listAdapter
    }

    fun encryptData(view: View){
        val alias = etAlias.text.toString()
        val content = etContent.text.toString()
        val passwd = etPassword.text.toString()
        passwd.toCharArray()
        //cipherStorage.encrypt(alias, passwd, content)
        cipherStorage.encrypt(alias, content)


    }

    fun getEncryptTxt(view: View){
        val alias = etAlias.text.toString()
        val passwd = etPassword.text.toString()
        //v2
        //val encryptedTxt = cipherStorage.getEncryptedData(alias)
        //etEncryptedText.setText(encryptedTxt)
    }

    fun decryptData(view: View){
        val alias = etAlias.text.toString()
        val passwd = etPassword.text.toString()
        //val decrypted = cipherStorage.decrypt(alias, passwd)
        val decrypted = cipherStorage.decrypt(alias)
        etDecryptedText.setText(decrypted?:"Null.")
    }

    fun delKey(view: View){
        val alias = etAlias.text.toString()
        etEncryptedText.setText("before del:"+cipherStorage.containsAlias(alias).toString())
        cipherStorage.removeKey(alias)
        etDecryptedText.setText("after del:"+cipherStorage.containsAlias(alias).toString())
    }

    internal class ViewHolder {
        var alias: TextView? = null
        var encrypt: Button? = null
        var decrypt: Button? = null
        var del: Button? = null
    }

    inner class KeyRecyclerAdapter(context: Context, val layoutId: Int) : ArrayAdapter<String>(context, layoutId) {
        private var mInflater: LayoutInflater? = null
        lateinit var keyAliases: List<String>

        init {
            mInflater = LayoutInflater.from(context)
        }

        fun setDataList(dataList : List<String>){
            keyAliases = dataList
        }

        override fun getCount(): Int {
            return keyAliases.size
        }

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            var holder: ViewHolder? = null
            var view: View? = null
            if(convertView == null ){
                view = mInflater?.inflate(layoutId, null)
                holder = ViewHolder()
                holder.alias = view?.findViewById(R.id.tv_alias)
                holder.encrypt = view?.findViewById(R.id.btn_encrypt)

                holder.encrypt?.visibility = View.GONE
                holder.decrypt = view?.findViewById(R.id.btn_decrypt)
                holder.del = view?.findViewById(R.id.btn_del)
                view?.setTag(holder)
            }else{
                view = convertView
                holder = view?.tag as ViewHolder
            }
            holder.alias?.text = keyAliases[position]
            holder.encrypt?.setOnClickListener {
                val alias = holder.alias?.text.toString()
                val contentTxt = etContent.text.toString()
                val passwd = etPassword.text.toString()
                //cipherStorage.encrypt(alias, contentTxt,passwd)
                cipherStorage.encrypt(alias, contentTxt)
                val encryptedTxt = context.getSharedPreferences("CipherPreferencesStorage_security_storage", Context.MODE_PRIVATE).getString(alias, null)
                etEncryptedText.setText(encryptedTxt)
            }
            holder.decrypt?.setOnClickListener {
                val passwd = etPassword.text.toString()
                //val contentTxt = cipherStorage.decrypt(keyAliases[position],passwd)
                val contentTxt = cipherStorage.decrypt(keyAliases[position])
                etDecryptedText.setText(contentTxt?:"Failed")
            }
            holder.del?.setOnClickListener {
                val passwd = etPassword.text.toString()
                cipherStorage?.removeKey(keyAliases[position])
            }

            return view!!
        }

        override fun getItem(position: Int): String? {
            return keyAliases[position]
        }

    }
}