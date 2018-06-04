package cn.kq.zp.keystore

import android.content.Intent
import android.os.Bundle
import android.os.PersistableBundle
import android.support.v7.app.AppCompatActivity
import android.view.View

/**
 * Created by zhaopan on 2018/5/30.
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.act_main_layout)
    }


    fun clickBtn19(view: View){
        startActivity(Intent(this, API19Activity::class.java))
    }

    fun clickBtn23(view: View){
        startActivity(Intent(this, API23Activity::class.java))
    }

    fun clickOpenUtil(view: View){
        startActivity(Intent(this, KeyStoreActivity::class.java))
    }

}