package cn.kq.zp.keystore

import android.content.Context
import android.support.multidex.MultiDex
import android.support.multidex.MultiDexApplication

/**
 * Created by zhaopan on 2018/5/30.
 */
class App : MultiDexApplication() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        MultiDex.install(this)
    }
}