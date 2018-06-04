/*
 * Copyright 2018 Leonardo Rossetto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cn.kq.zp.keystore.v2;

import android.content.Context;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

abstract class BaseCipherStorage implements CipherStorage {
    static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    final Context context;

    BaseCipherStorage(Context context) {
        this.context = context;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsAlias(String alias) {
        try {
            KeyStore keyStore = getKeyStoreAndLoad();
            return keyStore.containsAlias(alias) &&
                    CipherPreferencesStorage.containsAlias(context, alias);
        } catch (KeyStoreException e) {
            throw new KeyStoreAccessException("Failed to access Keystore", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void removeKey(String alias) {
        try {
            if (containsAlias(alias)) {
                KeyStore keyStore = getKeyStoreAndLoad();
                keyStore.deleteEntry(alias);
                CipherPreferencesStorage.remove(context, alias);
            }
        } catch (KeyStoreException e) {
            throw new KeyStoreAccessException("Failed to access Keystore", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void saveOrReplace(String alias, String password, String value) {
        if (containsAlias(alias)) {
            removeKey(alias);
        }
        encrypt(alias, password, value);
    }

    @Override
    public String getEncryptedData(String alias) {
        byte[] storedData = CipherPreferencesStorage.getKeyBytes(context, alias);
        if(null == storedData) return "none.";
        return new String(storedData, Charset.defaultCharset());
    }

    static KeyStore getKeyStoreAndLoad() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            return keyStore;
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException e) {
            throw new KeyStoreAccessException("Could not access Keystore", e);
        }
    }
}
