package temple.edu.pkiprovider;

import android.database.Cursor;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.method.KeyListener;
import android.util.Base64;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.EditText;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class PkiActivity extends AppCompatActivity {

    private boolean mIsEncrypted = false;
    KeyListener mKeyListener;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pki);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Get EditText
        final EditText editText = (EditText) findViewById(R.id.editText);
        final Button button = (Button) findViewById(R.id.button);

        // Save key listener for when editing is restored
        mKeyListener = editText.getKeyListener();

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mIsEncrypted = !mIsEncrypted;
                if (mIsEncrypted) {

                    Cursor cursor = getContentResolver().query(PkiContentProvider.contentUri,
                            new String[]{"_id", KeyDbContract.KeyEntry.COLUMN_NAME_PUBLIC},
                            null,
                            null,
                            null);
                    String keyString = cursor.getString(1);
                    RSAPublicKey publicKey = null;
                    if (keyString != null) {
                        try {
                            byte[] keyBytes = Base64.decode(keyString, Base64.DEFAULT);
                            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(keyBytes);
                            publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(encodedKeySpec);

                            // Disable editing in edit text
                            editText.setKeyListener(null);

                            // Encrypt text
                            String encryptedText = encryptText(editText.getText().toString(), publicKey);
                            editText.setText(encryptedText);
                        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }

                    if (publicKey != null)
                        System.out.println(publicKey.toString());

                } else {

                    Cursor cursor = getContentResolver().query(PkiContentProvider.contentUri,
                            new String[]{"_id", KeyDbContract.KeyEntry.COLUMN_NAME_PRIVATE},
                            null,
                            null,
                            null);
                    String keyString = cursor.getString(1);
                    RSAPrivateKey privateKey = null;
                    if (keyString != null) {
                        try {
                            byte[] keyBytes = Base64.decode(keyString, Base64.DEFAULT);
                            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
                            privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);

                            // Decrypt text
                            String decryptedText = decryptText(editText.getText().toString(), privateKey);
                            editText.setText(decryptedText);

                            // Make edit text editable again
                            editText.setKeyListener(mKeyListener);
                        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                            e.printStackTrace();
                        }

                    }
                }

                String text = mIsEncrypted ? getString(R.string.decrypt_text) : getString(R.string.encrypt_text);
                button.setText(text);
            }
        });
    }

    String encryptText(String text, RSAPublicKey publicKey) {


        byte[] data = text.getBytes();
        byte[] encryptedData = null;

        try {
            final Cipher cipher;

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedData = cipher.doFinal(data);

            final String encryptedText = new String(Base64.encode(encryptedData, Base64.DEFAULT), "UTF-8");
            return encryptedText;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    String decryptText(String text, RSAPrivateKey privateKey) {
        byte[] encryptedBytes = Base64.decode(text.getBytes(), Base64.DEFAULT);
        String decrypted = null;
        try {
            final Cipher cipher;
            byte[] decryptedBytes;

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedBytes = cipher.doFinal(encryptedBytes);
            decrypted = new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypted;
    }

    @Override
    protected void onStop() {
        // TODO: DELETE THIS! Needed to erase DB on exit, but should remove for future iterations
        deleteDatabase(KeyDbHelper.DATABASE_NAME);
        super.onStop();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_pki, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
