package temple.edu.pkiprovider;

import android.content.Intent;
import android.database.Cursor;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v7.widget.Toolbar;
import android.text.method.KeyListener;
import android.util.Base64;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.EditText;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import be.appfoundry.nfclibrary.activities.NfcActivity;
import temple.edu.pkiprovider.PEM.PEM;

public class PkiActivity extends NfcActivity {

    private boolean mIsEncrypted = false;
    KeyListener mKeyListener;
    private PublicKey mPublicKey;
    private PrivateKey mPrivateKey;

    private EditText mEditText;
    private Button mButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Enable Android Beam
        enableBeam();

        setContentView(R.layout.activity_pki);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Get EditText
        mEditText = (EditText) findViewById(R.id.editText);
        mButton = (Button) findViewById(R.id.button);

        // Save key listener for when editing is restored
        mKeyListener = mEditText.getKeyListener();

        mButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mIsEncrypted = !mIsEncrypted;
                if (mIsEncrypted) {

                    Cursor cursor = getContentResolver().query(PkiContentProvider.contentUri,
                            new String[]{"_id", KeyDbContract.KeyEntry.COLUMN_NAME_PRIVATE},
                            null,
                            null,
                            null);
                    String keyString = cursor.getString(1);
                    if (keyString != null) {
                        try {
                            if (mPrivateKey == null) {
                                byte[] keyBytes = Base64.decode(keyString, Base64.DEFAULT);
                                PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
                                mPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);
                            }

                            // Disable editing in edit text
                            mEditText.setKeyListener(null);

                            // Encrypt text
                            String encryptedText = encryptText(mEditText.getText().toString(), mPrivateKey);
                            mEditText.setText(encryptedText);
                        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }

                    if (mPrivateKey != null)
                        System.out.println(mPrivateKey.toString());

                } else {
                    Cursor cursor = getContentResolver().query(PkiContentProvider.contentUri,
                            new String[]{"_id", KeyDbContract.KeyEntry.COLUMN_NAME_PUBLIC},
                            null,
                            null,
                            null);
                    String keyString = cursor.getString(1);

                    if (keyString != null) {
                        try {
                            byte[] keyBytes = Base64.decode(keyString, Base64.DEFAULT);
                            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(keyBytes);
                            mPublicKey = KeyFactory.getInstance("RSA").generatePublic(encodedKeySpec);

                            // Decrypt text
                            String decryptedText = decryptText(mEditText.getText().toString(), mPublicKey);
                            mEditText.setText(decryptedText);

                            // Make edit text editable again
                            mEditText.setKeyListener(mKeyListener);
                        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                            e.printStackTrace();
                        }

                    }
                }

                String text = mIsEncrypted ? getString(R.string.decrypt_text) : getString(R.string.encrypt_text);
                mButton.setText(text);
            }
        });
    }

    String encryptText(String text, PrivateKey privateKey) {

        byte[] data = text.getBytes();
        byte[] encryptedData;

        try {
            final Cipher cipher;

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            encryptedData = cipher.doFinal(data);

            final String encryptedText = new String(Base64.encode(encryptedData, Base64.DEFAULT), "UTF-8");
            return encryptedText;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    String decryptText(String text, PublicKey publicKey) {
        byte[] encryptedBytes = Base64.decode(text.getBytes(), Base64.DEFAULT);
        String decrypted = null;
        try {
            final Cipher cipher;
            byte[] decryptedBytes;

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            decryptedBytes = cipher.doFinal(encryptedBytes);
            decrypted = new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypted;
    }

    @Override
    public NdefMessage createNdefMessage(NfcEvent event) {
        if (mPrivateKey == null || mEditText.getText().length() == 0)
            return null;

        String key = mPublicKey.toString();
        String text = encryptText(mEditText.getText().toString(), mPrivateKey);
        NdefMessage msg = new NdefMessage(
                new NdefRecord[] { createMimeRecord(
                        "application/temple.edu.pkiprovider/key", key.getBytes()),
                        createMimeRecord("application/temple.edu.pkiprovider/text", text.getBytes())
                        /**
                         * The Android Application Record (AAR) is commented out. When a device
                         * receives a push with an AAR in it, the application specified in the AAR
                         * is guaranteed to run. The AAR overrides the tag dispatch system.
                         * You can add it back in to guarantee that this
                         * activity starts when receiving a beamed message. For now, this code
                         * uses the tag dispatch system.
                        */
                        ,NdefRecord.createApplicationRecord("temple.edu.pkiprovider")
                });
        return msg;
    }

    /**
     * Parses the NDEF Message from the intent and prints to the TextView
     */
    void processIntent(Intent intent) {
        mEditText = (EditText) findViewById(R.id.editText);
        Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
                NfcAdapter.EXTRA_NDEF_MESSAGES);
        // only one message sent during the beam
        NdefMessage msg = (NdefMessage) rawMsgs[0];
        // record 0 & 1 contain the MIME type, record 2 is the AAR, if present
        byte[] keyPayload = msg.getRecords()[0].getPayload();
        byte[] textPayload = msg.getRecords()[1].getPayload();
        try {
            // Get the public key
            InputStream inputStream = new ByteArrayInputStream(keyPayload);
            mPublicKey = PEM.readPublicKey(inputStream);

            // Get the encrypted text, decrypt it
            String decryptedText = decryptText(new String(textPayload), mPublicKey);
            mEditText.setText(decryptedText);

            // Set button to "Encrypt" state
            mButton.setText(getString(R.string.encrypt_text));
            mIsEncrypted = false;
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    /**
     * Creates a custom MIME type encapsulated in an NDEF record
     *
     * @param mimeType
     */
    public NdefRecord createMimeRecord(String mimeType, byte[] payload) {
        byte[] mimeBytes = mimeType.getBytes(Charset.forName("US-ASCII"));
        NdefRecord mimeRecord = new NdefRecord(
                NdefRecord.TNF_MIME_MEDIA, mimeBytes, new byte[0], payload);
        return mimeRecord;
    }

    @Override
    public void onResume() {
        super.onResume();
        // Check to see that the Activity started due to an Android Beam
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processIntent(getIntent());
        }
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