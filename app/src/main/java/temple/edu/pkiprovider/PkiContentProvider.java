package temple.edu.pkiprovider;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by connorcrawford on 2/8/17.
 */

public class PkiContentProvider extends ContentProvider {

    SQLiteDatabase db;
    KeyDbHelper mDbHelper;
    private static final String algorithm = "RSA";
    KeyPairGenerator keyPairGenerator;
    static Uri contentUri = Uri.parse("content://" + "temple.edu.pkiprovider.PkiContentProvider");

    public PkiContentProvider() {}

    @Override
    public boolean onCreate() {

        mDbHelper = new KeyDbHelper(getContext());

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            // *Trump voice* "WRONG"
            throw new RuntimeException(e);
        }

        return false;
    }

    @Nullable
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {

        if (selection != null)
            Log.d("Selection", selection);
        if (selectionArgs != null)
            Log.d("Arguments", selectionArgs[0]);

        Cursor cursor = getKeyCursor(projection, selection, selectionArgs);
        if (!(cursor.getCount() > 0)) {
            KeyPair keyPair = generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            saveData(publicKey, privateKey);
            cursor = getKeyCursor(projection, selection, selectionArgs);
        }

        Log.d("Row count", String.valueOf(cursor.getCount()));

        return cursor;
    }

    @Nullable
    @Override
    public String getType(Uri uri) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Nullable
    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    private Cursor getKeyCursor(String[] projection, @Nullable String selection, @Nullable String[] selectionArgs) {

        if (mDbHelper == null)
            System.out.println("null");
        db = mDbHelper.getReadableDatabase();


        Cursor c = db.query(
                KeyDbContract.KeyEntry.TABLE_NAME
                , projection
                , selection
                , selectionArgs
                , null
                , null
                , null);
        c.moveToNext();

        return c;

    }

    public KeyPair generateKeyPair() {
        return keyPairGenerator.generateKeyPair();
    }

    // Save stock data to database
    private void saveData(RSAPublicKey publicKey, @Nullable RSAPrivateKey privateKey){

        // Gets the data repository in write mode
        db = mDbHelper.getWritableDatabase();

        // Create a new map of values, where column names are the keys
        ContentValues values = new ContentValues();
        String publicKeyString = Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
        values.put(KeyDbContract.KeyEntry.COLUMN_NAME_PUBLIC, publicKeyString);
        if (privateKey != null) {
            String privateKeyString = Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT);
            values.put(KeyDbContract.KeyEntry.COLUMN_NAME_PRIVATE, privateKeyString);
        }

        // Insert the new row, returning the primary key value of the new row
        long newRowId;
        newRowId = db.insert(
                KeyDbContract.KeyEntry.TABLE_NAME,
                null,
                values);

        if (newRowId > 0) {
            Log.d("Key data saved ", newRowId + " - " + publicKey);
        } else {
            Log.d("Key data NOT saved ", newRowId + " - " + publicKey);
        }

    }

}
