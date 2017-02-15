package temple.edu.pkiprovider;

import android.provider.BaseColumns;

/**
 * Created by connorcrawford on 2/8/17.
 */

public class KeyDbContract {

//    private static final String BLOB_TYPE = " BLOB";
    private static final String TEXT_TYPE = " TEXT";
    private static final String COMMA_SEP = ",";
    public static final String SQL_CREATE_ENTRIES =
            "CREATE TABLE " + KeyEntry.TABLE_NAME + " (" +
                    KeyEntry._ID + " INTEGER PRIMARY KEY AUTOINCREMENT" + COMMA_SEP +
                    KeyEntry.COLUMN_NAME_PUBLIC + TEXT_TYPE + COMMA_SEP +
                    KeyEntry.COLUMN_NAME_PRIVATE + TEXT_TYPE +
                    " )";

    public static final String SQL_DELETE_ENTRIES =
            "DROP TABLE IF EXISTS " + KeyEntry.TABLE_NAME;

    public static abstract class KeyEntry implements BaseColumns {
        public static final String TABLE_NAME = "entry";
        public static final String COLUMN_NAME_PUBLIC = "public_key";
        public static final String COLUMN_NAME_PRIVATE = "private_key";
    }

}
