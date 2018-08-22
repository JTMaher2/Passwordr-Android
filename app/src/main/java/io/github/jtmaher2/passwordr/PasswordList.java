package io.github.jtmaher2.passwordr;

import android.app.ActionBar;
import android.app.SearchManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.os.Environment;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.annotation.NonNull;
import android.support.design.widget.FloatingActionButton;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.SearchView;
import android.support.v7.widget.Toolbar;
import android.text.util.Linkify;
import android.util.Log;
import android.util.SparseArray;
import android.util.Xml;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.firebase.ui.auth.AuthUI;
import com.firebase.ui.auth.IdpResponse;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.FirebaseUserMetadata;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;

import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlSerializer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static android.Manifest.permission.WRITE_EXTERNAL_STORAGE;
import static android.graphics.Color.GREEN;
import static android.graphics.Color.RED;
import static android.view.View.GONE;
import static android.view.ViewGroup.LayoutParams.MATCH_PARENT;
import static android.view.ViewGroup.LayoutParams.WRAP_CONTENT;
import static com.firebase.ui.auth.util.ExtraConstants.IDP_RESPONSE;

public class PasswordList extends AppCompatActivity implements AdapterView.OnItemSelectedListener {
    private static final String TAG = "PasswordList";
    private static final String MY_PREFS_NAME = "PasswordrPreferences";
    private static final String PWNED_PASSWORDS_ENABLED = "PwnedPasswordsEnabled";
    private static final String NUM_SECONDS_BEFORE_CLIPBOARD_CLEAR = "NumSecondsBeforeClipboardClear";
    private static final int DEFAULT_SECONDS_BEFORE_CLIPBOARD_CLEAR = 12;
    private static final int MILLISECONDS_IN_SECOND = 1000;

    private static final int IV_LEN = 12;
    private static final int MASTER_PASSWORD_LENGTH = 32;
    private static final int PASSWORD_TEXT_SIZE = 20;
    private static final int NAME_TEXT_VIEW = 42;
    private static final int URL_TEXT_VIEW = 43;
    private static final int PASSWORD_TEXT_VIEW = 44;
    private static final int NOTE_TEXT_VIEW = 45;
    private static final int EDIT_AND_DELETE_BUTTONS = 46;
    private static final int PASSWORD_ID = 47;
    private static final int PASSWORD_LAYOUT = 48;
    private static final int PASSWORD_LABEL_LAYOUT = 49;
    private static final int DECRYPT_SUCCESS = 50;
    private static final int DECRYPT_ERROR = 51;
    private static final int DECRYPT_NULL = 52;
    private static final String TYPE_XML = "text/xml";
    private static final String TYPE_JSON = "application/octet-stream";
    private static final String TYPE_KEEPASS = "text/keepass";

    private static final int REQUEST_WRITE_STORAGE = 112;
    private ArrayList<Password> mSerializedPasswords;
    FirebaseAuth mAuth;
    FirebaseFirestore mFirestore;
    private static String mMasterPassword = "";
    private Context mContext;
    private String mChangedMasterPassword;
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";
    private static final String EXTRA_SIGNED_IN_CONFIG = "extra_signed_in_config";
    private static final String EXTRA_IMPORTED_PASSWORDS = "extra_imported_passwords";
    private static final String EXTRA_CHANGED_MASTER_PASSWORD = "extra_changed_master_password";
    private static final String EXTRA_EXPORT_TYPE = "extra_export_type";
    private ArrayList<Password> mImportedPasswords;
    private String mExportType;

    private boolean mFilter = false; // initially, do not display "Clear" option
    private int mDecryptStatus = DECRYPT_NULL;
    private ClipboardManager mClipMan;

    private static class PwnedPasswordsDownloaderTask extends AsyncTask<String, Void, ArrayList<String>> {
        String mPassword;
        WeakReference<LinearLayout> mPasswordsList;

        PwnedPasswordsDownloaderTask(LinearLayout passwordsList) {
            mPasswordsList = new WeakReference<>(passwordsList);
        }

        private String byteArrayToHexString(byte[] b) {
            StringBuilder result = new StringBuilder();
            for (byte aB : b) {
                result.append(Integer.toString((aB & 0xff) + 0x100, 16).substring(1));
            }
            return result.toString();
        }

        private String toSHA1(byte[] convertme) {
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance("SHA-1");
            }
            catch(NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            if (md != null) {
                return byteArrayToHexString(md.digest(convertme));
            } else {
                return null;
            }
        }

        @Override
        // Actual download method, run in the task thread
        protected ArrayList<String> doInBackground(String... params) {
            mPassword = params[0];

            String sha1Password = toSHA1(mPassword.getBytes());

            if (sha1Password != null) {
                return downloadPwnedPasswordMatches(new Uri.Builder().scheme("https")
                        .authority("api.pwnedpasswords.com")
                        .appendPath("range")
                        .appendPath(sha1Password.substring(0, 5))
                        .build().toString());
            } else {
                return null;
            }
        }

        @Override
        // Once the list is downloaded, check each of the hashes to see if it's a match
        protected void onPostExecute(ArrayList<String> matches) {
            int numNonMatches = 0;

            if (matches != null) {
                for (String match : matches) {
                    if ((mPassword.substring(0, 5) + match).equals(mPassword)) {
                        // find any layout that contains this password, and color it red
                        for (int i = 0; i < (mPasswordsList.get()).getChildCount(); i++) {
                            ViewGroup password = (ViewGroup) ((mPasswordsList.get()).getChildAt(i));

                            // if this password is same as password that was checked
                            if (((TextView)password.findViewById(PASSWORD_TEXT_VIEW)).getText().toString().equals(mPassword)) {
                                password.setBackgroundColor(RED);
                                break;
                            }
                        }
                        break;
                    } else {
                        numNonMatches++;
                    }
                }

                // if there were no matches
                // find any layout that contains this password, and color it green
                if (numNonMatches == matches.size()) {
                    for (int i = 0; i < (mPasswordsList.get()).getChildCount(); i++) {
                        ViewGroup password = (ViewGroup) ((mPasswordsList.get()).getChildAt(i));

                        if (((TextView)password.findViewById(PASSWORD_TEXT_VIEW)).getText().toString().equals(mPassword)) {
                            password.setBackgroundColor(GREEN);
                            break;
                        }
                    }
                }
            } else {
                // find any layout that contains this password, and color it green
                for (int i = 0; i < (mPasswordsList.get()).getChildCount(); i++) {
                    ViewGroup password = (ViewGroup) ((mPasswordsList.get()).getChildAt(i));

                    // if this password is same as password that was checked
                    if (((TextView)password.findViewById(PASSWORD_TEXT_VIEW)).getText().toString().equals(mPassword)) {
                        password.setBackgroundColor(GREEN);
                        break;
                    }
                }
            }
        }

        private ArrayList<String> downloadPwnedPasswordMatches(String urlStr) {
            ArrayList<String> matches = new ArrayList<>();
            StringBuilder sb = new StringBuilder();

            try {
                URL url = new URL(urlStr);
                HttpURLConnection con = (HttpURLConnection)url.openConnection();
                InputStream is = con.getInputStream();
                int i;
                boolean inCount = false; // not in the ":XX" segment at end of hash
                while ((i = is.read()) != -1) {
                    if (!inCount) {
                        if ((char) i == ':') {
                            matches.add(sb.toString());
                            sb.delete(0, sb.length()); // clear
                            inCount = true;
                        } else {
                            sb.append((char) i);
                        }
                    } else { // it is in the ":XX" segment at end of hash
                        if ((char) i == '\n') {
                            inCount = false;
                        }
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, e.getMessage());
            }

            return matches;
        }
    }

    public static Intent createIntent(
            Context context,
            IdpResponse idpResponse,
            String masterPassword,
            String changedMasterPassword,
            SignedInConfig signedInConfig,
            ArrayList<Password> importedPasswords,
            String exportType) {
        Intent startIntent = new Intent();

        return startIntent.setClass(context, PasswordList.class)
                .putExtra(IDP_RESPONSE, idpResponse)
                .putExtra(EXTRA_MASTER_PASSWORD, masterPassword)
                .putExtra(EXTRA_CHANGED_MASTER_PASSWORD, changedMasterPassword)
                .putExtra(EXTRA_SIGNED_IN_CONFIG, signedInConfig)
                .putParcelableArrayListExtra(EXTRA_IMPORTED_PASSWORDS, importedPasswords)
                .putExtra(EXTRA_EXPORT_TYPE, exportType);
    }

    // encrypt a field
    private String encryptField(String field) {
        // generate IV
        Random rand = new Random();
        byte[] iv = new byte[IV_LEN];
        rand.nextBytes(iv);

        String encryptedString = "";

        try {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            SecretKeySpec sks = generateKey(mMasterPassword);

            Cipher c = Cipher.getInstance("GCM");
            c.init(Cipher.ENCRYPT_MODE, sks, gcmParameterSpec);

            // encrypt
            byte[] encrypted = c.doFinal(field.getBytes());

            // combine IV + encrypted field together
            byte[] ivEncrypted = new byte[IV_LEN + encrypted.length];
            for (int i = 0; i < ivEncrypted.length; i++) {
                if (i < IV_LEN) {
                    ivEncrypted[i] = iv[i];
                } else {
                    ivEncrypted[i] = encrypted[i - IV_LEN];
                }
            }

            // convert to string
            StringBuilder output = new StringBuilder();
            for (int encryptedByte = 0; encryptedByte < ivEncrypted.length; encryptedByte++) {
                output.append(ivEncrypted[encryptedByte]);
                if (encryptedByte < ivEncrypted.length - 1) {
                    output.append(",");
                }
            }
            encryptedString = output.toString();
        } catch (Exception e) {
            Log.e(TAG, "AES encryption error: " + e.getMessage());
        }

        return encryptedString;
    }

    // decrypt a field
    private String decryptField(String field) {
        if (field != null && !field.isEmpty()) {
            String[] digits = field.split(",");
            byte[] iv = new byte[IV_LEN],
                    data = new byte[digits.length - IV_LEN];

            for (int i = 0; i < digits.length; i++) {
                if (i < IV_LEN) {
                    iv[i] = Byte.parseByte(digits[i]);
                } else {
                    data[i - IV_LEN] = Byte.parseByte(digits[i]);
                }
            }

            byte[] decoded;
            try {
                Cipher c = Cipher.getInstance("GCM");
                SecretKeySpec sks = generateKey(mMasterPassword);
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
                c.init(Cipher.DECRYPT_MODE, sks, gcmParameterSpec);
                decoded = c.doFinal(data);
            } catch (Exception e) {
                Log.e(TAG, e.getMessage());
                mDecryptStatus = DECRYPT_ERROR;
                return null;
            }

            if (decoded != null) {
                mDecryptStatus = DECRYPT_SUCCESS;
                return new String(decoded);
            }
        }

        mDecryptStatus = DECRYPT_NULL;
        return " ";
    }

    // makes a textview editable
    private EditText makeEditable(View layoutItemView) {
        EditText editableItem = new EditText(mContext);
        editableItem.setText(((TextView) layoutItemView).getText());
        editableItem.setId(layoutItemView.getId());

        return editableItem;
    }

    // enables edit mode
    View.OnClickListener editPasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            final ViewGroup thisPassword = (ViewGroup)view.getParent().getParent();
            for (int itemPos = 0; itemPos < thisPassword.getChildCount(); itemPos++) {
                View item = thisPassword.getChildAt(itemPos);

                // if it's not the edit and delete button layout, or the password ID
                if (item.getId() != EDIT_AND_DELETE_BUTTONS && item.getId() != PASSWORD_ID && item.getId() != PASSWORD_LAYOUT && item.getId() != PASSWORD_LABEL_LAYOUT) {
                    ViewGroup itemViewGroup = (ViewGroup)item;
                    for (int layoutItem = 0; layoutItem < itemViewGroup.getChildCount(); layoutItem++) {
                        View layoutItemView = itemViewGroup.getChildAt(layoutItem);
                        if (layoutItemView.getId() == NAME_TEXT_VIEW ||
                                layoutItemView.getId() == URL_TEXT_VIEW ||
                                layoutItemView.getId() == NOTE_TEXT_VIEW) {
                            itemViewGroup.addView(makeEditable(layoutItemView));
                            itemViewGroup.removeView(layoutItemView); // remove old TextView
                        }
                    }
                } else if (item.getId() == EDIT_AND_DELETE_BUTTONS){
                    LinearLayout editAndDeleteButtonLayout = (LinearLayout)item;
                    final Button itemButton = (Button)(editAndDeleteButtonLayout.getChildAt(0)); // Edit button is first in layout

                    itemButton.setText(R.string.done);

                    itemButton.setOnClickListener(savePasswordListener);
                } else if (item.getId() == PASSWORD_LAYOUT) {
                    // replace TextView with EditText
                    ViewGroup itemViewGroup = (ViewGroup)item;
                    for (int layoutItem = 0; layoutItem < itemViewGroup.getChildCount(); layoutItem++) {
                        View layoutItemViewGroup = itemViewGroup.getChildAt(layoutItem);
                        if (layoutItemViewGroup.getId() == PASSWORD_TEXT_VIEW) {
                            // add new edittext
                            EditText editPass = makeEditable(layoutItemViewGroup);
                            editPass.setId(R.id.passwordEditText);
                            itemViewGroup.addView(editPass, 0);
                            itemViewGroup.removeView(layoutItemViewGroup); // remove old TextView
                            itemViewGroup.removeViewAt(itemViewGroup.getChildCount() - 1); // remove COPY button
                            Button genPassBtn = new Button(mContext);
                            genPassBtn.setId(R.id.generatePasswordBtn);
                            genPassBtn.setText(R.string.generate);
                            genPassBtn.setOnClickListener(view1 -> {
                                String newPassword = Utils.generatePassword();
                                ((EditText)findViewById(R.id.passwordEditText)).setText(newPassword);
                            });
                            itemViewGroup.addView(genPassBtn);
                            break;
                        }
                    }
                } else if (item.getId() == PASSWORD_LABEL_LAYOUT) {
                    ((ViewGroup)item).removeViewAt(((ViewGroup)item).getChildCount() - 1); // remove SHOW button
                }
            }
        }
    };

    // takes user to ConfirmDelete activity
    View.OnClickListener deletePasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            String key = "";

            // find the key for this password
            final ViewGroup thisPassword = (ViewGroup)view.getParent().getParent();
            for (int itemPos = 0; itemPos < thisPassword.getChildCount(); itemPos++) {
                View item = thisPassword.getChildAt(itemPos);

                if (item.getId() == PASSWORD_ID) {
                    key = ((TextView)item).getText().toString();
                    break;
                }
            }

            // take user to confirm delete password activity
            startActivity(ConfirmDeletePasswordActivity.createIntent(mContext, mMasterPassword, key));
            finish();
        }
    };

    // copies a password to the clipboard
    View.OnClickListener copyPasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            final ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            // find the key for this password
            final ViewGroup thisPassword = (ViewGroup)view.getParent();
            String password = "";
            for (int itemPos = 0; itemPos < thisPassword.getChildCount(); itemPos++) {
                View item = thisPassword.getChildAt(itemPos);

                if (item.getId() == PASSWORD_TEXT_VIEW) {
                    password = ((TextView)item).getText().toString();
                }
            }
            ClipData clip = ClipData.newPlainText("copied_password", password);
            if (clipboard != null) {
                clipboard.setPrimaryClip(clip);
            }

            Toast.makeText(mContext, "Password copied.", Toast.LENGTH_LONG).show();

            // clear clipboard after X seconds
            int numSecondsBeforeClear = getSharedPreferences(MY_PREFS_NAME, MODE_PRIVATE).getInt(NUM_SECONDS_BEFORE_CLIPBOARD_CLEAR, DEFAULT_SECONDS_BEFORE_CLIPBOARD_CLEAR);

            new CountDownTimer(numSecondsBeforeClear * MILLISECONDS_IN_SECOND, MILLISECONDS_IN_SECOND) {

                public void onTick(long millisUntilFinished) {
                }

                public void onFinish() {
                    // clear clipboard
                    if (clipboard != null) {
                        clipboard.setPrimaryClip(ClipData.newPlainText("copied_password", ""));
                        Toast.makeText(mContext, "Password has been cleared from clipboard.", Toast.LENGTH_LONG).show();
                    }
                }
            }.start();
        }
    };

    // check if password has been pwned
    View.OnClickListener checkPwnedListener = view -> {
        LinearLayout passwordCard = (LinearLayout)view.getParent().getParent();
        String password = "";
        for (int i = 0; i < passwordCard.getChildCount(); i++) {
            if (passwordCard.getChildAt(i) instanceof LinearLayout) {
                LinearLayout layout = (LinearLayout)passwordCard.getChildAt(i);

                for (int j = 0; j < layout.getChildCount(); j++) {
                    if (layout.getChildAt(j).getId() == PASSWORD_TEXT_VIEW) {
                        password = ((TextView)layout.getChildAt(j)).getText().toString();
                        break;
                    }
                }
            }
        }
        new PwnedPasswordsDownloaderTask(findViewById(R.id.passwords_layout)).execute(password);
    };

    // applies changes to Firebase
    View.OnClickListener savePasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            // save changes
            Map<String, Object> newPassword = new HashMap<>();
            newPassword.put("userid", mAuth.getCurrentUser() == null ? "" : mAuth.getCurrentUser().getUid()); // associate this password with current user
            String key = ""; // the key that uniquely identifies this password
            ViewGroup thisPassword = (ViewGroup)view.getParent().getParent();

            for (int saveItemPos = 0; saveItemPos < thisPassword.getChildCount(); saveItemPos++) {
                View item = thisPassword.getChildAt(saveItemPos);

                if (item.getId() != EDIT_AND_DELETE_BUTTONS && item.getId() != PASSWORD_ID && item.getId() != PASSWORD_LAYOUT && item.getId() != PASSWORD_LABEL_LAYOUT) {
                    ViewGroup itemViewGroup = (ViewGroup)item;

                    for (int layoutItem = 0; layoutItem < itemViewGroup.getChildCount(); layoutItem++) {
                        View layoutItemView = itemViewGroup.getChildAt(layoutItem);
                        TextView uneditable = new TextView(mContext);

                        if (layoutItemView.getId() == NAME_TEXT_VIEW ||
                                layoutItemView.getId() == URL_TEXT_VIEW ||
                                layoutItemView.getId() == NOTE_TEXT_VIEW) {
                            EditText editable = (EditText) layoutItemView;
                            uneditable.setText(editable.getText());
                            uneditable.setId(editable.getId());
                            switch (editable.getId()) {
                                case NAME_TEXT_VIEW:
                                    newPassword.put("name", encryptField(((EditText) layoutItemView).getText().toString()));
                                    break;
                                case URL_TEXT_VIEW:
                                    newPassword.put("url", encryptField(((EditText) layoutItemView).getText().toString()));
                                    Linkify.addLinks(uneditable, Linkify.WEB_URLS);
                                    break;
                                case NOTE_TEXT_VIEW:
                                    newPassword.put("note", encryptField(((EditText) layoutItemView).getText().toString()));
                                    break;
                            }

                            // remove old edittext
                            itemViewGroup.removeView(editable);
                            // add new textview
                            itemViewGroup.addView(uneditable);
                        }
                    }
                } else if (item.getId() == PASSWORD_ID) {
                    key = ((TextView)item).getText().toString();
                } else if (item.getId() == PASSWORD_LAYOUT) {
                    LinearLayout passwordLayout = (LinearLayout)item;
                    for (int layoutItem = 0; layoutItem < passwordLayout.getChildCount(); layoutItem++) {
                        View layoutItemView = passwordLayout.getChildAt(layoutItem);

                        if (layoutItemView.getId() == R.id.passwordEditText) {
                            newPassword.put("password", encryptField(((EditText) layoutItemView).getText().toString()));
                            EditText editable = (EditText) layoutItemView;
                            TextView uneditable = new TextView(mContext);

                            uneditable.setText(editable.getText());
                            uneditable.setTextSize(PASSWORD_TEXT_SIZE);
                            uneditable.setId(PASSWORD_TEXT_VIEW);
                            uneditable.setVisibility(View.INVISIBLE);

                            // remove old edittext
                            passwordLayout.removeView(editable);
                            // add new textview
                            passwordLayout.addView(uneditable, 0);

                            // remove generate button
                            passwordLayout.removeView(findViewById(R.id.generatePasswordBtn));

                            // add copy button
                            Button copyButton = new Button(mContext);
                            copyButton.setText(R.string.copy);
                            copyButton.setOnClickListener(copyPasswordListener);
                            passwordLayout.addView(copyButton); // add COPY button
                            break;
                        }
                    }
                } else if (item.getId() == PASSWORD_LABEL_LAYOUT) {
                    // add SHOW button
                    Button showButton = new Button(mContext);
                    showButton.setText(R.string.show);
                    showButton.setOnClickListener(showPasswordListener);
                    ((LinearLayout)item).addView(showButton);
                }
            }

            // overwrite existing password
            mFirestore.collection("passwords").document(key)
                    .set(newPassword)
                    .addOnSuccessListener(aVoid -> Log.d(TAG, "DocumentSnapshot successfully written!"))
                    .addOnFailureListener(e -> Log.w(TAG, "Error writing document", e));

            ((Button)view).setText(R.string.edit); // change text back to normal
            view.setOnClickListener(editPasswordListener); // revert listener to normal
        }
    };

    View.OnClickListener showPasswordListener = view -> {
        // reveal the password
        ViewGroup passwordLayout = (ViewGroup)view.getParent().getParent();
        for (int itemPos = 0; itemPos < passwordLayout.getChildCount(); itemPos++) {
            View sibling = passwordLayout.getChildAt(itemPos);
            if (sibling.getId() == PASSWORD_LAYOUT) {
                for (int itemPos2 = 0; itemPos2 < ((ViewGroup)sibling).getChildCount(); itemPos2++) {
                    View child = ((ViewGroup)sibling).getChildAt(itemPos2);
                    if (child.getId() == PASSWORD_TEXT_VIEW) {
                        child.setVisibility(View.VISIBLE);
                        break;
                    }
                }
            }
        }
    };

    // convert password list to JSON file, and save to disk
    private void writeJSONFile() {
        JSONObject passwordsJSON = new JSONObject();
        try {
            File externStoragePubDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            FileOutputStream fileos = new FileOutputStream(new File(externStoragePubDir, "passwords.json"));

            for (int p = 0; p < mSerializedPasswords.size(); p++) {
                JSONObject passwordJSON = new JSONObject();
                Password curPass = mSerializedPasswords.get(p);
                passwordJSON.put("name", curPass.name);
                passwordJSON.put("url", curPass.url);
                passwordJSON.put("password_str", curPass.password);
                passwordJSON.put("note", curPass.note);

                passwordsJSON.put("password-" + p, passwordJSON);
            }
            // get rid of the backslashes that the .put method automatically prepends to forward slashes
            fileos.write(new JSONObject().put("passwords", passwordsJSON).toString().replace("\\/", "/").getBytes());
            fileos.close();
            Toast.makeText(mContext, "Passwords have been exported to " + externStoragePubDir.getPath() + "/passwords.json", Toast.LENGTH_LONG).show();
        } catch (IOException | JSONException e) {
            e.printStackTrace();
        }
    }

    // convert password list to CSV file with escaped double quotes, and save to disk
    private void writeKeePassCSVFile() {
        StringBuilder output = new StringBuilder();

        output.append("title, url, password, note\n");

        try {
            File externStoragePubDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            FileOutputStream fileos = new FileOutputStream(new File(externStoragePubDir, "passwords.csv"));

            for (int p = 0; p < mSerializedPasswords.size(); p++) {
                Password curPass = mSerializedPasswords.get(p);
                output.append(curPass.name.replace('\n', ' ').replace("\"", "\\\"")).append(',')
                        .append(curPass.url.replace('\n', ' ').replace("\"", "\\\"")).append(',')
                        .append(curPass.password.replace('\n', ' ').replace("\"", "\\\"")).append(',')
                        .append(curPass.note.replace('\n', ' ').replace("\"", "\\\"")).append('\n');
            }
            fileos.write(output.toString().getBytes());
            fileos.close();
            Toast.makeText(mContext, "Passwords have been exported to " + externStoragePubDir.getPath() + "/passwords.csv", Toast.LENGTH_LONG).show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode)
        {
            case REQUEST_WRITE_STORAGE: {
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED)
                {
                    switch (mExportType) {
                        case TYPE_XML:
                            writeXMLFile();
                            break;
                        case TYPE_JSON:
                            writeJSONFile();
                            break;
                        case TYPE_KEEPASS:
                            writeKeePassCSVFile();
                    }
                } else
                {
                    Toast.makeText(this, "The app was not allowed to write to your storage. Hence, it cannot function properly. Please consider granting it this permission", Toast.LENGTH_LONG).show();
                }
            }
        }

    }

    // convert password list to XML file, and save to disk
    private void writeXMLFile() {
        try {
            File externStoragePubDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            FileOutputStream fileos = new FileOutputStream(new File(externStoragePubDir, "passwords.xml"));
            XmlSerializer xmlSerializer = Xml.newSerializer();
            StringWriter writer = new StringWriter();
            xmlSerializer.setOutput(writer);

            // generate document
            xmlSerializer.startDocument("UTF-8", true);
            xmlSerializer.startTag(null, "passwords");

            for (Password p : mSerializedPasswords) {
                xmlSerializer.startTag(null, "password");
                xmlSerializer.startTag(null, "name");
                xmlSerializer.text(p.name);
                xmlSerializer.endTag(null, "name");
                xmlSerializer.startTag(null, "url");
                xmlSerializer.text(p.url);
                xmlSerializer.endTag(null, "url");
                xmlSerializer.startTag(null, "password_str");
                xmlSerializer.text(p.password);
                xmlSerializer.endTag(null, "password_str");
                xmlSerializer.startTag(null, "note");
                xmlSerializer.text(p.note);
                xmlSerializer.endTag(null, "note");
                xmlSerializer.endTag(null, "password");
            }

            xmlSerializer.endTag(null, "passwords");
            xmlSerializer.endDocument();
            xmlSerializer.flush();

            String dataWrite = writer.toString();
            fileos.write(dataWrite.getBytes());
            fileos.close();
            Toast.makeText(mContext, "Passwords have been exported to " + externStoragePubDir.getPath() + "/passwords.xml", Toast.LENGTH_LONG).show();
        }
        catch (IllegalArgumentException | IllegalStateException | IOException e) {
            Log.e(TAG, Arrays.toString(e.getStackTrace()));
        }
    }

    // check if a password is in the list
    private SparseArray<String> inList(Password password) {
        LinearLayout passwordsLayout = findViewById(R.id.passwords_layout);
        boolean inList = false;
        String urlInList = "", passwordInList = "", noteInList = "", keyInList = "";
        for (int i = 0; i < passwordsLayout.getChildCount(); i++) {
            LinearLayout passwordCard = (LinearLayout) passwordsLayout.getChildAt(i);
            String name = "", url = "", passwordStr = "", note = "", key = "";

            for (int elem = 0; elem < passwordCard.getChildCount(); elem++) {
                View elemView = passwordCard.getChildAt(elem);

                if (elemView instanceof LinearLayout) {
                    LinearLayout elemViewLayout = (LinearLayout)elemView;
                    for (int elem2 = 0; elem2 < elemViewLayout.getChildCount(); elem2++) {
                        View elemView2 = elemViewLayout.getChildAt(elem2);

                        switch (elemView2.getId()) {
                            case NAME_TEXT_VIEW:
                                name = ((TextView) elemView2).getText().toString();
                                break;
                            case URL_TEXT_VIEW:
                                url = ((TextView) elemView2).getText().toString();
                                break;
                            case PASSWORD_TEXT_VIEW:
                                passwordStr = ((TextView) elemView2).getText().toString();
                                break;
                            case NOTE_TEXT_VIEW:
                                note = ((TextView) elemView2).getText().toString();
                                break;
                        }
                    }
                } else if (passwordCard.getChildAt(elem).getId() == PASSWORD_ID) {
                    key = ((TextView)passwordCard.getChildAt(elem)).getText().toString();
                }
            }

            if (name.equalsIgnoreCase(password.name)) {
                inList = true;
                urlInList = url;
                passwordInList = passwordStr;
                noteInList = note;
                keyInList = key;
                break;
            }
        }
        int retVal;
        if (inList) {
            if (urlInList.equalsIgnoreCase(password.url) &&
                    passwordInList.equals(password.password) &&
                    noteInList.equalsIgnoreCase(password.note)) {
                retVal = 0; // everything is the same
            } else {
                retVal = 1; // name is same, but url, password, and/or note are different
            }
        } else {
            retVal = 2; // the password is not in the list
        }
        SparseArray<String> retSparseArray = new SparseArray<>();
        retSparseArray.append(retVal, keyInList);
        return retSparseArray;
    }

    // download passwords from Firestore
    private void populateList(FirebaseFirestore db, FirebaseUser curUser, boolean isClear) {
        final LinearLayout[] passwordsLayout = {findViewById(R.id.passwords_layout)};
        final ViewGroup passwordsLayoutParent = (ViewGroup) passwordsLayout[0].getParent();
        final LinearLayout newPasswordsLayout = new LinearLayout(mContext);
        newPasswordsLayout.setOrientation(LinearLayout.VERTICAL);
        boolean initial = false;
        // if the first password is empty, and it's not a clear list action
        if (passwordsLayout[0].getChildCount() == 0 && !isClear) {
            initial = true;
        }

        final ProgressBar loadingPasswordsBar = findViewById(R.id.encryptingOrDeletingPasswordsProgressBar);

        // sort options
        final Spinner sortOptions = findViewById(R.id.sort_options);
        // Create an ArrayAdapter using the sort options array and a default spinner layout
        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(this,
                R.array.sort_options, android.R.layout.simple_spinner_item);
        // Specify the layout to use when the list of choices appears
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        // Apply the adapter to the spinner
        sortOptions.setAdapter(adapter);
        sortOptions.setOnItemSelectedListener(this);

        final boolean finalInitial = initial;

        db.collection("passwords")
                .whereEqualTo("userid", curUser.getUid())
                .get()
                .addOnCompleteListener(task -> {
                    if (task.isSuccessful()) {
                        loop: for (DocumentSnapshot document : task.getResult()) {
                            LinearLayout passwordCard = new LinearLayout(mContext);
                            passwordCard.setOrientation(LinearLayout.VERTICAL);

                            // name
                            LinearLayout nameLayout = new LinearLayout(mContext);
                            nameLayout.setOrientation(LinearLayout.HORIZONTAL);
                            TextView nameLabelTextView = new TextView(mContext);
                            nameLabelTextView.setText(R.string.name_label);
                            nameLayout.addView(nameLabelTextView);
                            TextView nameTextView = new TextView(mContext);
                            String decryptedName = decryptField(document.getString("name"));
                            switch (mDecryptStatus) {
                                case DECRYPT_SUCCESS:
                                case DECRYPT_NULL:
                                    nameTextView.setText(decryptedName);
                                    break;
                                case DECRYPT_ERROR:
                                    // wrong password, so take user back to login activity
                                    startActivity(LoginActivity.createIntent(mContext));
                                    finish();
                                    break loop;
                            }
                            nameTextView.setId(NAME_TEXT_VIEW);
                            nameLayout.addView(nameTextView);
                            passwordCard.addView(nameLayout);

                            // url
                            LinearLayout urlLayout = new LinearLayout(mContext);
                            urlLayout.setOrientation(LinearLayout.HORIZONTAL);
                            TextView urlLabelTextView = new TextView(mContext);
                            urlLabelTextView.setText(R.string.url_label);
                            urlLayout.addView(urlLabelTextView);
                            TextView urlTextView = new TextView(mContext);
                            String decryptedUrl = decryptField(document.getString("url"));
                            switch (mDecryptStatus)
                            {
                                case DECRYPT_SUCCESS:
                                case DECRYPT_NULL:
                                    urlTextView.setText(decryptedUrl);
                                    break;
                                case DECRYPT_ERROR:
                                    // wrong password, so take user back to login activity
                                    startActivity(LoginActivity.createIntent(mContext));
                                    finish();
                                    break loop;
                            }
                            urlTextView.setId(URL_TEXT_VIEW);
                            Linkify.addLinks(urlTextView, Linkify.WEB_URLS);
                            urlLayout.addView(urlTextView);
                            passwordCard.addView(urlLayout);

                            // password
                            LinearLayout passwordLabelLayout = new LinearLayout(mContext);
                            passwordLabelLayout.setId(PASSWORD_LABEL_LAYOUT);
                            passwordLabelLayout.setOrientation(LinearLayout.HORIZONTAL);
                            passwordLabelLayout.setMinimumWidth(MATCH_PARENT);
                            passwordLabelLayout.setMinimumHeight(WRAP_CONTENT);
                            TextView passwordLabelTextView = new TextView(mContext);
                            passwordLabelTextView.setText(R.string.password_label);
                            passwordLabelLayout.addView(passwordLabelTextView);
                            View emptyView = new View(mContext);
                            emptyView.setMinimumWidth(0);
                            emptyView.setMinimumHeight(0);
                            emptyView.setLayoutParams(new LinearLayout.LayoutParams(ActionBar.LayoutParams.WRAP_CONTENT, ActionBar.LayoutParams.WRAP_CONTENT, 1.0f));
                            passwordLabelLayout.addView(emptyView);
                            Button showPasswordButton = new Button(mContext);
                            showPasswordButton.setWidth(WRAP_CONTENT);
                            showPasswordButton.setHeight(WRAP_CONTENT);
                            showPasswordButton.setText(R.string.show);
                            showPasswordButton.setOnClickListener(showPasswordListener);
                            passwordLabelLayout.addView(showPasswordButton);
                            passwordCard.addView(passwordLabelLayout);
                            LinearLayout passwordLayout = new LinearLayout(mContext);
                            passwordLayout.setId(PASSWORD_LAYOUT);
                            passwordLayout.setOrientation(LinearLayout.HORIZONTAL);
                            passwordLayout.setMinimumWidth(MATCH_PARENT);
                            passwordLayout.setMinimumHeight(WRAP_CONTENT);
                            TextView passwordTextView = new TextView(mContext);
                            String decryptedPassword = decryptField(document.getString("password"));
                            switch (mDecryptStatus)
                            {
                                case DECRYPT_SUCCESS:
                                case DECRYPT_NULL:
                                    passwordTextView.setText(decryptedPassword);
                                    break;
                                case DECRYPT_ERROR:
                                    // wrong password, so take user back to login activity
                                    startActivity(LoginActivity.createIntent(mContext));
                                    finish();
                                    break loop;
                            }
                            passwordTextView.setId(PASSWORD_TEXT_VIEW);
                            passwordTextView.setVisibility(View.INVISIBLE);
                            passwordTextView.setTextSize(PASSWORD_TEXT_SIZE);
                            passwordLayout.addView(passwordTextView);
                            View emptyView2 = new View(mContext);
                            emptyView2.setMinimumWidth(0);
                            emptyView2.setMinimumHeight(0);
                            emptyView2.setLayoutParams(new LinearLayout.LayoutParams(ActionBar.LayoutParams.WRAP_CONTENT, ActionBar.LayoutParams.WRAP_CONTENT, 1.0f));
                            passwordLayout.addView(emptyView2);
                            Button copyPasswordButton = new Button(mContext);
                            copyPasswordButton.setText(R.string.copy);
                            copyPasswordButton.setOnClickListener(copyPasswordListener);
                            passwordLayout.addView(copyPasswordButton);
                            passwordCard.addView(passwordLayout);

                            // note
                            LinearLayout noteLayout = new LinearLayout(mContext);
                            noteLayout.setOrientation(LinearLayout.HORIZONTAL);
                            TextView noteLabelTextView = new TextView(mContext);
                            noteLabelTextView.setText(R.string.note);
                            noteLayout.addView(noteLabelTextView);
                            TextView noteTextView = new TextView(mContext);
                            String decryptedNote = decryptField(document.getString("note"));
                            // if it's not empty, add a newline
                            /*if (decryptedNote != null && !decryptedNote.equals(" "))
                                decryptedNote += "\n";*/
                            switch (mDecryptStatus)
                            {
                                case DECRYPT_SUCCESS:
                                case DECRYPT_NULL:
                                    noteTextView.setText(decryptedNote);
                                    break;
                                case DECRYPT_ERROR:
                                    // wrong password, so take user back to login activity
                                    startActivity(LoginActivity.createIntent(mContext));
                                    finish();
                                    break loop;
                            }
                            noteTextView.setId(NOTE_TEXT_VIEW);
                            noteLayout.addView(noteTextView);
                            passwordCard.addView(noteLayout);

                            // Edit & Delete button layout
                            LinearLayout editDeleteAndCheckButtons = new LinearLayout(mContext);
                            editDeleteAndCheckButtons.setId(EDIT_AND_DELETE_BUTTONS);
                            editDeleteAndCheckButtons.setOrientation(LinearLayout.HORIZONTAL);

                            // Edit button
                            Button editButton = new Button(mContext);
                            editButton.setText(R.string.edit);
                            editButton.setOnClickListener(editPasswordListener);
                            editDeleteAndCheckButtons.addView(editButton);

                            // Delete button
                            Button deleteButton = new Button(mContext);
                            deleteButton.setText(R.string.delete);
                            deleteButton.setOnClickListener(deletePasswordListener);
                            editDeleteAndCheckButtons.addView(deleteButton);

                            // if user has enabled pwned passwords, add additional "Check" button
                            if (getSharedPreferences(MY_PREFS_NAME, MODE_PRIVATE).getBoolean(PWNED_PASSWORDS_ENABLED, false)) {
                                Button checkPwnedButton = new Button(mContext);
                                checkPwnedButton.setText(R.string.check);
                                checkPwnedButton.setOnClickListener(checkPwnedListener);
                                editDeleteAndCheckButtons.addView(checkPwnedButton);
                            }

                            passwordCard.addView(editDeleteAndCheckButtons);

                            // Password ID
                            TextView passwordID = new TextView(mContext);
                            passwordID.setText(document.getId());
                            passwordID.setVisibility(View.INVISIBLE);
                            passwordID.setId(PASSWORD_ID);
                            passwordCard.addView(passwordID);

                            if (finalInitial) {
                                passwordsLayout[0].addView(passwordCard);
                            } else {
                                newPasswordsLayout.addView(passwordCard);
                            }
                        }

                        // if it's initial update
                        if (finalInitial) {
                            // if user wants to change the master password
                            if (mChangedMasterPassword != null && !mChangedMasterPassword.equals("")) {
                                mMasterPassword = mChangedMasterPassword; // re-assign master password to new one

                                final int[] numEncrypted = {0}; // the number of passwords that have been re-encrypted
                                loadingPasswordsBar.setVisibility(View.VISIBLE);

                                // re-encrypt everything using new master password
                                for (int password = 0; password < passwordsLayout[0].getChildCount(); password++) {
                                    // get card
                                    LinearLayout passwordCard = (LinearLayout) passwordsLayout[0].getChildAt(password);

                                    String key = "";
                                    Map<String, Object> newFields = new HashMap<>();
                                    newFields.put("userid", mAuth.getCurrentUser() == null ? "" : mAuth.getCurrentUser().getUid()); // associate this password with current user

                                    // get key, name, url, password, and note
                                    for (int elem = 0; elem < passwordCard.getChildCount(); elem++) {
                                        View elemView = passwordCard.getChildAt(elem);

                                        // encrypt using new master password
                                        if (elemView instanceof LinearLayout) {
                                            for (int elemViewElem = 0; elemViewElem < ((LinearLayout) elemView).getChildCount(); elemViewElem++) {
                                                View elemViewElemView = ((LinearLayout) elemView).getChildAt(elemViewElem);

                                                switch (elemViewElemView.getId()) {
                                                    case NAME_TEXT_VIEW:
                                                        newFields.put("name", encryptField(((TextView) elemViewElemView).getText().toString()));
                                                        break;
                                                    case URL_TEXT_VIEW:
                                                        newFields.put("url", encryptField(((TextView) elemViewElemView).getText().toString()));
                                                        break;
                                                    case PASSWORD_LAYOUT:
                                                        for (int elemViewElemViewElem = 0; elemViewElemViewElem < ((LinearLayout) elemViewElemView).getChildCount(); elemViewElemViewElem++) {
                                                            View elemViewElemViewElemView = ((LinearLayout) elemViewElemView).getChildAt(elemViewElemViewElem);

                                                            switch (elemViewElemViewElemView.getId()) {
                                                                case PASSWORD_TEXT_VIEW:
                                                                    newFields.put("password", encryptField(((TextView) elemViewElemViewElemView).getText().toString()));
                                                                    break;
                                                            }
                                                        }
                                                        break;
                                                    case NOTE_TEXT_VIEW:
                                                        newFields.put("note", encryptField(((TextView) elemViewElemView).getText().toString()));
                                                        break;
                                                }
                                            }
                                        } else if (elemView.getId() == PASSWORD_ID) {
                                            key = ((TextView) elemView).getText().toString();
                                        }
                                    }

                                    // upload to firebase
                                    mFirestore.collection("passwords").document(key).set(newFields).addOnSuccessListener(aVoid -> {
                                        numEncrypted[0]++;
                                        if (numEncrypted[0] == passwordsLayout[0].getChildCount()) {
                                            loadingPasswordsBar.setVisibility(GONE);
                                            // sort A-Z
                                            onItemSelected(sortOptions, sortOptions.getChildAt(0), 0, 0);
                                        }
                                        Log.d(TAG, "DocumentSnapshot successfully written!");
                                    }).addOnFailureListener(e -> Log.w(TAG, "Error writing document", e));
                                }
                            } else if (mImportedPasswords != null && mImportedPasswords.size() > 0) {
                                // if there are imported passwords,
                                // delete all of this user's passwords from Firebase
                                final int[] numModified = {0}; // the number of passwords that have been added or deleted
                                loadingPasswordsBar.setVisibility(View.VISIBLE);
                                // the password list was empty, so there is nothing to delete
                                // upload imported passwords
                                for (Password importedPassword : mImportedPasswords) {
                                    // if password is not already in list, add it to Firestore
                                    SparseArray<String> inList = inList(importedPassword);
                                    switch (inList.keyAt(0)) {
                                        case 0: // password is already in list, with all fields the same
                                            numModified[0]++;
                                            if (numModified[0] == mImportedPasswords.size()) {
                                                // refresh list
                                                startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null, null, null));
                                                finish();
                                            }
                                            break;
                                        case 1: // password with this name is already in list, with url, password, and/or note being different
                                            Map<String, Object> newFields = new HashMap<>();
                                            newFields.put("password", importedPassword.password);
                                            newFields.put("note", importedPassword.note);
                                            mFirestore.collection("passwords").document(inList.valueAt(0)).set(newFields).addOnSuccessListener(aVoid -> {
                                                numModified[0]++;
                                                if (numModified[0] == mImportedPasswords.size()) {
                                                    // refresh list
                                                    startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null, null, null));
                                                    finish();
                                                }
                                                Log.d(TAG, "DocumentSnapshot successfully written!");
                                            }).addOnFailureListener(e -> Log.w(TAG, "Error writing document", e));
                                            break;
                                        case 2: // password is entirely new
                                            Map<String, Object> newPassword = new HashMap<>();
                                            newPassword.put("userid", mAuth.getCurrentUser() == null ? "" : mAuth.getCurrentUser().getUid()); // associate this password with current user
                                            newPassword.put("name", encryptField(importedPassword.name));
                                            newPassword.put("url", encryptField(importedPassword.url));
                                            newPassword.put("password", encryptField(importedPassword.password));
                                            newPassword.put("note", encryptField(importedPassword.note));

                                            mFirestore.collection("passwords").document()
                                                    .set(newPassword)
                                                    .addOnSuccessListener(aVoid -> {
                                                        Log.d(TAG, "DocumentSnapshot successfully written!");
                                                        numModified[0]++;
                                                        if (numModified[0] == mImportedPasswords.size()) {
                                                            // refresh list
                                                            startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null, null, null));
                                                            finish();
                                                        }
                                                    })
                                                    .addOnFailureListener(e -> Log.w(TAG, "Error writing document", e));
                                            break;
                                    }
                                }
                            } else {
                                // sort A-Z
                                onItemSelected(sortOptions, sortOptions.getChildAt(0), 0, 0);
                                passwordsLayout[0] = findViewById(R.id.passwords_layout);
                                if (mExportType != null) {
                                    // if external storage is writable
                                    if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState()))
                                    {
                                        // put all password fields in list
                                        mSerializedPasswords = new ArrayList<>();
                                        for (int password = 0; password < passwordsLayout[0].getChildCount(); password++) {
                                            // get card
                                            LinearLayout passwordCard = (LinearLayout) passwordsLayout[0].getChildAt(password);
                                            String name = "", url = "", passwordStr = "", note = "";

                                            // get key, name, url, password, and note of each password
                                            for (int elem = 0; elem < passwordCard.getChildCount(); elem++) {
                                                View elemView = passwordCard.getChildAt(elem);

                                                if (elemView instanceof LinearLayout) {
                                                    for (int elemViewElem = 0; elemViewElem < ((LinearLayout) elemView).getChildCount(); elemViewElem++) {
                                                        View elemViewElemView = ((LinearLayout) elemView).getChildAt(elemViewElem);

                                                        switch (elemViewElemView.getId()) {
                                                            case NAME_TEXT_VIEW:
                                                                name = ((TextView) elemViewElemView).getText().toString();
                                                                break;
                                                            case URL_TEXT_VIEW:
                                                                url = ((TextView) elemViewElemView).getText().toString();
                                                                break;
                                                            case PASSWORD_TEXT_VIEW:
                                                                passwordStr = ((TextView) elemViewElemView).getText().toString();
                                                                break;
                                                            case NOTE_TEXT_VIEW:
                                                                note = ((TextView) elemViewElemView).getText().toString();
                                                                break;
                                                        }
                                                    }
                                                }
                                            }

                                            mSerializedPasswords.add(new Password(name, url, passwordStr, note));
                                        }

                                        // check if user has granted WRITE_EXTERNAL_STORAGE permission
                                        boolean hasPermission = (ContextCompat.checkSelfPermission(mContext,
                                                WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED);
                                        if (hasPermission) {
                                            switch (mExportType) {
                                                case TYPE_XML:
                                                    writeXMLFile();
                                                    break;
                                                case TYPE_JSON:
                                                    writeJSONFile();
                                                    break;
                                                case TYPE_KEEPASS:
                                                    writeKeePassCSVFile();
                                                    break;
                                            }
                                        } else {
                                            requestPermissions(new String[]{WRITE_EXTERNAL_STORAGE}, REQUEST_WRITE_STORAGE);
                                        }
                                    }
                                }
                            }

                            // listen to search input
                            Intent intent = getIntent();
                            if (Intent.ACTION_SEARCH.equals(intent.getAction())) {
                                String query = intent.getStringExtra(SearchManager.QUERY);
                                filterResults(query);
                            }
                        } else { // it's not initial update
                            // replace passwordsLayout with filteredPasswordsLayout
                            for (int i = 0; i < passwordsLayoutParent.getChildCount(); i++) {
                                if (passwordsLayoutParent.getChildAt(i).getId() == passwordsLayout[0].getId()) {
                                    passwordsLayoutParent.removeViewAt(i);
                                    break;
                                }
                            }
                            newPasswordsLayout.setId(passwordsLayout[0].getId()); // assign password layout ID to new password layout
                            passwordsLayoutParent.addView(newPasswordsLayout);

                            // sort A-Z
                            onItemSelected(sortOptions, sortOptions.getChildAt(0), 0, 0);
                        }

                        loadingPasswordsBar.setVisibility(GONE); // all passwords downloaded
                    } else {
                        Log.w(TAG, "Error getting documents.", task.getException());
                    }
                });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the options menu from XML
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_password_list, menu);

        // Get the SearchView and set the searchable configuration
        SearchManager searchManager = (SearchManager) getSystemService(Context.SEARCH_SERVICE);
        SearchView searchView = (SearchView) menu.findItem(R.id.menu_search).getActionView();
        // Assumes current activity is the searchable activity
        if (searchManager != null) {
            searchView.setSearchableInfo(searchManager.getSearchableInfo(getComponentName()));
        }
        searchView.setIconifiedByDefault(false); // Do not iconify the widget; expand it by default

        MenuItem clearSearch = menu.findItem(R.id.menu_clear_search);

        clearSearch.setOnMenuItemClickListener(menuItem -> {
            // disable the "Clear" option
            mFilter = false;
            invalidateOptionsMenu();

            // re-populate list with every password
            populateList(FirebaseFirestore.getInstance(), mAuth.getCurrentUser(), true);
            return false;
        });

        MenuItem changeMasterPassword = menu.findItem(R.id.menu_change_master_password);

        changeMasterPassword.setOnMenuItemClickListener(menuItem -> {
            // take user to change master password activity
            startActivity(ChangeMasterPasswordActivity.createIntent(mContext, mMasterPassword));
            finish();
            return false;
        });

        MenuItem importExportPasswords = menu.findItem(R.id.menu_import_export);

        importExportPasswords.setOnMenuItemClickListener(menuItem -> {
            // take user to change master password activity
            startActivity(ImportExportPasswordsActivity.createIntent(mContext, mMasterPassword));
            finish();
            return false;
        });

        MenuItem settings = menu.findItem(R.id.menu_settings);

        settings.setOnMenuItemClickListener(menuItem -> {
            startActivity(SettingsActivity.createIntent(mContext, mMasterPassword));
            finish();
            return false;
        });

        MenuItem pwnedPasswords = menu.findItem(R.id.menu_pwned_passwords);
        pwnedPasswords.setVisible(getSharedPreferences(MY_PREFS_NAME, MODE_PRIVATE).getBoolean(PWNED_PASSWORDS_ENABLED, false));
        pwnedPasswords.setOnMenuItemClickListener(menuItem -> {
            doPwnedCheckOnAllPasswords();
            return false;
        });

        MenuItem signOut = menu.findItem(R.id.menu_sign_out);
        signOut.setOnMenuItemClickListener(menuItem -> {
            signOutUser();
            return false;
        });

        return true;
    }

    // checks all passwords to see if they have been pwned
    private void doPwnedCheckOnAllPasswords() {
        AlertDialog.Builder builder = new AlertDialog.Builder(mContext, android.R.style.Theme_Material_Dialog_Alert);
        builder.setTitle("Pwned Passwords Check All?")
                .setMessage("Are you sure you want to check every password against the Pwned Passwords API?")
                .setPositiveButton(android.R.string.yes, (dialog, which) -> {
                    // continue with check
                    LinearLayout passwordsLayout = findViewById(R.id.passwords_layout);

                    for (int i = 0; i < passwordsLayout.getChildCount(); i++) {
                        new PwnedPasswordsDownloaderTask(passwordsLayout).execute(((TextView)(passwordsLayout.getChildAt(i)).findViewById(PASSWORD_TEXT_VIEW)).getText().toString());
                    }
                })
                .setNegativeButton(android.R.string.no, (dialog, which) -> {
                    // do nothing
                })
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show();
    }

    // sign out user and return to login screen
    private void signOutUser()
    {
        mAuth.signOut();
        startActivity(LoginActivity.createIntent(mContext));
        finish();
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        menu.findItem(R.id.menu_clear_search).setVisible(mFilter);
        return true;
    }

    // filter the results based on search string
    private void filterResults(String query) {
        LinearLayout passwordsLayout = findViewById(R.id.passwords_layout),
                filteredPasswordsLayout = new LinearLayout(this);
        filteredPasswordsLayout.setOrientation(LinearLayout.VERTICAL);
        filteredPasswordsLayout.setId(R.id.passwords_layout);

        // get all password names
        for (int passwordIndex = 0; passwordIndex < passwordsLayout.getChildCount(); passwordIndex++) {
            LinearLayout passwordCard = (LinearLayout) passwordsLayout.getChildAt(passwordIndex);

            for (int passwordElemIndex = 0; passwordElemIndex < passwordCard.getChildCount(); passwordElemIndex++) {
                View passwordCardElem = passwordCard.getChildAt(passwordElemIndex);

                if (passwordCardElem instanceof LinearLayout) {
                    for (int passwordFieldIndex = 0; passwordFieldIndex < ((LinearLayout) passwordCardElem).getChildCount(); passwordFieldIndex++) {
                        View passwordField = ((LinearLayout) passwordCardElem).getChildAt(passwordFieldIndex);

                        // add password to new view if it contains search string
                        if (passwordField.getId() == NAME_TEXT_VIEW) {
                            TextView nameTextView = (TextView) passwordField;
                            String name = nameTextView.getText().toString();
                            if (name.toLowerCase().contains(query.toLowerCase())) {
                                passwordsLayout.removeView(passwordCard);
                                filteredPasswordsLayout.addView(passwordCard);
                            }
                        }
                    }
                }
            }
        }

        // replace passwordsLayout with filteredPasswordsLayout
        ViewGroup passwordsLayoutParent = (ViewGroup) passwordsLayout.getParent();
        int index = passwordsLayoutParent.indexOfChild(passwordsLayout);
        passwordsLayoutParent.removeView(passwordsLayout);
        passwordsLayoutParent.addView(filteredPasswordsLayout, index);

        // enable the "Clear" menu option
        mFilter = true;
        invalidateOptionsMenu();
    }

    // add zeroes to password, or remove characters, to make it 32 chars long
    private String make32CharsLong(String password) {
        // make sure master password is correct length
        StringBuilder sb = new StringBuilder();
        sb.append(password);
        while (sb.length() < MASTER_PASSWORD_LENGTH) {
            sb.append("0");
        }
        while (sb.length() > MASTER_PASSWORD_LENGTH) {
            sb.delete(sb.length() - 1, sb.length());
        }
        return sb.toString();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mClipMan = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        mClipMan.setPrimaryClip(ClipData.newPlainText("copied_password", ""));
        setContentView(R.layout.activity_password_list);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(getString(R.string.passwords));
        }
        Toolbar toolbar = findViewById(R.id.password_list_toolbar);
        setSupportActionBar(toolbar);
        toolbar.setNavigationIcon(R.drawable.abc_ic_ab_back_material);
        toolbar.setNavigationOnClickListener(view -> onBackPressed());

        FirebaseApp.initializeApp(this);
        FirebaseFirestore db = FirebaseFirestore.getInstance();
        mContext = this;
        mAuth = FirebaseAuth.getInstance();
        mFirestore = FirebaseFirestore.getInstance();
        Bundle extras = getIntent().getExtras();
        if (extras != null) {
            String masterPassword = extras.getString(EXTRA_MASTER_PASSWORD);

            if (masterPassword != null) {
                mMasterPassword = make32CharsLong(masterPassword);
            }

            String changedMasterPassword = extras.getString(EXTRA_CHANGED_MASTER_PASSWORD);

            if (changedMasterPassword != null) {
                mChangedMasterPassword = make32CharsLong(changedMasterPassword);
            }

            mImportedPasswords = extras.getParcelableArrayList(EXTRA_IMPORTED_PASSWORDS);

            mExportType = extras.getString(EXTRA_EXPORT_TYPE);
        }

        FirebaseUser curUser = mAuth.getCurrentUser();

        if (curUser != null) {
            populateList(db, curUser, false);

            // add new password
            FloatingActionButton newPasswordBtn = findViewById(R.id.new_password_btn);
            newPasswordBtn.setOnClickListener(view -> {
                // take user to new password activity
                startActivity(NewPasswordActivity.createIntent(mContext, mMasterPassword));
                finish();
            });

            // get list signed in time
            db.collection("settings")
                    .document(curUser.getUid())
                    .get()
                    .addOnCompleteListener(task -> {
                            if (task.isSuccessful()) {
                                DocumentSnapshot d = task.getResult();
                                String lastSignedIn = d.getString("lastSignInTime");

                                ((TextView) findViewById(R.id.lastSignedIn)).setText(lastSignedIn);
                                LinearLayout lastSignInLayout = findViewById(R.id.lastSignInLayout);
                                lastSignInLayout.setVisibility(View.VISIBLE);
                                // show the last signed in time for 10 seconds
                                CountDownTimer cdt = new CountDownTimer(10000L, 1L) {
                                    @Override
                                    public void onTick(long l) {

                                    }

                                    @Override
                                    public void onFinish() {
                                        lastSignInLayout.setVisibility(GONE);
                                    }
                                };
                                cdt.start();

                                FirebaseUserMetadata metadata = curUser.getMetadata();
                                if (metadata != null) {
                                    // write new sign in time to database
                                    lastSignedIn = new Date(metadata.getLastSignInTimestamp()).toString();

                                    Map<String, Object> newSettings = new HashMap<>();
                                    newSettings.put("enableHIBP", d.getBoolean("enableHIBP")); // associate this password with current user
                                    newSettings.put("lastSignInTime", lastSignedIn);

                                    mFirestore.collection("settings").document()
                                            .set(newSettings);
                                }
                            }
                        });
        } else {
            startActivity(LoginActivity.createIntent(this));
            finish();
        }
    }

    @Override
    public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
        final String sortType = parent.getItemAtPosition(pos).toString(); // either A-Z or Z-A
        LinearLayout passwordsLayout = findViewById(R.id.passwords_layout);

        if (passwordsLayout.getChildCount() > 0) {
            LinearLayout sortedPasswordsLayout = new LinearLayout(mContext);
            sortedPasswordsLayout.setOrientation(LinearLayout.VERTICAL);
            sortedPasswordsLayout.setId(R.id.passwords_layout);
            ArrayList<String> allPasswordNames = new ArrayList<>();

            // get all password names
            for (int passwordIndex = 0; passwordIndex < passwordsLayout.getChildCount(); passwordIndex++) {
                LinearLayout passwordCard = (LinearLayout) passwordsLayout.getChildAt(passwordIndex);

                for (int passwordElemIndex = 0; passwordElemIndex < passwordCard.getChildCount(); passwordElemIndex++) {
                    View passwordCardElem = passwordCard.getChildAt(passwordElemIndex);

                    if (passwordCardElem instanceof LinearLayout) {
                        for (int passwordFieldIndex = 0; passwordFieldIndex < ((LinearLayout) passwordCardElem).getChildCount(); passwordFieldIndex++) {
                            View passwordField = ((LinearLayout) passwordCardElem).getChildAt(passwordFieldIndex);

                            // add name to list
                            if (passwordField.getId() == NAME_TEXT_VIEW) {
                                allPasswordNames.add(((TextView) passwordField).getText().toString());
                            }
                        }
                    }
                }
            }

            // sort the list of names
            Collections.sort(allPasswordNames, (name2, name1) -> {
                if (sortType.equals("A-Z")) {
                    return name2.toLowerCase().compareTo(name1.toLowerCase());
                } else { // Z-A
                    return name1.toLowerCase().compareTo(name2.toLowerCase());
                }
            });

            // populate sortedPasswordsLayout with password cards based on new order
            for (int passwordNameIndex = 0; passwordNameIndex < allPasswordNames.size(); passwordNameIndex++) {
                for (int passwordIndex = 0; passwordIndex < passwordsLayout.getChildCount(); passwordIndex++) {
                    LinearLayout passwordCard = (LinearLayout) passwordsLayout.getChildAt(passwordIndex);

                    for (int passwordElemIndex = 0; passwordElemIndex < passwordCard.getChildCount(); passwordElemIndex++) {
                        View passwordCardElem = passwordCard.getChildAt(passwordElemIndex);

                        if (passwordCardElem instanceof LinearLayout) {
                            for (int passwordFieldIndex = 0; passwordFieldIndex < ((LinearLayout) passwordCardElem).getChildCount(); passwordFieldIndex++) {
                                View passwordField = ((LinearLayout) passwordCardElem).getChildAt(passwordFieldIndex);

                                if (passwordField.getId() == NAME_TEXT_VIEW) {
                                    TextView passwordNameTextView = (TextView) passwordField;

                                    // if this password card corresponds to the current sorted name
                                    if (passwordNameTextView.getText().toString().equals(allPasswordNames.get(passwordNameIndex))) {
                                        passwordsLayout.removeView(passwordCard); // remove from old layout
                                        sortedPasswordsLayout.addView(passwordCard); // add to sorted passwords layout
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // replace passwordsLayout with sortedPasswordsLayout
            ViewGroup passwordsLayoutParent = (ViewGroup) passwordsLayout.getParent();
            int index = passwordsLayoutParent.indexOfChild(passwordsLayout);
            passwordsLayoutParent.removeView(passwordsLayout);
            passwordsLayoutParent.addView(sortedPasswordsLayout, index);
        }
    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {    }

    // generates an AES key
    private SecretKeySpec generateKey(String password) throws Exception{
        byte[] keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte) 0x0);
        byte[] passwordBytes = password.getBytes("UTF-8");
        int length = Math.min(passwordBytes.length, keyBytes.length);
        System.arraycopy(passwordBytes, 0, keyBytes, 0, length);
        return new SecretKeySpec(keyBytes, "GCM");
    }

    @Override
    public void onBackPressed() {
        signOutUser();
    }

    static final class SignedInConfig implements Parcelable {
        int logo;
        int theme;

        List<AuthUI.IdpConfig> providerInfo;
        String tosUrl;

        boolean isCredentialSelectorEnabled;
        boolean isHintSelectorEnabled;

        SignedInConfig(int logo,
                       int theme,
                       List<AuthUI.IdpConfig> providerInfo,
                       String tosUrl,
                       boolean isCredentialSelectorEnabled,
                       boolean isHintSelectorEnabled) {
            this.logo = logo;
            this.theme = theme;
            this.providerInfo = providerInfo;
            this.tosUrl = tosUrl;
            this.isCredentialSelectorEnabled = isCredentialSelectorEnabled;
            this.isHintSelectorEnabled = isHintSelectorEnabled;
        }

        SignedInConfig(Parcel in) {
            logo = in.readInt();
            theme = in.readInt();
            providerInfo = new ArrayList<>();
            in.readList(providerInfo, AuthUI.IdpConfig.class.getClassLoader());
            tosUrl = in.readString();
            isCredentialSelectorEnabled = in.readInt() != 0;
            isHintSelectorEnabled = in.readInt() != 0;
        }

        public static final Creator<SignedInConfig> CREATOR = new Creator<SignedInConfig>() {
            @Override
            public SignedInConfig createFromParcel(Parcel in) {
                return new SignedInConfig(in);
            }

            @Override
            public SignedInConfig[] newArray(int size) {
                return new SignedInConfig[size];
            }
        };

        @Override
        public int describeContents() {
            return 0;
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            dest.writeInt(logo);
            dest.writeInt(theme);
            dest.writeList(providerInfo);
            dest.writeString(tosUrl);
            dest.writeInt(isCredentialSelectorEnabled ? 1 : 0);
            dest.writeInt(isHintSelectorEnabled ? 1 : 0);
        }
    }

    // clear password from clipboard (if there is any) when app is killed
    @Override
    protected void onDestroy() {
        if (!(mClipMan.getPrimaryClip().getItemAt(0).getText().toString().isEmpty())) {
            mClipMan.setPrimaryClip(ClipData.newPlainText("copied_password", ""));
            Toast.makeText(mContext, "Password has been cleared from clipboard.", Toast.LENGTH_LONG).show();
        }
        super.onDestroy();
    }
}