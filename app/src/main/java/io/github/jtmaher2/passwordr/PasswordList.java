package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.annotation.NonNull;
import android.support.v4.widget.NestedScrollView;
import android.support.v7.app.AppCompatActivity;
import android.text.Editable;
import android.text.util.Linkify;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.firebase.ui.auth.AuthUI;
import com.firebase.ui.auth.IdpResponse;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.firestore.DocumentReference;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.QuerySnapshot;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import butterknife.internal.ListenerClass;

import static android.text.InputType.TYPE_CLASS_TEXT;
import static android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD;
import static android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD;
import static com.firebase.ui.auth.util.ExtraConstants.EXTRA_IDP_RESPONSE;

public class PasswordList extends AppCompatActivity {
    private static final String TAG = "PasswordList";
    private static final int IV_LEN = 12;
    private static final int MASTER_PASSWORD_LENGTH = 32;
    private static final int NAME_TEXT_VIEW = 42;
    private static final int URL_TEXT_VIEW = 43;
    private static final int PASSWORD_TEXT_VIEW = 44;
    private static final int NOTE_TEXT_VIEW = 45;
    private static final int EDIT_BUTTON = 46;
    private static final int PASSWORD_ID = 47;

    FirebaseAuth mAuth;
    FirebaseFirestore mFirestore;
    private String mMasterPassword = "";
    private Context mContext;
    private SignedInConfig mSignedInConfig;
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";

    private static final String EXTRA_SIGNED_IN_CONFIG = "extra_signed_in_config";
    public static Intent createIntent(
            Context context,
            IdpResponse idpResponse,
            String masterPassword,
            SignedInConfig signedInConfig) {
        Intent startIntent = new Intent();
        if (idpResponse != null) {
            startIntent.putExtra(EXTRA_IDP_RESPONSE, idpResponse);
        }
        if (!masterPassword.equals("")) {
            startIntent.putExtra(EXTRA_MASTER_PASSWORD, masterPassword);
        }

        return startIntent.setClass(context, PasswordList.class)
                .putExtra(EXTRA_SIGNED_IN_CONFIG, signedInConfig);
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
            StringBuilder output = new StringBuilder();
            for (byte encryptedByte : encrypted) {
                output.append(encryptedByte).append(",");
            }
            encryptedString = output.toString();
        } catch (Exception e) {
            Log.e(TAG, "AES encryption error: " + e.getMessage());
        }

        return encryptedString;
    }

    // decrypt a field
    private String decryptField(String field) {
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

        byte[] decoded = null;
        try {
            Cipher c = Cipher.getInstance("GCM");
            SecretKeySpec sks = generateKey(mMasterPassword);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            c.init(Cipher.DECRYPT_MODE, sks, gcmParameterSpec);
            decoded = c.doFinal(data);
        } catch (Exception e) {
            Log.e(TAG, "AES decryption error: " + e.getMessage());
        }

        if (decoded != null)
            return new String(decoded);

        return null;
    }

    // enables edit mode
    View.OnClickListener editPasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            final ViewGroup thisPassword = (ViewGroup)view.getParent();
            for (int itemPos = 0; itemPos < thisPassword.getChildCount(); itemPos++) {
                View item = thisPassword.getChildAt(itemPos);

                // if it's not the edit button itself
                if (item.getId() != EDIT_BUTTON) {
                    ViewGroup itemViewGroup = (ViewGroup)item;
                    for (int layoutItem = 0; layoutItem < itemViewGroup.getChildCount(); layoutItem++) {
                        View layoutItemView = itemViewGroup.getChildAt(layoutItem);
                        if (layoutItemView.getId() == NAME_TEXT_VIEW ||
                                layoutItemView.getId() == URL_TEXT_VIEW ||
                                layoutItemView.getId() == PASSWORD_TEXT_VIEW ||
                                layoutItemView.getId() == NOTE_TEXT_VIEW) {
                            // replace with EditText
                            EditText editableItem = new EditText(mContext);
                            editableItem.setText(((TextView) layoutItemView).getText());
                            editableItem.setId(layoutItemView.getId());
                            itemViewGroup.removeView(layoutItemView); // remove old TextView
                            if (layoutItemView.getId() == PASSWORD_TEXT_VIEW) {
                                itemViewGroup.removeViewAt(itemViewGroup.getChildCount() - 1); // remove SHOW button
                            }
                            // add new edittext
                            itemViewGroup.addView(editableItem);
                        }
                    }
                } else {
                    final Button itemButton = (Button)item;

                    itemButton.setText(R.string.done);

                    itemButton.setOnClickListener(savePasswordListener);
                }
            }
        }
    };

    // applies changes to Firebase
    View.OnClickListener savePasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            // save changes
            Map<String, Object> newPassword = new HashMap<>();
            String key = ""; // the key that uniquely identifies this password
            ViewGroup thisPassword = (ViewGroup)view.getParent();

            for (int saveItemPos = 0; saveItemPos < thisPassword.getChildCount(); saveItemPos++) {
                View item = thisPassword.getChildAt(saveItemPos);

                if (item.getId() != EDIT_BUTTON && item.getId() != PASSWORD_ID) {
                    ViewGroup itemViewGroup = (ViewGroup)item;

                    for (int layoutItem = 0; layoutItem < itemViewGroup.getChildCount(); layoutItem++) {
                        View layoutItemView = itemViewGroup.getChildAt(layoutItem);
                        TextView uneditable = new TextView(mContext);

                        if (layoutItemView.getId() == NAME_TEXT_VIEW ||
                                layoutItemView.getId() == URL_TEXT_VIEW ||
                                layoutItemView.getId() == PASSWORD_TEXT_VIEW ||
                                layoutItemView.getId() == NOTE_TEXT_VIEW) {
                            EditText editable = (EditText)layoutItemView;
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
                                case PASSWORD_TEXT_VIEW:
                                    newPassword.put("password", encryptField(((EditText) layoutItemView).getText().toString()));
                                    uneditable.setVisibility(View.INVISIBLE);
                                    uneditable.setTextIsSelectable(true);
                                    break;
                                case NOTE_TEXT_VIEW:
                                    newPassword.put("note", encryptField(((EditText) layoutItemView).getText().toString()));
                                    break;
                            }

                            // remove old edittext
                            itemViewGroup.removeView(editable);
                            // add new textview
                            itemViewGroup.addView(uneditable);
                            if (layoutItemView.getId() == PASSWORD_TEXT_VIEW) {
                                Button showButton = new Button(mContext);
                                showButton.setText(R.string.show);
                                showButton.setOnClickListener(showPasswordListener);
                                itemViewGroup.addView(showButton); // add SHOW button
                            }
                        }
                    }

                } else if (item.getId() == PASSWORD_ID) {
                    key = ((TextView)item).getText().toString();
                }
            }

            // upload to Firebase
            DocumentReference doc = FirebaseFirestore.getInstance().collection("passwords").document(key);
            doc.update(newPassword);

            ((Button)view).setText(R.string.edit); // change text back to normal
            ((Button)view).setOnClickListener(editPasswordListener); // revert listener to normal
        }
    };

    View.OnClickListener showPasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            // reveal the password
            ViewGroup passwordLayout = (ViewGroup)view.getParent();
            for (int itemPos = 0; itemPos < passwordLayout.getChildCount(); itemPos++) {
                View sibling = passwordLayout.getChildAt(itemPos);
                if (sibling.getId() == PASSWORD_TEXT_VIEW) {
                    sibling.setVisibility(View.VISIBLE);
                    break;
                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_list);

        FirebaseApp.initializeApp(this);
        FirebaseFirestore db = FirebaseFirestore.getInstance();
        mContext = this;
        mAuth = FirebaseAuth.getInstance();
        mFirestore = FirebaseFirestore.getInstance();
        Bundle extras = getIntent().getExtras();
        mMasterPassword = extras == null ? "" : extras.getString(EXTRA_MASTER_PASSWORD);

        // make sure master password is correct length
        StringBuilder sb = new StringBuilder();
        sb.append(mMasterPassword);
        while (sb.length() < MASTER_PASSWORD_LENGTH) {
            sb.append("0");
        }
        while (sb.length() > 32) {
            sb.delete(sb.length() - 1, sb.length());
        }
        mMasterPassword = sb.toString();

        FirebaseUser curUser = mAuth.getCurrentUser();

        final LinearLayout passwordsLayout = findViewById(R.id.passwords_layout);

        if (curUser != null) {
            db.collection("passwords")
                .whereEqualTo("userid", curUser.getUid())
                .get()
                .addOnCompleteListener(new OnCompleteListener<QuerySnapshot>() {
                    @Override
                    public void onComplete(@NonNull Task<QuerySnapshot> task) {
                        if (task.isSuccessful()) {
                            for (DocumentSnapshot document : task.getResult()) {
                                LinearLayout passwordCard = new LinearLayout(mContext);
                                passwordCard.setOrientation(LinearLayout.VERTICAL);

                                // name
                                LinearLayout nameLayout = new LinearLayout(mContext);
                                nameLayout.setOrientation(LinearLayout.HORIZONTAL);
                                TextView nameLabelTextView = new TextView(mContext);
                                nameLabelTextView.setText(R.string.name_label);
                                nameLayout.addView(nameLabelTextView);
                                TextView nameTextView = new TextView(mContext);
                                nameTextView.setText(decryptField(document.getString("name")));
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
                                urlTextView.setText(decryptField(document.getString("url")));
                                urlTextView.setId(URL_TEXT_VIEW);
                                Linkify.addLinks(urlTextView, Linkify.WEB_URLS);
                                urlLayout.addView(urlTextView);
                                passwordCard.addView(urlLayout);

                                // password
                                LinearLayout passwordLayout = new LinearLayout(mContext);
                                passwordLayout.setOrientation(LinearLayout.HORIZONTAL);
                                TextView passwordLabelTextView = new TextView(mContext);
                                passwordLabelTextView.setText(R.string.password_label);
                                passwordLayout.addView(passwordLabelTextView);
                                TextView passwordTextView = new TextView(mContext);
                                passwordTextView.setText(decryptField(document.getString("password")));
                                passwordTextView.setId(PASSWORD_TEXT_VIEW);
                                passwordTextView.setVisibility(View.INVISIBLE);
                                passwordTextView.setTextIsSelectable(true);
                                passwordLayout.addView(passwordTextView);
                                Button showPasswordButton = new Button(mContext);
                                showPasswordButton.setText(R.string.show);
                                showPasswordButton.setOnClickListener(showPasswordListener);
                                passwordLayout.addView(showPasswordButton);
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
                                if (decryptedNote != null && !decryptedNote.equals(" "))
                                    decryptedNote += "\n";
                                noteTextView.setText(decryptedNote);
                                noteTextView.setId(NOTE_TEXT_VIEW);
                                noteLayout.addView(noteTextView);
                                passwordCard.addView(noteLayout);

                                // Edit button
                                Button editButton = new Button(mContext);
                                editButton.setText(R.string.edit);
                                editButton.setId(EDIT_BUTTON);
                                editButton.setOnClickListener(editPasswordListener);
                                passwordCard.addView(editButton);

                                passwordsLayout.addView(passwordCard);
                            }
                        } else {
                            Log.w(TAG, "Error getting documents.", task.getException());
                        }
                    }
                });
        } else {
            startActivity(LoginActivity.createIntent(this));
            finish();
        }
    }

    // generates an AES key
    private SecretKeySpec generateKey(String password) throws Exception{
        byte[] keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte) 0x0);
        byte[] passwordBytes = password.getBytes("UTF-8");
        int length = Math.min(passwordBytes.length, keyBytes.length);
        System.arraycopy(passwordBytes, 0, keyBytes, 0, length);
        return new SecretKeySpec(keyBytes, "GCM");
    }

    private void addPassword() {
        final DocumentReference docRef = mFirestore.collection("passwords").document();


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
}