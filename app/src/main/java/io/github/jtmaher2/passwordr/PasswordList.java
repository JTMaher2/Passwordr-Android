package io.github.jtmaher2.passwordr;

import android.app.SearchManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.annotation.NonNull;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.SearchView;
import android.support.v7.widget.Toolbar;
import android.text.util.Linkify;
import android.util.Log;
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

import com.firebase.ui.auth.AuthUI;
import com.firebase.ui.auth.IdpResponse;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.QuerySnapshot;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static com.firebase.ui.auth.util.ExtraConstants.EXTRA_IDP_RESPONSE;

public class PasswordList extends AppCompatActivity implements AdapterView.OnItemSelectedListener {
    private static final String TAG = "PasswordList";
    private static final int IV_LEN = 12;
    private static final int MASTER_PASSWORD_LENGTH = 32;
    private static final int NAME_TEXT_VIEW = 42;
    private static final int URL_TEXT_VIEW = 43;
    private static final int PASSWORD_TEXT_VIEW = 44;
    private static final int NOTE_TEXT_VIEW = 45;
    private static final int EDIT_AND_DELETE_BUTTONS = 46;
    private static final int PASSWORD_ID = 47;

    FirebaseAuth mAuth;
    FirebaseFirestore mFirestore;
    private static String mMasterPassword = "";
    private Context mContext;
    private String mChangedMasterPassword;
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";
    private static final String EXTRA_SIGNED_IN_CONFIG = "extra_signed_in_config";
    private static final String EXTRA_CHANGED_MASTER_PASSWORD = "extra_changed_master_password";

    private boolean mFilter = false; // initially, do not display "Clear" option

    public static Intent createIntent(
            Context context,
            IdpResponse idpResponse,
            String masterPassword,
            String changedMasterPassword,
            SignedInConfig signedInConfig) {
        Intent startIntent = new Intent();
        if (idpResponse != null) {
            startIntent.putExtra(EXTRA_IDP_RESPONSE, idpResponse);
        }
        if (masterPassword != null) {
            startIntent.putExtra(EXTRA_MASTER_PASSWORD, masterPassword);
        }
        if (changedMasterPassword != null) {
            startIntent.putExtra(EXTRA_CHANGED_MASTER_PASSWORD, changedMasterPassword);
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

                // if it's not the edit and delete button layout, or the password ID
                if (item.getId() != EDIT_AND_DELETE_BUTTONS && item.getId() != PASSWORD_ID) {
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
                } else if (item.getId() == EDIT_AND_DELETE_BUTTONS){
                    LinearLayout editAndDeleteButtonLayout = (LinearLayout)item;
                    final Button itemButton = (Button)(editAndDeleteButtonLayout.getChildAt(0)); // Edit button is first in layout

                    itemButton.setText(R.string.done);

                    itemButton.setOnClickListener(savePasswordListener);
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
            final ViewGroup thisPassword = (ViewGroup)view.getParent();
            for (int itemPos = 0; itemPos < thisPassword.getChildCount(); itemPos++) {
                View item = thisPassword.getChildAt(itemPos);

                if (item.getId() == PASSWORD_ID) {
                    key = ((TextView)item).getText().toString();
                }
            }

            // take user to confirm delete password activity
            startActivity(ConfirmDeletePasswordActivity.createIntent(mContext, mMasterPassword, key));
            finish();
        }
    };

    // applies changes to Firebase
    View.OnClickListener savePasswordListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            // save changes
            Map<String, Object> newPassword = new HashMap<>();
            newPassword.put("userid", mAuth.getCurrentUser() == null ? "" : mAuth.getCurrentUser().getUid()); // associate this password with current user
            String key = ""; // the key that uniquely identifies this password
            ViewGroup thisPassword = (ViewGroup)view.getParent();

            for (int saveItemPos = 0; saveItemPos < thisPassword.getChildCount(); saveItemPos++) {
                View item = thisPassword.getChildAt(saveItemPos);

                if (item.getId() != EDIT_AND_DELETE_BUTTONS && item.getId() != PASSWORD_ID) {
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

            // overwrite existing password
            mFirestore.collection("passwords").document(key)
                    .set(newPassword)
                    .addOnSuccessListener(new OnSuccessListener<Void>() {
                        @Override
                        public void onSuccess(Void aVoid) {
                            Log.d(TAG, "DocumentSnapshot successfully written!");
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        @Override
                        public void onFailure(@NonNull Exception e) {
                            Log.w(TAG, "Error writing document", e);
                        }
                    });

            ((Button)view).setText(R.string.edit); // change text back to normal
            view.setOnClickListener(editPasswordListener); // revert listener to normal
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

    // download passwords from Firestore
    private void populateList(FirebaseFirestore db, FirebaseUser curUser) {
        final LinearLayout passwordsLayout = findViewById(R.id.passwords_layout);
        final ViewGroup passwordsLayoutParent = (ViewGroup) passwordsLayout.getParent();
        final LinearLayout newPasswordsLayout = new LinearLayout(mContext);
        newPasswordsLayout.setOrientation(LinearLayout.VERTICAL);
        boolean initial = false;
        if (passwordsLayout.getChildCount() == 0) {
            initial = true;
        }

        final ProgressBar encryptingPasswordsProgressBar = findViewById(R.id.encryptingPasswordsProgressBar);
        encryptingPasswordsProgressBar.setVisibility(View.GONE);

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

        // display all passwords using mMasterPassword as decryption key
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

                                    // Edit & Delete button layout
                                    LinearLayout editAndDeleteButtons = new LinearLayout(mContext);
                                    editAndDeleteButtons.setId(EDIT_AND_DELETE_BUTTONS);
                                    editAndDeleteButtons.setOrientation(LinearLayout.HORIZONTAL);

                                    // Edit button
                                    Button editButton = new Button(mContext);
                                    editButton.setText(R.string.edit);
                                    editButton.setOnClickListener(editPasswordListener);
                                    editAndDeleteButtons.addView(editButton);

                                    // Delete button
                                    Button deleteButton = new Button(mContext);
                                    deleteButton.setText(R.string.delete);
                                    deleteButton.setOnClickListener(deletePasswordListener);
                                    editAndDeleteButtons.addView(deleteButton);

                                    passwordCard.addView(editAndDeleteButtons);

                                    // Password ID
                                    TextView passwordID = new TextView(mContext);
                                    passwordID.setText(document.getId());
                                    passwordID.setVisibility(View.INVISIBLE);
                                    passwordID.setId(PASSWORD_ID);
                                    passwordCard.addView(passwordID);

                                    if (finalInitial) {
                                        passwordsLayout.addView(passwordCard);
                                    } else {
                                        newPasswordsLayout.addView(passwordCard);
                                    }
                                }

                                // if it's initial update, accept search input
                                if (finalInitial) {
                                    // if user wants to change the master password
                                    if (mChangedMasterPassword != null && !mChangedMasterPassword.equals("")) {
                                        mMasterPassword = mChangedMasterPassword; // re-assign master password to new one

                                        final int[] numEncrypted = {0}; // the number of passwords that have been re-encrypted
                                        encryptingPasswordsProgressBar.setVisibility(View.VISIBLE);

                                        // re-encrypt everything using new master password
                                        for (int password = 0; password < passwordsLayout.getChildCount(); password++) {
                                            // get card
                                            LinearLayout passwordCard = (LinearLayout) passwordsLayout.getChildAt(password);

                                            String key = "";
                                            Map<String, Object> newFields = new HashMap<>();
                                            newFields.put("userid", mAuth.getCurrentUser() == null ? "" : mAuth.getCurrentUser().getUid()); // associate this password with current user

                                            // get key, name, url, password, and note
                                            for (int elem = 0; elem < passwordCard.getChildCount(); elem++) {
                                                View elemView = passwordCard.getChildAt(elem);

                                                // encrypt using new master password
                                                if (elemView instanceof LinearLayout) {
                                                    for (int elemViewElem = 0; elemViewElem < ((LinearLayout) elemView).getChildCount(); elemViewElem++) {
                                                        View elemViewElemView = ((LinearLayout)elemView).getChildAt(elemViewElem);

                                                        switch (elemViewElemView.getId()) {
                                                            case NAME_TEXT_VIEW:
                                                                newFields.put("name", encryptField(((TextView) elemViewElemView).getText().toString()));
                                                                break;
                                                            case URL_TEXT_VIEW:
                                                                newFields.put("url", encryptField(((TextView) elemViewElemView).getText().toString()));
                                                                break;
                                                            case PASSWORD_TEXT_VIEW:
                                                                newFields.put("password", encryptField(((TextView) elemViewElemView).getText().toString()));
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
                                            mFirestore.collection("passwords").document(key).set(newFields).addOnSuccessListener(new OnSuccessListener<Void>() {
                                                @Override
                                                public void onSuccess(Void aVoid) {
                                                    numEncrypted[0]++;
                                                    if (numEncrypted[0] == passwordsLayout.getChildCount()) {
                                                        encryptingPasswordsProgressBar.setVisibility(View.GONE);
                                                        // sort A-Z
                                                        onItemSelected(sortOptions, sortOptions.getChildAt(0), 0, 0);
                                                    }
                                                    Log.d(TAG, "DocumentSnapshot successfully written!");
                                                }
                                            }).addOnFailureListener(new OnFailureListener() {
                                                @Override
                                                public void onFailure(@NonNull Exception e) {
                                                    Log.w(TAG, "Error writing document", e);
                                                }
                                            });
                                        }
                                    } else {
                                        // sort A-Z
                                        onItemSelected(sortOptions, sortOptions.getChildAt(0), 0, 0);
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
                                        if (passwordsLayoutParent.getChildAt(i).getId() == passwordsLayout.getId()) {
                                            passwordsLayoutParent.removeViewAt(i);
                                            break;
                                        }
                                    }
                                    newPasswordsLayout.setId(passwordsLayout.getId()); // assign password layout ID to new password layout
                                    passwordsLayoutParent.addView(newPasswordsLayout);

                                    // sort A-Z
                                    onItemSelected(sortOptions, sortOptions.getChildAt(0), 0, 0);
                                }
                            } else {
                                Log.w(TAG, "Error getting documents.", task.getException());
                            }
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

        clearSearch.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                // disable the "Clear" option
                mFilter = false;
                invalidateOptionsMenu();

                // re-populate list with every password
                populateList(FirebaseFirestore.getInstance(), mAuth.getCurrentUser());
                return false;
            }
        });

        MenuItem changeMasterPassword = menu.findItem(R.id.menu_change_master_password);

        changeMasterPassword.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                // take user to change master password activity
                startActivity(ChangeMasterPasswordActivity.createIntent(mContext, mMasterPassword));
                finish();
                return false;
            }
        });

        MenuItem importExportPasswords = menu.findItem(R.id.menu_import_export);

        importExportPasswords.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                // take user to change master password activity
                startActivity(ImportExportPasswordsActivity.createIntent(mContext));
                finish();
                return false;
            }
        });

        return true;
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
        setContentView(R.layout.activity_password_list);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(getString(R.string.passwords));
        }

        Toolbar toolbar = findViewById(R.id.password_list_toolbar);
        setSupportActionBar(toolbar);
        toolbar.setNavigationIcon(android.support.v7.appcompat.R.drawable.abc_ic_ab_back_material);
        toolbar.setNavigationOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                onBackPressed();
            }
        });

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
        }

        FirebaseUser curUser = mAuth.getCurrentUser();

        if (curUser != null) {
            populateList(db, curUser);

            // add new password
            FloatingActionButton newPasswordBtn = findViewById(R.id.new_password_btn);
            newPasswordBtn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    // take user to new password activity
                    startActivity(NewPasswordActivity.createIntent(mContext, mMasterPassword));
                    finish();
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
            Collections.sort(allPasswordNames, new Comparator<String>() {
                @Override
                public int compare(String name2, String name1) {
                    if (sortType.equals("A-Z")) {
                        return name2.toLowerCase().compareTo(name1.toLowerCase());
                    } else { // Z-A
                        return name1.toLowerCase().compareTo(name2.toLowerCase());
                    }
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
        // go back to sign in screen
        startActivity(LoginActivity.createIntent(mContext));
        finish();
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