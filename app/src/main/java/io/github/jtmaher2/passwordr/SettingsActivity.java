package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;

/**
 * Created by James on 3/21/2018.
 */

public class SettingsActivity extends AppCompatActivity {

    private class addListenerOnTextChange implements TextWatcher {
        EditText mEdittextview;
        SharedPreferences mPrefs;

        addListenerOnTextChange(EditText edittextview, SharedPreferences prefs) {
            super();
            this.mEdittextview= edittextview;
            this.mPrefs = prefs;
        }

        @Override
        public void afterTextChanged(Editable s) {
        }

        @Override
        public void beforeTextChanged(CharSequence s, int start, int count,
                                      int after) {
        }

        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {
            if (s != null && !s.toString().isEmpty()) {
                mPrefs.edit().putInt(NUM_SECONDS_BEFORE_CLIPBOARD_CLEAR, Integer.parseInt(s.toString())).apply();
            }
        }
    }

    private static final String MY_PREFS_NAME = "PasswordrPreferences";
    private static final String PWNED_PASSWORDS_ENABLED = "PwnedPasswordsEnabled";
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";
    private static final String NUM_SECONDS_BEFORE_CLIPBOARD_CLEAR = "NumSecondsBeforeClipboardClear";
    private String mMasterPassword;

    public static Intent createIntent(
            Context context,
            String masterPassword) {
        Intent startIntent = new Intent();

        return startIntent.setClass(context, SettingsActivity.class)
                .putExtra(EXTRA_MASTER_PASSWORD, masterPassword);
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        Bundle extras = getIntent().getExtras();
        if (extras != null) {
            mMasterPassword = extras.getString(EXTRA_MASTER_PASSWORD);
        }

        final SharedPreferences prefs = getSharedPreferences(MY_PREFS_NAME, MODE_PRIVATE);


        CheckBox enablePwnedPasswordsCheckBox = findViewById(R.id.enable_pwned_passwords_checkbox);

        enablePwnedPasswordsCheckBox.setChecked(prefs.getBoolean(PWNED_PASSWORDS_ENABLED, false));
        enablePwnedPasswordsCheckBox.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                prefs.edit().putBoolean(PWNED_PASSWORDS_ENABLED, ((CheckBox)view).isChecked()).apply();
            }
        });

        EditText numSecondsToWaitInput = findViewById(R.id.numSecondsToWaitInput);
        numSecondsToWaitInput.addTextChangedListener(new addListenerOnTextChange(numSecondsToWaitInput, prefs));
    }

    @Override
    public boolean onSupportNavigateUp() {
        // go back to list
        startActivity(PasswordList.createIntent(getApplicationContext(), null, mMasterPassword, null, null, null, null));
        finish();
        return super.onSupportNavigateUp();
    }
}
