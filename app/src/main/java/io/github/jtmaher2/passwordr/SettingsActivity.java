package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.provider.Settings;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.CheckBox;

/**
 * Created by James on 3/21/2018.
 */

public class SettingsActivity extends AppCompatActivity {
    private static final String MY_PREFS_NAME = "PasswordrPreferences";
    private static final String PWNED_PASSWORDS_ENABLED = "PwnedPasswordsEnabled";
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";
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
    }

    @Override
    public boolean onSupportNavigateUp() {
        // go back to list
        startActivity(PasswordList.createIntent(getApplicationContext(), null, mMasterPassword, null, null, null, null));
        finish();
        return super.onSupportNavigateUp();
    }
}
