package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.util.regex.Pattern;

public class ChangeMasterPasswordActivity extends AppCompatActivity {
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";

    public static Intent createIntent(
            Context context,
            String masterPassword) {
        Intent startIntent = new Intent();
        if (!masterPassword.equals("")) {
            startIntent.putExtra(EXTRA_MASTER_PASSWORD, masterPassword);
        }

        return startIntent.setClass(context, ChangeMasterPasswordActivity.class);
    }

    // does the password meet the criteria (at least 8 chars long, at least 1 number, at least 1 non-alphanumeric)?
    private boolean meetsCriteria (String password) {
        return password.length() >= 8 && password.matches(".*\\d+.*") && Pattern.compile("[^a-zA-Z0-9]").matcher(password).find();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_change_master_password);
        final Button saveButton = findViewById(R.id.saveMasterPasswordButton);
        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String oldMasterPassword = getIntent().getExtras() != null ? getIntent().getExtras().getString(EXTRA_MASTER_PASSWORD) : "",
                        newMasterPassword = ((EditText)findViewById(R.id.newMasterPasswordEditText)).getText().toString(),
                        confirmNewMasterPassword = ((EditText)findViewById(R.id.confirmNewMasterPasswordEditText)).getText().toString();

                if (newMasterPassword.equals(confirmNewMasterPassword)) { // pass master password
                    if (meetsCriteria(newMasterPassword)) {
                        startActivity(PasswordList.createIntent(getApplicationContext(), null, oldMasterPassword, newMasterPassword, null, null, null));
                        finish();
                    } else {
                        Snackbar.make((View)saveButton.getParent(), "The master password must be at least 8 chars, with 1 number and 1 non-alphanumeric character.", Snackbar.LENGTH_LONG).show();
                    }
                } else {
                    Snackbar.make((View)saveButton.getParent(), "The passwords must match.", Snackbar.LENGTH_LONG).show();
                }
            }
        });

        Button cancelButton = findViewById(R.id.cancelMasterPasswordButton);
        cancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) { // do not pass anything
                startActivity(PasswordList.createIntent(getApplicationContext(), null, null, null,null, null, null));
                finish();
            }
        });
    }
}
