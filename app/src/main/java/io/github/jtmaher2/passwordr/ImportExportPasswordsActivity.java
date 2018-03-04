package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

public class ImportExportPasswordsActivity extends AppCompatActivity {

    public static Intent createIntent(
            Context context) {
        Intent startIntent = new Intent();

        return startIntent.setClass(context, ConfirmDeletePasswordActivity.class);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_import_export_passwords);
    }
}
