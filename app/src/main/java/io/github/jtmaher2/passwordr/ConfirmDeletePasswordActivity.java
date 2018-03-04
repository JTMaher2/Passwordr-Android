package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.widget.Button;

import com.firebase.ui.auth.IdpResponse;
import com.google.firebase.firestore.FirebaseFirestore;

import static com.firebase.ui.auth.util.ExtraConstants.EXTRA_IDP_RESPONSE;

public class ConfirmDeletePasswordActivity extends AppCompatActivity {
    FirebaseFirestore mFirestore;
    static String mKey;
    static String mMasterPassword;
    Context mContext;
    private static final String EXTRA_PASSWORD_KEY = "extra_password_key";
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";

    public static Intent createIntent(
            Context context,
            String masterPassword,
            String key) {
        Intent startIntent = new Intent();

        return startIntent.setClass(context, ConfirmDeletePasswordActivity.class)
                .putExtra(EXTRA_PASSWORD_KEY, key)
                .putExtra(EXTRA_MASTER_PASSWORD, masterPassword);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mContext = this;
        setContentView(R.layout.activity_confirm_delete_password);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        mFirestore = FirebaseFirestore.getInstance();
        Button confirmDeletePasswordBtn = findViewById(R.id.confirm_delete_btn),
                cancelDeletePasswordBtn = findViewById(R.id.cancel_delete_btn);

        Bundle extras = getIntent().getExtras();
        mKey = extras == null ? "" : extras.getString(EXTRA_PASSWORD_KEY);
        mMasterPassword = extras == null ? "" : extras.getString(EXTRA_MASTER_PASSWORD);

        confirmDeletePasswordBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // delete password from Firebase
                mFirestore.collection("passwords").document(mKey)
                        .delete();

                // go back to passwords list
                startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null));
                finish();
            }
        });

        cancelDeletePasswordBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // go back to passwords list
                startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null));
                finish();
            }
        });

        if (getSupportActionBar() != null)
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
    }

}
