package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.firestore.FirebaseFirestore;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class NewPasswordActivity extends AppCompatActivity {
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";
    private static final String TAG = "NewPasswordActivity";
    private static final int IV_LEN = 12;
    private static final int GEN_PASSWORD_LENGTH = 20;
    private static final int MASTER_PASSWORD_LENGTH = 32;
    private String mMasterPassword;
    private Context mContext;

    FirebaseAuth mAuth;
    FirebaseFirestore mFirestore;

    public static Intent createIntent(
            Context context,
            String masterPassword) {
        Intent startIntent = new Intent();
        if (!masterPassword.equals("")) {
            startIntent.putExtra(EXTRA_MASTER_PASSWORD, masterPassword);
        }

        return startIntent.setClass(context, NewPasswordActivity.class);
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

    // generates a PASSWORD_LEN long password with a certain number of letters, numbers, and symbols
    private String generatePassword() {
        String string = "abcdefghijklmnopqrstuvwxyz"; //to upper
        String numeric = "0123456789";
        String punctuation = "!@#$%^&*()_+~`|}{[]\\:;?><,./-=";
        String password = "";
        String character = "";

        while( password.length()<GEN_PASSWORD_LENGTH ) {
            double entity1 = Math.ceil(string.length() * Math.random()*Math.random());
            double entity2 = Math.ceil(numeric.length() * Math.random()*Math.random());
            double entity3 = Math.ceil(punctuation.length() * Math.random()*Math.random());
            char hold = string.charAt( (int)entity1 );
            hold = (entity1%2==0)?(Character.toUpperCase(hold)):(hold);
            character += hold;
            character += numeric.charAt( (int)entity2 );
            character += punctuation.charAt( (int)entity3 );
            password = character;
        }

        return password;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_new_password);
        Toolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setTitle("New Password");
        setSupportActionBar(toolbar);

        final EditText nameEditText = findViewById(R.id.nameEditText),
                urlEditText = findViewById(R.id.urlEditText),
                passwordEditText = findViewById(R.id.passwordEditText),
                confirmPasswordEditText = findViewById(R.id.confirmPasswordEditText),
                noteEditText = findViewById(R.id.noteEditText);

        mAuth = FirebaseAuth.getInstance();
        mFirestore = FirebaseFirestore.getInstance();
        mContext = this;

        Bundle extras = getIntent().getExtras();
        mMasterPassword = extras == null ? "" : extras.getString(EXTRA_MASTER_PASSWORD);

        // make sure master password is correct length
        StringBuilder sb = new StringBuilder();
        sb.append(mMasterPassword);
        while (sb.length() < MASTER_PASSWORD_LENGTH) {
            sb.append("0");
        }
        while (sb.length() > MASTER_PASSWORD_LENGTH) {
            sb.delete(sb.length() - 1, sb.length());
        }
        mMasterPassword = sb.toString();

        FloatingActionButton fab = findViewById(R.id.save_new_password_btn);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // encrypt and save password
                if (passwordEditText.getText().toString().equals(confirmPasswordEditText.getText().toString())) {
                    Map<String, Object> newPassword = new HashMap<>();
                    newPassword.put("userid", mAuth.getCurrentUser() == null ? "" : mAuth.getCurrentUser().getUid()); // associate this password with current user
                    newPassword.put("name", encryptField(nameEditText.getText().toString()));
                    newPassword.put("url", encryptField(urlEditText.getText().toString()));
                    newPassword.put("password", encryptField(passwordEditText.getText().toString()));
                    newPassword.put("note", encryptField(noteEditText.getText().toString()));

                    mFirestore.collection("passwords").document()
                            .set(newPassword)
                            .addOnSuccessListener(new OnSuccessListener<Void>() {
                                @Override
                                public void onSuccess(Void aVoid) {
                                    Log.d(TAG, "DocumentSnapshot successfully written!");

                                    // go back to list
                                    startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null));
                                    finish();
                                }
                            })
                            .addOnFailureListener(new OnFailureListener() {
                                @Override
                                public void onFailure(@NonNull Exception e) {
                                    Log.w(TAG, "Error writing document", e);
                                }
                            });
                }

            }
        });

        Button genPasswordBtn = findViewById(R.id.generatePasswordBtn);
        genPasswordBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String newPassword = generatePassword();
                passwordEditText.setText(newPassword);
                confirmPasswordEditText.setText(newPassword);
            }
        });

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setDisplayShowHomeEnabled(true);
        }
    }

    @Override
    public boolean onSupportNavigateUp() {
        // go back to list
        startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null));
        finish();
        return true;
    }

}
