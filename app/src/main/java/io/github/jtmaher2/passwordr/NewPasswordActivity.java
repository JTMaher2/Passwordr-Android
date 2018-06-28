package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.AsyncTask;
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

import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
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
    private static final int MASTER_PASSWORD_LENGTH = 32;

    private String mMasterPassword;
    private Context mContext;

    FirebaseAuth mAuth;
    FirebaseFirestore mFirestore;

    private static class PwnedPasswordsDownloaderTask extends AsyncTask<String, Void, ArrayList<String>> {
        String mPassword;
        WeakReference<EditText> mPasswordEditText;

        PwnedPasswordsDownloaderTask(EditText passwordEditText) {
            mPasswordEditText = new WeakReference<>(passwordEditText);
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
                        mPasswordEditText.get().setBackgroundColor(Color.RED);
                        break;
                    } else {
                        numNonMatches++;
                    }
                }

                // if there were no matches
                // find any layout that contains this password, and color it green
                if (numNonMatches == matches.size()) {
                    mPasswordEditText.get().setBackgroundColor(Color.GREEN);
                }
            } else {
                // find any layout that contains this password, and color it green
                mPasswordEditText.get().setBackgroundColor(Color.GREEN);
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
                                    startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null, null, null));
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
                String newPassword = Utils.generatePassword();
                passwordEditText.setText(newPassword);
                confirmPasswordEditText.setText(newPassword);
            }
        });

        Button checkPasswordBtn = findViewById(R.id.checkPasswordBtn);
        checkPasswordBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new PwnedPasswordsDownloaderTask(passwordEditText).execute(passwordEditText.getText().toString());
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
        startActivity(PasswordList.createIntent(mContext, null, mMasterPassword, null, null, null, null));
        finish();
        return true;
    }

}
