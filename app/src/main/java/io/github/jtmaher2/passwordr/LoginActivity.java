package io.github.jtmaher2.passwordr;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.loader.app.LoaderManager;
import androidx.loader.content.Loader;

import android.view.View;
import android.widget.EditText;

import com.firebase.ui.auth.AuthUI;
import com.firebase.ui.auth.IdpResponse;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;

/**
 * A login screen that offers login via email/password.
 */
public class LoginActivity extends AppCompatActivity implements LoaderManager.LoaderCallbacks<Cursor> {
    private static final String FIREBASE_TOS_URL = "https://firebase.google.com/terms/";
    private static final String FIREBASE_PRIVACY_POLICY_URL = "https://firebase.google.com/terms/analytics/#7_privacy";
    private static final int RC_SIGN_IN = 9001;

    // UI references.
    private static WeakReference<View> mProgressView;
    private EditText mMasterPasswordInput;
    private static int mShortAnimTime;

    private ArrayList<AuthUI.IdpConfig> mSignInProviders;

    public static Intent createIntent(Context context) {
        return new Intent(context, LoginActivity.class);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        mShortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

        mSignInProviders = new ArrayList<>();
        mSignInProviders.add(new AuthUI.IdpConfig.GoogleBuilder().build());
        mSignInProviders.add(new AuthUI.IdpConfig.FacebookBuilder().build());
        mSignInProviders.add(new AuthUI.IdpConfig.TwitterBuilder().build());
        AuthUI.IdpConfig gitHubIdp = new AuthUI.IdpConfig.GitHubBuilder()
                .setPermissions(Collections.singletonList("gist"))
                .build();
        mSignInProviders.add(gitHubIdp);

        findViewById(R.id.submit_master_password_btn).setOnClickListener(view -> attemptFirebaseLogin());

        mMasterPasswordInput = findViewById(R.id.master_password_input);
        mProgressView = new WeakReference<>(findViewById(R.id.login_progress));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == RC_SIGN_IN) {

            handleSignInResponse(resultCode, data);

        }
    }

    @MainThread
    private void handleSignInResponse(int resultCode, Intent data) {
        IdpResponse response = IdpResponse.fromResultIntent(data);

        // Successfully signed in
        if (resultCode == RESULT_OK) {
            startSignedInActivity(response);
            finish();
        }
    }

    private void startSignedInActivity(IdpResponse response) {
        startActivity(
                PasswordList.createIntent(
                        this,
                        response,
                        mMasterPasswordInput.getText().toString(),
                        null,
                        new PasswordList.SignedInConfig(
                                AuthUI.NO_LOGO,
                                AuthUI.getDefaultTheme(),
                                mSignInProviders,
                                FIREBASE_TOS_URL,
                                false,
                                false),
                        null,
                        null));
    }

    /**
     * Attempts to sign in or register the account specified by the Google, Twiiter, or Facebook sign in providers.
     */
    private void attemptFirebaseLogin() {
        // Show a progress spinner, and kick off a background task to
        // perform the user login attempt.
        showProgress();
        startActivityForResult(
                AuthUI.getInstance().createSignInIntentBuilder()
                        .setTheme(AuthUI.getDefaultTheme())
                        .setLogo(AuthUI.NO_LOGO)
                        .setAvailableProviders(mSignInProviders)
                        .setTosAndPrivacyPolicyUrls(FIREBASE_TOS_URL, FIREBASE_PRIVACY_POLICY_URL)
                        .setIsSmartLockEnabled(false)
                        .build(),
                RC_SIGN_IN);
    }

    /**
     * Shows the progress UI and hides the login form.
     */
    @TargetApi(Build.VERSION_CODES.HONEYCOMB_MR2)
    private static void showProgress() {
        // On Honeycomb MR2 we have the ViewPropertyAnimator APIs, which allow
        // for very easy animations. If available, use these APIs to fade-in
        // the progress spinner.
        View progressView = mProgressView.get();
        progressView.setVisibility(View.VISIBLE);
        progressView.animate().setDuration(mShortAnimTime).alpha(
                1).setListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                progressView.setVisibility(View.VISIBLE);
            }
        });
    }

    @NonNull
    @Override
    public Loader<Cursor> onCreateLoader(int i, @Nullable Bundle bundle) {
        return null;
    }

    @Override
    public void onLoadFinished(@NonNull Loader<Cursor> loader, Cursor cursor) {

    }

    @Override
    public void onLoaderReset(@NonNull Loader<Cursor> loader) {

    }
}

