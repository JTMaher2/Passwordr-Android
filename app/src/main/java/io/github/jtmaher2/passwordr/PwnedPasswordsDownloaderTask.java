package io.github.jtmaher2.passwordr;

import android.net.Uri;
import android.os.AsyncTask;
import android.util.Log;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import static android.graphics.Color.GREEN;
import static android.graphics.Color.RED;

public class PwnedPasswordsDownloaderTask extends AsyncTask<String, Void, ArrayList<String>> implements AsyncResponse {
    private String mPassword;
    private WeakReference<LinearLayout> mPasswordsList;
    private static final String TAG = "PwnedPasswordsTask";
    private static final int PASSWORD_TEXT_VIEW = 44;

    public AsyncResponse delegate = null;

    // for use in PasswordList
    PwnedPasswordsDownloaderTask(LinearLayout passwordsList) {
        mPasswordsList = new WeakReference<>(passwordsList);
    }

    // for use in NewPasswordActivity
    PwnedPasswordsDownloaderTask(String password) {
        mPassword = password;
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
                    if (mPasswordsList != null) {
                        // it's all passwords in PasswordsList activity
                        // find any layout that contains this password, and color it red
                        for (int i = 0; i < (mPasswordsList.get()).getChildCount(); i++) {
                            ViewGroup password = (ViewGroup) ((mPasswordsList.get()).getChildAt(i));

                            // if this password is same as password that was checked
                            if (((TextView) password.findViewById(PASSWORD_TEXT_VIEW)).getText().toString().equals(mPassword)) {
                                password.setBackgroundColor(RED);
                                break;
                            }
                        }
                    }

                    delegate.processFinish(true); // this password was pwned
                    break;
                } else {
                    numNonMatches++;
                }
            }

            // if there were no matches
            if (numNonMatches == matches.size()) {
                // if this is the PasswordList activity
                // find any layout that contains this password, and color it green
                if (mPasswordsList != null) {
                    for (int i = 0; i < (mPasswordsList.get()).getChildCount(); i++) {
                        ViewGroup password = (ViewGroup) ((mPasswordsList.get()).getChildAt(i));

                        if (((TextView) password.findViewById(PASSWORD_TEXT_VIEW)).getText().toString().equals(mPassword)) {
                            password.setBackgroundColor(GREEN);
                            break;
                        }
                    }
                }

                delegate.processFinish(false); // this password is safe
            }
        } else {
            if (mPasswordsList != null) {
                // it's PasswordList activity
                // find any layout that contains this password, and color it green
                for (int i = 0; i < (mPasswordsList.get()).getChildCount(); i++) {
                    ViewGroup password = (ViewGroup) ((mPasswordsList.get()).getChildAt(i));

                    // if this password is same as password that was checked
                    if (((TextView) password.findViewById(PASSWORD_TEXT_VIEW)).getText().toString().equals(mPassword)) {
                        password.setBackgroundColor(GREEN);
                        break;
                    }
                }
            }

            delegate.processFinish(false); // this password is safe
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