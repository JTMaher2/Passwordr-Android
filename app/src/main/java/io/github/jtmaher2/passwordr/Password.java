package io.github.jtmaher2.passwordr;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Created by James on 3/10/2018.
 */

// This class represents a single password in the XML feed.
// It includes the data members "name," "url," "password," and "note"
public class Password implements Parcelable {
    public final String name;
    public final String url;
    public final String password;
    public final String note;

    protected Password(Parcel in) {
        name = in.readString();
        url = in.readString();
        password = in.readString();
        note = in.readString();
    }

    public Password(String name, String url, String password, String note) {
        this.name = name;
        this.url = url;
        this.password = password;
        this.note = note;
    }

    public static final Creator<Password> CREATOR = new Creator<Password>() {
        @Override
        public Password createFromParcel(Parcel in) {
            return new Password(in);
        }

        @Override
        public Password[] newArray(int size) {
            return new Password[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(name);
        parcel.writeString(url);
        parcel.writeString(password);
        parcel.writeString(note);
    }
}
