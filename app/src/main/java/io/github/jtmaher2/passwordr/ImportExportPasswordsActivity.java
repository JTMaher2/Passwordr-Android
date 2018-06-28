package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.JsonReader;
import android.util.Xml;
import android.view.View;
import android.widget.Button;
import android.widget.RadioGroup;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

public class ImportExportPasswordsActivity extends AppCompatActivity {
    static final int REQUEST_PASSWORD_IMPORT = 1;
    private static final String EXTRA_MASTER_PASSWORD = "extra_master_password";
    private static final String TYPE_XML = "text/xml";
    private static final String TYPE_KEEPASS = "text/keepass";
    private static final String TYPE_CSV = "text/csv";
    private static final String TYPE_JSON = "application/octet-stream";

    private static final String ns = null;
    private String mMasterPassword;
    private String mType; // either XML or JSON

    public static Intent createIntent(
            Context context,
            String masterPassword) {
        Intent startIntent = new Intent();

        return startIntent.setClass(context, ImportExportPasswordsActivity.class)
                .putExtra(EXTRA_MASTER_PASSWORD, masterPassword);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_import_export_passwords);

        final RadioGroup importExport = findViewById(R.id.import_export_group),
                xmlJson = findViewById(R.id.xml_json_group);

        /*xmlJson.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener(){
            @Override
            public void onCheckedChanged(RadioGroup radioGroup, int i) {
                if (radioGroup.getCheckedRadioButtonId() == R.id.keepassRadioBtn) {
                    if (importExport.getCheckedRadioButtonId() == R.id.exportRadioBtn) {
                        ((RadioButton)findViewById(R.id.exportRadioBtn)).toggle(); // turn off export button
                        ((RadioButton)findViewById(R.id.importRadioBtn)).toggle(); // turn on import button
                        Snackbar.make(findViewById(R.id.import_export_passwords_layout), "You can't export KeePass XML.", Snackbar.LENGTH_LONG).show();
                    }
                }
            }
        });

        importExport.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener(){
            @Override
            public void onCheckedChanged(RadioGroup radioGroup, int i) {
                if (radioGroup.getCheckedRadioButtonId() == R.id.exportRadioBtn) {
                    if (xmlJson.getCheckedRadioButtonId() == R.id.keepassRadioBtn) {
                        ((RadioButton)findViewById(R.id.exportRadioBtn)).toggle(); // turn off export button
                        ((RadioButton)findViewById(R.id.importRadioBtn)).toggle(); // turn on import button
                        Snackbar.make(findViewById(R.id.import_export_passwords_layout), "You can't export KeePass XML.", Snackbar.LENGTH_LONG).show();
                    }
                }
            }
        });*/

        Bundle extras = getIntent().getExtras();
        mMasterPassword = extras == null ? "" : extras.getString(EXTRA_MASTER_PASSWORD);

        Button goButton = findViewById(R.id.go_btn);
        goButton.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                if (xmlJson.getCheckedRadioButtonId() == R.id.xmlRadioBtn) {
                    mType = TYPE_XML;
                } else if (xmlJson.getCheckedRadioButtonId() == R.id.keepassRadioBtn) {
                    mType = TYPE_KEEPASS;
                } else {
                    mType = TYPE_JSON;
                }

                if (importExport.getCheckedRadioButtonId() == R.id.importRadioBtn) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    if (mType.equals(TYPE_KEEPASS))
                        intent.setType(TYPE_XML); // type/keepass is not valid, so replace
                    else
                        intent.setType(mType); // valid
                    if (intent.resolveActivity(getPackageManager()) != null) {
                        startActivityForResult(intent, REQUEST_PASSWORD_IMPORT);
                    }
                } else {
                    // export
                    if (mType.equals(TYPE_KEEPASS))
                        mType = TYPE_CSV; // change to CSV

                    startActivity(PasswordList.createIntent(getApplicationContext(), null, mMasterPassword, null, null, null, mType));
                    finish();
                }
            }
        });

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
    }

    @Override
    public boolean onSupportNavigateUp() {
        // go back to list
        startActivity(PasswordList.createIntent(getApplicationContext(), null, mMasterPassword, null, null, null, null));
        finish();
        return super.onSupportNavigateUp();
    }

    private ArrayList<Password> readPasswords(XmlPullParser parser) throws XmlPullParserException, IOException {
        ArrayList<Password> passwords = new ArrayList<>();

        parser.require(XmlPullParser.START_TAG, ns, "passwords");
        while (parser.next() != XmlPullParser.END_TAG) {
            if (parser.getEventType() != XmlPullParser.START_TAG) {
                continue;
            }
            String password = parser.getName();
            // Starts by looking for the entry tag
            if (password.equals("password")) {
                passwords.add(readPassword(parser));
            } else {
                skip(parser);
            }
        }
        return passwords;
    }

    // Parses the contents of a password. If it encounters a name, url, password, or note tag, hands them
    // off to their respective "read" methods for processing. Otherwise, skips the tag.
    private Password readPassword(XmlPullParser parser) throws XmlPullParserException, IOException {
        parser.require(XmlPullParser.START_TAG, ns, "password");
        String name = null;
        String url = null;
        String password = null;
        String note = null;
        while (parser.next() != XmlPullParser.END_TAG) {
            if (parser.getEventType() != XmlPullParser.START_TAG) {
                continue;
            }
            String field = parser.getName();
            switch (field) {
                case "name":
                    name = readField(parser, field);
                    break;
                case "url":
                    url = readField(parser, field);
                    break;
                case "password_str":
                    password = readField(parser, field);
                    break;
                case "note":
                    note = readField(parser, field);
                    break;
                default:
                    skip(parser);
                    break;
            }
        }
        return new Password(name, url, password, note);
    }

    // Extracts password field text values.
    private String readText(XmlPullParser parser) throws IOException, XmlPullParserException {
        String result = "";
        if (parser.next() == XmlPullParser.TEXT) {
            result = parser.getText();
            parser.nextTag();
        }
        return result;
    }

    // Processes field tag in the password list.
    private String readField(XmlPullParser parser, String fieldName) throws IOException, XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, ns, fieldName);
        String field = readText(parser);
        parser.require(XmlPullParser.END_TAG, ns, fieldName);
        return field;
    }

    // Skips tags the parser isn't interested in. Uses depth to handle nested tags. i.e.,
    // if the next tag after a START_TAG isn't a matching END_TAG, it keeps going until it
    // finds the matching END_TAG (as indicated by the value of "depth" being 0).
    private void skip(XmlPullParser parser) throws XmlPullParserException, IOException {
        if (parser.getEventType() != XmlPullParser.START_TAG) {
            throw new IllegalStateException();
        }
        int depth = 1;
        while (depth != 0) {
            switch (parser.next()) {
                case XmlPullParser.END_TAG:
                    depth--;
                    break;
                case XmlPullParser.START_TAG:
                    depth++;
                    break;
            }
        }
    }

    public Password readJSONPassword(JsonReader reader) throws IOException {
        String name = null,
                url = null,
                passwordStr = null,
                note = null;

        reader.nextName();
        reader.beginObject();
        while (reader.hasNext()) {
            String field = reader.nextName();
            switch (field) {
                case "name":
                    name = reader.nextString();
                    break;
                case "url":
                    url = reader.nextString();
                    break;
                case "password_str":
                    passwordStr = reader.nextString();
                    break;
                case "note":
                    note = reader.nextString();
                    break;
                default:
                    reader.skipValue();
                    break;
            }
        }
        reader.endObject();

        return new Password(name, url, passwordStr, note);
    }

    public ArrayList<Password> readJSONPasswords(JsonReader reader) throws IOException {
        ArrayList<Password> passwords = new ArrayList<>();

        reader.beginObject();
        while (reader.hasNext()) {
            if (reader.nextName().equals("passwords")) {
                reader.beginObject();
                while (reader.hasNext()) {
                    passwords.add(readJSONPassword(reader));
                }
                reader.endObject();
                break;
            }
        }

        return passwords;
    }

    // adds KeePass XML passwords to list based on XPath expression
    private void addKeePassXMLPasswordsToList(XPath xpath, XPathExpression expr,
                                           Document doc, ArrayList<Password> passwords) throws XPathExpressionException {
        NodeList entries = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);

        for (int entryIdx = 0; entryIdx < entries.getLength(); entryIdx++) {
            Node entry = entries.item(entryIdx);

            // get title
            String titleStr = "";
            XPathExpression titleExpr = xpath.compile("./String[Key = \"Title\"]");
            NodeList titles = (NodeList) titleExpr.evaluate(entry, XPathConstants.NODESET);
            for (int titleIdx = 0; titleIdx < titles.getLength(); titleIdx++) {
                Node title = titles.item(titleIdx);
                XPathExpression titleValExpr = xpath.compile("./Value");
                NodeList titleVals = (NodeList) titleValExpr.evaluate(title, XPathConstants.NODESET);
                for (int titleVal = 0; titleVal < titleVals.getLength(); titleVal++) {
                    titleStr = titleVals.item(titleVal).getTextContent();
                }
            }

            // get URL
            String urlStr = "";
            XPathExpression urlExpr = xpath.compile("./String[Key = \"URL\"]");
            NodeList urls = (NodeList) urlExpr.evaluate(entry, XPathConstants.NODESET);
            for (int urlIdx = 0; urlIdx < urls.getLength(); urlIdx++) {
                Node url = urls.item(urlIdx);
                XPathExpression urlValExpr = xpath.compile("./Value");
                NodeList urlVals = (NodeList) urlValExpr.evaluate(url, XPathConstants.NODESET);
                for (int urlVal = 0; urlVal < urlVals.getLength(); urlVal++) {
                    urlStr = urlVals.item(urlVal).getTextContent();
                }
            }

            // get password
            String passwordStr = "";
            XPathExpression passwordExpr = xpath.compile("./String[Key = \"Password\"]");
            NodeList passwordNodes = (NodeList) passwordExpr.evaluate(entry, XPathConstants.NODESET);
            for (int passwordIdx = 0; passwordIdx < passwordNodes.getLength(); passwordIdx++) {
                Node password = passwordNodes.item(passwordIdx);
                XPathExpression passwordValExpr = xpath.compile("./Value");
                NodeList passwordVals = (NodeList) passwordValExpr.evaluate(password, XPathConstants.NODESET);
                for (int passwordVal = 0; passwordVal < passwordVals.getLength(); passwordVal++) {
                    passwordStr = passwordVals.item(passwordVal).getTextContent();
                }
            }

            // get note
            String noteStr = "";
            XPathExpression noteExpr = xpath.compile("./String[Key = \"Note\"]");
            NodeList notes = (NodeList) noteExpr.evaluate(entry, XPathConstants.NODESET);
            for (int noteIdx = 0; noteIdx < notes.getLength(); noteIdx++) {
                Node note = notes.item(noteIdx);
                XPathExpression noteValExpr = xpath.compile("./Value");
                NodeList noteVals = (NodeList) noteValExpr.evaluate(note, XPathConstants.NODESET);
                for (int noteVal = 0; noteVal < noteVals.getLength(); noteVal++) {
                    noteStr = noteVals.item(noteVal).getTextContent();
                }
            }

            passwords.add(new Password(titleStr, urlStr, passwordStr, noteStr));
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == REQUEST_PASSWORD_IMPORT) {
            Uri uri = data.getData();
            if (uri != null) {
                // open the file
                InputStream input = null;
                try {
                    input = getContentResolver().openInputStream(uri);
                    ArrayList<Password> passwords = null;
                    if (input != null) {
                        switch (mType) {
                            case TYPE_XML:
                                XmlPullParser parser = Xml.newPullParser();
                                parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false);
                                parser.setInput(input, null);
                                parser.nextTag();
                                passwords = readPasswords(parser);
                                break;
                            case TYPE_KEEPASS:
                                passwords = new ArrayList<>();
                                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                                DocumentBuilder builder = factory.newDocumentBuilder();
                                Document doc = builder.parse(input);
                                XPathFactory xPathfactory = XPathFactory.newInstance();
                                XPath xpath = xPathfactory.newXPath();

                                XPathExpression outerEntriesExpr = xpath.compile("/KeePassFile/Root/Group/Entry");
                                addKeePassXMLPasswordsToList(xpath, outerEntriesExpr, doc, passwords);

                                XPathExpression innerEntriesExpr = xpath.compile("/KeePassFile/Root/Group/Group/Entry");
                                addKeePassXMLPasswordsToList(xpath, innerEntriesExpr, doc, passwords);

                                break;
                            case TYPE_JSON:
                                try (JsonReader reader = new JsonReader(new InputStreamReader(input, "UTF-8"))) {
                                    passwords = readJSONPasswords(reader);
                                }
                                break;
                        }
                    }

                    // go back to passwords list, passing the new passwords as an extra
                    startActivity(PasswordList.createIntent(getApplicationContext(), null, mMasterPassword, null, null, passwords, null));
                    finish();
                } catch (IOException | XmlPullParserException | ParserConfigurationException | XPathExpressionException | SAXException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        if (input != null)
                            input.close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        }
    }
}
