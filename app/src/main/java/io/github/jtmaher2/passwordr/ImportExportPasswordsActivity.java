package io.github.jtmaher2.passwordr;

import android.content.Context;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.RadioGroup;

public class ImportExportPasswordsActivity extends AppCompatActivity {
    static final int REQUEST_PASSWORD_IMPORT = 1;

    public static Intent createIntent(
            Context context) {
        Intent startIntent = new Intent();

        return startIntent.setClass(context, ImportExportPasswordsActivity.class);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_import_export_passwords);

        final RadioGroup importExport = findViewById(R.id.import_export_group),
                xmlJson = findViewById(R.id.xml_json_group);

        Button goButton = findViewById(R.id.go_btn);
        goButton.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                String type = (xmlJson.getCheckedRadioButtonId() == R.id.xmlRadioBtn ? "application/xml" : "application/json");

                if (importExport.getCheckedRadioButtonId() == R.id.importRadioBtn) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType(type);
                    if (intent.resolveActivity(getPackageManager()) != null) {
                        startActivityForResult(intent, REQUEST_PASSWORD_IMPORT);
                    }
                } else {

                }
            }
        });
    }
}
