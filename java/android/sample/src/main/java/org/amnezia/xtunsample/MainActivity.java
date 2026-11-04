package org.amnezia.xtunsample;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;

import org.amnezia.xtun.XtunProxy;

public class MainActivity extends Activity {
    private static final int REQUEST_VPN = 1;
    private int proto;
    private EditText conf;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Spinner spinner = new Spinner(this);
        spinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, XtunProxy.Proto.values()));
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
                proto = i;
            }
            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {}
        });
        proto = getPreferences(MODE_PRIVATE).getInt("proto", 0);
        spinner.setSelection(proto);

        conf = new EditText(this);
        conf.setHint("Insert config");
        conf.setGravity(Gravity.TOP);
        conf.setTypeface(Typeface.MONOSPACE);
        conf.setText(getPreferences(MODE_PRIVATE).getString("conf", ""));

        Button start = new Button(this);
        start.setText("Start");
        start.setOnClickListener(v -> {
            getPreferences(MODE_PRIVATE).edit()
                    .putInt("proto", proto)
                    .putString("conf", conf.getText().toString())
                    .apply();
            Intent prepare = VpnService.prepare(this);
            if (prepare != null) {
                startActivityForResult(prepare, REQUEST_VPN);
            } else {
                onActivityResult(REQUEST_VPN, RESULT_OK, null);
            }
        });

        Button stop = new Button(this);
        stop.setText("Stop");
        stop.setOnClickListener(v -> startService(
                new Intent(this, XtunVpnService.class).setAction(XtunVpnService.ACTION_STOP)
        ));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setFitsSystemWindows(true);
        root.addView(spinner);
        root.addView(conf, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        root.addView(start);
        root.addView(stop);
        setContentView(root);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startService(new Intent(this, XtunVpnService.class)
                    .setAction(XtunVpnService.ACTION_START)
                    .putExtra("proto", proto)
                    .putExtra("conf", conf.getText().toString()));
        }
    }
}
