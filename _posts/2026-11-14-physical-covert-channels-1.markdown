---
title: "Optical payload delivery from Android to Linux - part 1. Manchester coding"
date: 2026-11-14 10:00:00 +0300
header:
  teaser: "/assets/images/235/photo_2026-11-15_21-37-00.jpg"
categories:
  - research
tags:
  - linux
  - malware
  - math
  - physics
  - signal processing
  - blue team
---

﷽

Hello, cybersecurity enthusiasts and white hackers!    

![malware](/assets/images/235/photo_2026-11-15_21-37-00.jpg){:class="img-responsive"}    

In my [previous DSP research](), we encoded bytes as sound. Welcome to a new series: **Optical payload delivery in Malware Development**. Over the next few parts, I will try to explore how to treat shellcode not as acoustic channel, but as an optical. This part sends a fixed `MEOW` frame from an Android screen as timed brightness changes. Since I have only my Thinkpad machines, a ThinkPad camera records the display; a C receiver checks the frame and dispatches `MEOW` to a linked Linux x86-64 assembly function that prints `Meow-meow!`.     

As usual, let's imagine that the Android app uses no permissions and makes no network connection. The receiver gets the video from the ThinkPad camera, FFmpeg extracts grayscale samples, and the C program validates the frame's CRC before calling the fixed handler. The received bytes are a four-byte identifier; the receiver does not execute them as machine code yet.      

The synthetic trace, generated MP4 and Moto G54 screenrecord decode `MEOW` and print `Meow-meow!`. I also completed the physical Android-screen-to-ThinkPad-camera run in Demo 2: the C receiver recovered `MEOW`, validated CRC `0x0ead`, and printed `Meow-meow!`.     

### the channel and concept

An endpoint can encode bytes as timed changes in screen brightness. A nearby camera records those changes, and a receiver reconstructs the frame.    

Our physical path is:    

```bash
Android app -> screen pixels -> light -> ThinkPad camera -> recorded video
                                                              |
                                                              v
                 C receiver + linked ASM <- grayscale samples <- FFmpeg
```

The Android screen sends the signal while the ThinkPad camera records it. FFmpeg converts the selected video region into one grayscale sample per frame, and the C receiver decodes that stream after capture.    

### frame and modulation

The frame is small:    

```bash
AA AA AA AA | D3 91 | length: 1 byte | text: 1..32 bytes | CRC: 2 bytes
 preamble     sync                                      high byte first
```

All bytes travel most significant bit first. The four-byte payload ID is `MEOW`. After CRC validation, the receiver dispatches that ID to one fixed handler. CRC-16/CCITT-FALSE uses polynomial `0x1021`, initial value `0xffff`, no reflection and no final XOR; it covers the length byte and payload.     

We use Manchester encoding:    

```bash
bit 0: gray 80  -> gray 176
bit 1: gray 176 -> gray 80
          250 ms     250 ms
```

Every bit contains a transition. The receiver compares the mean intensity of the first half with the second half, so it does not need a single global dark/light threshold. It still needs enough contrast in the captured image.    

One bit takes `0.5` seconds, giving a raw rate of `2 bits/s`. The `13`-byte `MEOW` frame takes `52` seconds, plus five seconds of leading gray and two seconds of trailing gray: `59` seconds total.      

The full phone screen stays at gray `128` while idle and during the guards. During the frame it switches between gray `80` and `176`. The app requests a fixed screen brightness for the run and hides its prompt while transmitting, leaving the camera's region of interest as a uniform patch.     

### mathematical model and decoding condition

First of all, we need some theoretical fundament. In the simple terms, the Android app changes the gray code across the screen. The phone display and ThinkPad camera transform it before the receiver sees a sample.     

Let the transmitted gray code be $$u(t)\in\{80,128,176\}$$. The display maps it to emitted luminance $$L(t)=F(u(t))$$, where $$F$$ models the panel's static transfer curve, current brightness and color processing. For frame $$k$$, the camera's ROI value can be approximated as

$$
\begin{aligned}
y_k = Q\!\Biggl(&a_k + g_k \frac{1}{T_e}\int_{t_k}^{t_k+T_e} L(\tau)\,d\tau \\
                &{}+ n_k \Biggr).
\end{aligned}
$$

Here $$T_e$$ is exposure time, $$t_k$$ is the exposure start, $$g_k$$ is camera gain, $$a_k$$ is offset, $$n_k$$ represents sensor and image-processing noise, and $$Q$$ includes quantization and video encoding. Rolling shutter makes $$t_k$$ vary with image row; choosing a small ROI near the center of the phone screen limits, but does not eliminate, this effect. The grayscale bytes produced by FFmpeg are the $$y_k$$ used by `receiver.c`.

#### Manchester mapping

Let a bit be $$b_i\in\{0,1\}$$, a bit period be $$T_b=0.5\,\mathrm{s}$$, and a half-bit period be $$T_h=T_b/2=0.25\,\mathrm{s}$$. Define the light state $$m(t)\in\{0,1\}$$, with gray levels $$G_L=80$$ and $$G_H=176$$. For time $$\tau\in[0,T_b)$$ within the bit:

$$
\begin{aligned}
m_i(\tau)&=\begin{cases}
b_i, & 0\leq\tau<T_h,\\
1-b_i, & T_h\leq\tau<T_b,
\end{cases} \\[0.4em]
u_i(\tau)&=G_L+(G_H-G_L)m_i(\tau).
\end{aligned}
$$

Thus bit `0` is dark then light; bit `1` is light then dark. This is exactly the decision in `grayAt()` in `OpticalActivity.java`: `value` is $$b_i$$, and the light state is $$b_i$$ for the first half and $$1-b_i$$ for the second.

Manchester coding is DC balanced over a complete bit. In the code domain:

$$
\begin{aligned}
\frac{1}{T_b}\int_0^{T_b}m_i(\tau)\,d\tau&=\frac12, \\[0.4em]
\frac{1}{T_b}\int_0^{T_b}u_i(\tau)\,d\tau&=\frac{G_L+G_H}{2}=128.
\end{aligned}
$$

The two bit values have the same average code value; the information is in the direction of the transition. Under a static display transfer function, both bit values also spend equal time at each emitted level, so their ideal average emitted luminance is $$\left(F(G_L)+F(G_H)\right)/2$$, even if $$F$$ is nonlinear. This can reduce sensitivity to a constant offset, but does not remove gain changes, exposure adaptation, clipping, display response or frame loss.

#### when the Manchester decision is correct

Assume the receiver has found the correct frame phase and half-bit duration, and its two central windows lie inside their corresponding transmitted halves. Let their noiseless measured means be $$\mu_0$$ and $$\mu_1$$, with $$\Delta=\mu_H-\mu_L>0$$. The differential statistic is

$$
D_i=\bar y_{i,0}-\bar y_{i,1}.
$$

Under the mapping above, $$D_i=+\Delta$$ for bit `1`, and $$D_i=-\Delta$$ for bit `0`. Therefore the sign of $$D_i$$ recovers the bit exactly when the two means remain ordered. In the code, `means[0] > means[1]` returns `1`.

Now suppose the average error in each half-window is bounded by $$\eta$$: $$\lvert \bar y_{i,j}-\mu_{i,j} \rvert\leq\eta$$. For bit one, write the observed means as $$\bar y_{i,0}=\mu_H+\epsilon_0$$ and $$\bar y_{i,1}=\mu_L+\epsilon_1$$, where $$\lvert \epsilon_0 \rvert,\lvert \epsilon_1 \rvert\leq\eta$$. Then

$$
D_i=\Delta+\epsilon_0-\epsilon_1\geq\Delta-2\eta.
$$

For bit zero, $$D_i\leq-\Delta+2\eta$$. Thus $$\Delta>2\eta$$ preserves the sign in either case. The implementation also rejects pairs whose differential magnitude is below 6 gray levels. A sufficient condition for both the correct sign and this threshold is

$$
\Delta>6+2\eta.
$$

This is a conditional correctness result for the Manchester decision. Honestly, it does not prove that a particular camera produces this contrast; $$\Delta$$ and $$\eta$$ must be measured from its actual recording. The implementation averages the central 60% of each half, matching the `0.2` and `0.8` bounds in `byte_at()`.

#### timing and exposure condition

The camera's normalized sample stream is nominally $$f_s=30$$ samples/s. Each half-bit therefore spans

$$
N_h=f_sT_h=30\cdot0.25=7.5\text{ samples}.
$$

The receiver searches $$\widehat N_h$$ from `7.15` through `7.85` samples, stepping by `0.01`; `start` searches the phase in integer sample steps. If the true half duration is outside that range, or the capture contains a large timing discontinuity, this implementation can miss the frame.

For the central `60%` mean to avoid transitions, a sufficient timing condition for half $$j$$ is

$$
|e_j|+\frac{T_e}{2}+T_r+T_d < 0.2T_h,
$$

where $$e_j$$ is the sample-center timing error, $$T_e$$ is exposure duration, $$T_r$$ bounds display rise/fall smearing, and $$T_d$$ is timing uncertainty from capture and frame-rate conversion. It includes up to half a normalized sample (about `16.7 ms`) from the receiver's integer-sample phase search, plus any additional resampling or timestamp error. The right-hand side is `50 ms` here. This bound assumes a stable ROI, no clipping, and a bounded transition response; the current program does not read camera exposure or row timestamps and does not verify the inequality. It only searches a limited constant-rate timing range.

#### frame length, rate and error check

For payload length $$L$$ bytes, the frame has $$N=L+9$$ bytes: six preamble/sync bytes, one length byte, $$L$$ data bytes and two CRC bytes. The frame has $$8N$$ bits and $$16N$$ half-bits. Since each half takes $$T_h$$, the total duration including guards is

$$
\begin{aligned}
T_{\mathrm{total}}&=5\,\mathrm{s}+16(L+9)T_h+2\,\mathrm{s} \\
                  &=\bigl[7+4(L+9)\bigr]\,\mathrm{s}.
\end{aligned}
$$

For `MEOW`, $$L=4$$, so $$T_{\mathrm{total}}=59\,\mathrm{s}$$. For `Meow-meow!`, $$L=10$$, so $$T_{\mathrm{total}}=83\,\mathrm{s}$$. The useful payload rate is

$$
R_{\mathrm{useful}}=\frac{8L}{T_{\mathrm{total}}}\quad\text{bits/s},
$$

or about `0.54 bits/s` for `MEOW` and `0.96 bits/s` for `Meow-meow!`. The raw Manchester bit rate is `2 bits/s`; framing and guards lower the useful rate.

CRC-16/CCITT-FALSE uses generator polynomial $$x^{16}+x^{12}+x^5+1$$, initial remainder `0xffff`, and no reflection or final XOR. The implementation covers the length byte and payload. The receiver rejects a frame when the computed and received CRCs differ; CRC does not correct errors or authenticate the sender. The standard check value for ASCII `123456789` is `0x29b1`, a useful independent check of the CRC routine.

In polynomial terms, an error pattern $$E(x)$$ goes undetected only if $$g(x)$$ divides it. Since $$g$$ has degree `16`, every nonzero burst error of length at most `16` bits is detected; longer error patterns can still be divisible by $$g$$. This is error detection, not correction or authentication.

The inequalities define the contrast and timing conditions used by the decoder. The synthetic trace meets them by construction. The ThinkPad camera recording in Demo 2 recovered the frame; it is one successful capture, not a reliability estimate.

#### screenrecord check before camera

I first ran the current APK on the Moto G54 and recorded the phone with Android `screenrecord`. After cropping the gray signal patch, FFmpeg produced `2,033` grayscale samples. The C receiver found `MEOW`, verified CRC `0x0ead`, estimated the frame start at `11.87` s and the half-bit duration at `0.2490` s, then printed `Meow-meow!`. This confirms the sender and decoder work together in a digital capture; the ThinkPad camera did not record this signal.    

The screenrecord confirms the sender and decoder in a digital capture. The separate ThinkPad camera run below confirms the physical optical path: the receiver found the frame at `7.87` s, estimated a `0.2490` s half-bit, validated CRC `0x0ead`, and printed `Meow-meow!`. I keep the camera crop on the gray patch and the phone still during transmission.

For each camera run, I keep the sent text, original video, camera mode and frame rate, exposure, phone distance and angle, screen brightness, crop, and receiver output together. I calculate the light/dark contrast from the cropped samples as

$$
\Delta = \mu_{\mathrm{light}} - \mu_{\mathrm{dark}}.
$$

The decoder needs the contrast and timing bounds derived above. In particular, $$\Delta > 6 + 2\eta$$ requires $$\eta$$ to bound the error in each half-bit window; a sample standard deviation describes observed spread but is not, by itself, that bound.

For repeated transmissions, I count $$x$$ frames whose CRC passes and whose recovered text matches the sent text, out of $$n$$ attempts. The observed packet success fraction is

$$
\hat p = \frac{x}{n}.
$$

To show the uncertainty in that fraction, I use the 95% Wilson interval. With $$z=1.96$$, its center $$c$$ and half-width $$h$$ are

$$
\begin{aligned}
c&=\frac{\hat p+z^2/(2n)}{1+z^2/n}, \\[0.4em]
h&=\frac{z}{1+z^2/n}
\sqrt{\frac{\hat p(1-\hat p)}{n}+\frac{z^2}{4n^2}}.
\end{aligned}
$$

The interval is $$[c-h,c+h]$$. This gives a confidence range for the packet success fraction across repeated runs; one successful frame only confirms that single capture.

Bit-error rate needs individual bit decisions:

$$
\widehat{\mathrm{BER}}=\frac{N_{\mathrm{wrong}}}{N_{\mathrm{sent}}}.
$$

The current receiver only returns a frame after CRC validation, so it does not expose rejected bit decisions. I can calculate packet success from repeated runs now; to calculate BER, I first need to add per-bit candidate logging to the receiver.     

Let's create a first version of practical PoC.      

### practical example 1. Android transmitter

The app constructs a 13-byte frame: six preamble/sync bytes, one length byte, the four-byte ID `MEOW`, and a two-byte CRC. The CRC covers the length and payload:

```java
private byte[] makeFrame() {
    byte[] payload = {'M', 'E', 'O', 'W'};
    byte[] result = new byte[SYNC.length + 1 + payload.length + 2];
    for (int i = 0; i < SYNC.length; i++) result[i] = (byte) SYNC[i];
    result[SYNC.length] = (byte) payload.length;
    System.arraycopy(payload, 0, result, SYNC.length + 1, payload.length);
    int crc = crc16(result, SYNC.length, payload.length + 1);
    result[result.length - 2] = (byte) (crc >> 8);
    result[result.length - 1] = (byte) crc;
    return result;
}
```

`grayAt()` maps the current time to the screen level. It holds gray 128 for the five-second guard, then emits each bit as two 250-ms halves:

```java
private int grayAt(long elapsedMs) {
    long dataMs = elapsedMs - GUARD_MS;
    if (dataMs < 0 || dataMs >= frame.length * 4000L) return 128;
    long half = dataMs / HALF_MS;
    long bit = half / 2;
    int value = (frame[(int) (bit / 8)] >> (7 - (bit & 7))) & 1;
    boolean light = (half & 1) == 0 ? value == 1 : value == 0;
    return light ? 176 : 80;
}
```

Tap **Meow! ♥️** to start the 59-second frame. The button is disabled during transmission, the status line changes, and the wide gray patch carries the timed levels while the cat and plot remain visible. The activity derives each level from elapsed time instead of sleeping once per half-bit. If the UI thread skips a half-bit, the app stops the run so it does not silently send a malformed frame. On completion, the patch returns to gray 128.

The activity keeps the cat, labels and plot visible while the wide gray patch carries the signal. The vertical stack is centered slightly below the screen midpoint; this keeps the transmission area easy to frame with the camera.

Now the complete Android activity (`OpticalActivity.java`):

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

public final class OpticalActivity extends Activity {
    private static final long GUARD_MS = 5000;
    private static final long HALF_MS = 250;
    private static final int[] SYNC = {0xaa, 0xaa, 0xaa, 0xaa, 0xd3, 0x91};

    private final Handler main = new Handler(Looper.getMainLooper());
    private View signal;
    private Button transmit;
    private TextView status;
    private SignalPlotView plot;
    private byte[] frame;
    private long started;
    private long lastHalf = -1;
    private boolean sending;
    private int previousGray = -1;

    private final Runnable updateSignal = new Runnable() {
        @Override public void run() {
            if (!sending) return;
            long elapsed = SystemClock.elapsedRealtime() - started;
            long duration = 7000 + frame.length * 4000L;
            if (elapsed >= duration) {
                finishSignal("Frame sent. Check the C receiver.");
                return;
            }
            if (elapsed >= GUARD_MS && elapsed < duration - 2000) {
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
        frame = makeFrame();

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

        TextView payload = new TextView(this);
        payload.setText("PAYLOAD   MEOW     •     MANCHESTER     •     CRC-16");
        payload.setTextColor(Color.rgb(211, 219, 234));
        payload.setTextSize(11);
        payload.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams payloadParams = centered(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(32));
        payloadParams.topMargin = dp(8);
        page.addView(payload, payloadParams);

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
        sending = true;
        lastHalf = -1;
        previousGray = -1;
        started = SystemClock.elapsedRealtime();
        transmit.setEnabled(false);
        transmit.setText("Sending MEOW…");
        status.setText("Preamble  ->  payload  ->  CRC");
        plot.clear();
        main.removeCallbacks(updateSignal);
        main.post(updateSignal);
    }

    private int grayAt(long elapsedMs) {
        long dataMs = elapsedMs - GUARD_MS;
        if (dataMs < 0 || dataMs >= frame.length * 4000L) return 128;
        long half = dataMs / HALF_MS;
        long bit = half / 2;
        int value = (frame[(int) (bit / 8)] >> (7 - (bit & 7))) & 1;
        boolean light = (half & 1) == 0 ? value == 1 : value == 0;
        return light ? 176 : 80;
    }

    private byte[] makeFrame() {
        byte[] payload = {'M', 'E', 'O', 'W'};
        byte[] result = new byte[SYNC.length + 1 + payload.length + 2];
        for (int i = 0; i < SYNC.length; i++) result[i] = (byte) SYNC[i];
        result[SYNC.length] = (byte) payload.length;
        System.arraycopy(payload, 0, result, SYNC.length + 1, payload.length);
        int crc = crc16(result, SYNC.length, payload.length + 1);
        result[result.length - 2] = (byte) (crc >> 8);
        result[result.length - 1] = (byte) crc;
        return result;
    }

    private int crc16(byte[] data, int offset, int length) {
        int crc = 0xffff;
        for (int i = 0; i < length; i++) {
            crc ^= (data[offset + i] & 0xff) << 8;
            for (int bit = 0; bit < 8; bit++)
                crc = (crc & 0x8000) != 0 ? ((crc << 1) ^ 0x1021) & 0xffff
                        : (crc << 1) & 0xffff;
        }
        return crc;
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
        if (sending) finishSignal("Transmission stopped. Tap Meow! to retry.");
        super.onPause();
    }

    @Override protected void onDestroy() {
        main.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
```

The small `SignalPlotView` draws the observed gray transitions for the interface; it is separate from the wide patch captured by the receiver:

```java
package lab.opticalmeow;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.View;

public final class SignalPlotView extends View {
    private final float[] levels = new float[32];
    private final Paint grid = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint wave = new Paint(Paint.ANTI_ALIAS_FLAG);
    private int count;

    public SignalPlotView(Context context) {
        super(context);
        grid.setColor(0xFF34445D);
        grid.setStrokeWidth(1.0f);
        wave.setColor(0xFF69DCD5);
        wave.setStrokeWidth(4.0f);
        wave.setStyle(Paint.Style.STROKE);
        wave.setStrokeCap(Paint.Cap.ROUND);
        wave.setStrokeJoin(Paint.Join.ROUND);
    }

    public void clear() {
        count = 0;
        invalidate();
    }

    public void addLevel(int gray) {
        if (count == levels.length) {
            System.arraycopy(levels, 1, levels, 0, levels.length - 1);
            count--;
        }
        levels[count++] = gray > 128 ? 1.0f : (gray < 128 ? 0.0f : 0.5f);
        invalidate();
    }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float w = getWidth();
        float h = getHeight();
        canvas.drawLine(0, h / 2, w, h / 2, grid);
        canvas.drawLine(0, h / 4, w, h / 4, grid);
        canvas.drawLine(0, 3 * h / 4, w, 3 * h / 4, grid);
        if (count == 0) return;
        Path path = new Path();
        for (int i = 0; i < count; i++) {
            float x = i * w / Math.max(1, levels.length - 1);
            float y = h - levels[i] * h;
            if (i == 0) path.moveTo(x, y);
            else path.lineTo(x, y);
        }
        canvas.drawPath(path, wave);
    }
}
```

For a repeatable decoder check without a screen or camera, `trace.c` generates the same grayscale samples at 30 samples per second. This is a software fixture, not an optical transmission:

```c
/*
 * trace.c - synthetic fixture for the optical receiver
 * author: @cocomelonc
 * gcc -std=c11 -O2 -Wall -Wextra trace.c -o trace
 */
#include <stdint.h>
#include <stdio.h>

static uint16_t crc16(const uint8_t *p, size_t n) {
  uint16_t crc = 0xffff;
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint16_t)p[i] << 8;
    for (int j = 0; j < 8; j++)
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                            : (uint16_t)(crc << 1);
  }
  return crc;
}

static int gray_at(const uint8_t *frame, size_t n, double seconds) {
  double t = seconds - 5.0;
  if (t < 0 || t >= (double)n * 4.0) return 128;
  size_t half = (size_t)(t / 0.25);
  size_t bit = half / 2;
  int value = (frame[bit / 8] >> (7 - bit % 8)) & 1;
  int light = (half & 1) ? !value : value;
  return light ? 176 : 80;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s output.u8\n", argv[0]);
    return 2;
  }
  uint8_t frame[13] = {0xaa, 0xaa, 0xaa, 0xaa, 0xd3, 0x91, 4, 'M', 'E', 'O', 'W'};
  uint16_t crc = crc16(frame + 6, 5);
  frame[11] = (uint8_t)(crc >> 8);
  frame[12] = (uint8_t)crc;
  FILE *f = fopen(argv[1], "wb");
  if (!f) { perror(argv[1]); return 1; }
  for (size_t i = 0; i < 59 * 30; i++) {
    if (fputc(gray_at(frame, sizeof(frame), (double)i / 30.0), f) == EOF) {
      perror("trace write");
      fclose(f);
      return 1;
    }
  }
  if (fclose(f) != 0) { perror("trace close"); return 1; }
  fprintf(stderr, "[=^..^=] synthetic fixture; CRC %04x; no display or camera used\n", crc);
  return 0;
}
```

### practical example 2. receiver

FFmpeg gives us one grayscale value per video frame after cropping the signal area and averaging it. We normalize the stream to 30 samples per second. A nominal half-bit then occupies 7.5 samples. The receiver searches phase and half-bit duration, checks the preamble and length, and accepts a candidate only when its CRC matches.

After CRC validation, the receiver compares the payload with MEOW. That ID calls meow_print(), a normal function linked into the C program. The bytes received from the screen are not copied into executable memory.

The fixed handler uses the Linux x86-64 write system call:

```nasm
/*
 * meow.S - fixed Linux x86-64 payload action
 * author: @cocomelonc
 */
.section .rodata
message:
  .ascii "Meow-meow!\n"
message_len = . - message

.text
.globl meow_print
.type meow_print, @function
meow_print:
  mov $1, %rax
  mov $1, %rdi
  lea message(%rip), %rsi
  mov $message_len, %rdx
  syscall
  ret
.size meow_print, .-meow_print

.section .note.GNU-stack,"",@progbits
```

Now the complete full source code (`receiver.c`), the receiver scans the sample stream, validates the frame and dispatches `MEOW`:    

```c
/*
 * receiver.c - offline optical Manchester decoder, 30 grayscale samples/s
 * author: @cocomelonc
 * gcc -std=c11 -O2 -Wall -Wextra receiver.c meow.S -o receiver -lm
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

extern void meow_print(void);

static uint16_t crc16(const uint8_t *p, size_t n) {
  uint16_t crc = 0xffff;
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint16_t)p[i] << 8;
    for (int j = 0; j < 8; j++)
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                            : (uint16_t)(crc << 1);
  }
  return crc;
}

/* Average the central 60 percent of each half to avoid transitions. */
static int byte_at(const double *sum, size_t n, double start, double half, int byte) {
  int value = 0;
  for (int b = 0; b < 8; b++) {
    double means[2];
    for (int h = 0; h < 2; h++) {
      double pos = start + (byte * 16 + b * 2 + h) * half;
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

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s samples.u8 [recovered.txt]\n", argv[0]); return 2;
  }
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror(argv[1]); return 2; }
  uint8_t *raw = malloc(18001);
  double *sum = calloc(18001, sizeof(double));
  if (!raw || !sum) { fprintf(stderr, "out of memory\n"); fclose(f); free(raw); free(sum); return 2; }
  size_t n = fread(raw, 1, 18001, f);
  int error = ferror(f);
  fclose(f);
  if (error || n > 18000) {
    fprintf(stderr, "input error or more than 10 minutes at 30 samples/s\n"); free(raw); free(sum); return 2;
  }
  for (size_t i = 0; i < n; i++) sum[i + 1] = sum[i] + raw[i];
  free(raw);
  const uint8_t sync[6] = {0xaa, 0xaa, 0xaa, 0xaa, 0xd3, 0x91};
  /* Search phase and clock rate; the camera and sender share no clock. */
  for (int tick = 715; tick <= 785; tick++) {
    double half = tick / 100.0;
    for (size_t start = 0; (double)start + 160.0 * half <= (double)n; start++) {
      uint8_t frame[41];
      int ok = 1;
      for (int j = 0; j < 6; j++) {
        int v = byte_at(sum, n, (double)start, half, j);
        if (v != sync[j]) { ok = 0; break; }
        frame[j] = (uint8_t)v;
      }
      if (!ok) continue;
      int len = byte_at(sum, n, (double)start, half, 6);
      if (len < 1 || len > 32) continue;
      frame[6] = (uint8_t)len;
      for (int j = 7; j < len + 9; j++) {
        int v = byte_at(sum, n, (double)start, half, j);
        if (v < 0) { ok = 0; break; }
        frame[j] = (uint8_t)v;
      }
      if (!ok) continue;
      uint16_t got = (uint16_t)((uint16_t)frame[7 + len] << 8 | frame[8 + len]);
      uint16_t want = crc16(frame + 6, (size_t)len + 1);
      if (got != want) continue;
      if (argc == 3) {
        FILE *out = fopen(argv[2], "wb");
        if (!out) { perror(argv[2]); free(sum); return 2; }
        int written = fwrite(frame + 7, 1, (size_t)len, out) == (size_t)len;
        int closed = fclose(out) == 0;
        if (!written || !closed) { fprintf(stderr, "output error\n"); free(sum); return 2; }
      }
      printf("[=^..^=] valid CRC %04x; %d bytes; start %.2f s; half %.4f s\n",
             got, len, start / 30.0, half / 30.0);
      printf("[=^..^=] received: ");
      for (int i = 0; i < len; i++) {
        unsigned char c = frame[7 + i];
        if (c >= 32 && c <= 126) putchar(c); else printf("\\x%02x", c);
      }
      putchar('\n');
      if (len == 4 && memcmp(frame + 7, "MEOW", 4) == 0) {
        printf("[=^..^=] CRC valid; dispatching the fixed MEOW handler\n");
        fflush(stdout);
        meow_print();
      }
      free(sum); return 0;
    }
  }
  fprintf(stderr, "[=^..^=] no valid frame; check crop, exposure, timing and complete capture\n");
  free(sum); return 1;
}
```

### demo setup

So, the Android app changes only the phone display. It requests no Android permissions. The ThinkPad uses its camera and FFmpeg to record and decode the visible signal.

Install the C compiler, FFmpeg, V4L2 tools and ADB on my Parrot/Debian:

```bash
sudo apt update
sudo apt install gcc ffmpeg v4l-utils adb
```

![malware](/assets/images/235/2026-11-18_10-23.png){:class="img-responsive"}    

![malware](/assets/images/235/2026-11-18_10-24.png){:class="img-responsive"}    

Build first:

```bash
cd ~/hacking/optical-malware-delivery-poc/android
./gradlew assembleDebug
```

![malware](/assets/images/235/2026-11-18_10-26.png){:class="img-responsive"}    

![malware](/assets/images/235/2026-11-18_10-26_1.png){:class="img-responsive"}    

then install the Android app:      

```bash
adb devices -l
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

![malware](/assets/images/235/2026-11-18_10-28.png){:class="img-responsive"}    

![malware](/assets/images/235/2026-11-18_10-30.png){:class="img-responsive"}    

The APK is at `app/build/outputs/apk/debug/app-debug.apk`. The manifest contains no permission declarations. The activity uses a new full-bleed cat illustration for its launcher icon and centers the interface slightly below the vertical midpoint:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:allowBackup="false"
        android:icon="@mipmap/ic_launcher"
        android:label="ReconCat Optical"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:theme="@android:style/Theme.Material.Light.NoActionBar">
        <activity
            android:name=".OpticalActivity"
            android:configChanges="orientation|screenSize"
            android:exported="true"
            android:screenOrientation="portrait">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

![malware](/assets/images/235/photo_2026-11-18_10-31-44.jpg){:class="img-responsive"}    

Build the C receiver:    

```bash
gcc -std=c11 -O2 -Wall -Wextra receiver.c meow.S -o receiver -lm
```

![malware](/assets/images/235/2026-11-18_10-21.png){:class="img-responsive"}    

and its fixed handler:    

```bash
gcc -std=c11 -O2 -Wall -Wextra trace.c -o trace
```

![malware](/assets/images/235/2026-11-18_10-33.png){:class="img-responsive"}    

### demo 1. validate the software path

Generate a deterministic grayscale trace and pass it to the receiver:

```bash
./trace meow.u8
./receiver meow.u8 recovered.txt
cat recovered.txt; printf '\n'
```

Expected output:

![malware](/assets/images/235/2026-11-18_17-50.png){:class="img-responsive"}    

The MP4 path is also reproducible:

```bash
ffmpeg -y -v error -f rawvideo -pixel_format gray -video_size 1x1 -framerate 30 -i meow.u8 -vf 'scale=640:480:flags=neighbor' -c:v libx264 -pix_fmt yuv420p generated.mp4
ffmpeg -y -v error -i generated.mp4 -an -vf 'crop=iw/4:ih/2:3*iw/8:ih/4,format=gray,scale=1:1:flags=area,fps=30' -f rawvideo -pix_fmt gray from-video.u8
./receiver from-video.u8
```

I ran both paths: each recovered CRC `0ead`, dispatched `MEOW`, and printed `Meow-meow!`.   

![malware](/assets/images/235/2026-11-18_17-51.png){:class="img-responsive"}    

![malware](/assets/images/235/2026-11-18_17-51_1.png){:class="img-responsive"}    

### Android screenrecord check

I installed the current APK on a Motorola moto g54 5G and captured the display with Android's `screenrecord`. FFmpeg extracted only the wide gray patch, then the same C receiver decoded the frame. This checks the current Android UI and frame generator through a digital screen capture; it does not exercise the phone display, light path or ThinkPad camera.

Start recording, tap **Meow! ♥️** while it runs, then pull the finished video. The crop below matches the `1080×2400` Moto capture; adjust it if the device resolution or layout differs:

```bash
adb shell screenrecord --time-limit 75 --bit-rate 4000000 /sdcard/optical.mp4
```

![malware](/assets/images/235/photo_2026-11-18_18-55-28.jpg){:class="img-responsive"}    

![malware](/assets/images/235/photo_2026-11-18_18-55-27.jpg){:class="img-responsive"}    

![malware](/assets/images/235/photo_2026-11-18_18-56-30.jpg){:class="img-responsive"}    

![malware](/assets/images/235/photo_2026-11-18_18-56-19.jpg){:class="img-responsive"}    

![malware](/assets/images/235/photo_2026-11-18_18-56-12.jpg){:class="img-responsive"}    

![malware](/assets/images/235/photo_2026-11-18_18-55-49.jpg){:class="img-responsive"}    

```bash
adb pull /sdcard/optical.mp4 optical-screen.mp4
ffmpeg -i optical-screen.mp4 -an -vf 'crop=iw*0.90:ih*0.22:iw*0.05:ih*0.455,format=gray,scale=1:1:flags=area,fps=30' -f rawvideo -pix_fmt gray optical-screen.u8
```

![malware](/assets/images/235/2026-11-18_18-59.png){:class="img-responsive"}    

![malware](/assets/images/235/2026-11-18_18-59_1.png){:class="img-responsive"}    

![malware](/assets/images/235/2026-11-18_18-59_2.png){:class="img-responsive"}    

![malware](/assets/images/235/2026-11-18_19-00.png){:class="img-responsive"}    

then run receiver:      

```bash
./receiver optical-screen.u8 optical-screen.txt
cat optical-screen.txt; printf '\n'
```

The current build produced `2,033` grayscale samples. The receiver reported a valid CRC `0x0ead`, four-byte `MEOW` payload, start at `11.87s` and estimated half-bit duration `0.2490s`, then printed `Meow-meow!`.

![malware](/assets/images/235/2026-11-18_19-02.png){:class="img-responsive"}    

### demo 2. record the optical signal

List the ThinkPad camera and start a `70`-second capture. Use the device and a resolution reported by `v4l2-ctl` if they differ from these defaults:    

```bash
v4l2-ctl --list-devices
ffmpeg -f v4l2 -framerate 30 -video_size 640x480 -i /dev/video0 -t 70 -an -c:v libx264 -preset ultrafast -crf 18 capture.mp4
```

![malware](/assets/images/235/2026-11-18_19-04.png){:class="img-responsive"}    

for my Thinkpad X1 Carbon:     

![malware](/assets/images/235/2026-11-18_19-10.png){:class="img-responsive"}   

![malware](/assets/images/235/2026-11-18_19-11.png){:class="img-responsive"}   

While FFmpeg is recording, we need to open ReconCat Optical on Android, aim the ThinkPad camera at the phone screen, and tap **Meow! ♥️** button on the screen. Keep the phone centered and still until the app reports that the frame was sent. The app sends one `59`-second frame; the longer capture leaves room for starting and stopping the run.     

![malware](/assets/images/235/photo_2026-11-18_19-31-44.jpg){:class="img-responsive"}   

Preview before capture:     

```bash
ffplay -f v4l2 -input_format mjpeg -framerate 30 -video_size 640x480 -vf 'drawbox=x=(iw-48)/2:y=(ih-48)/2:w=48:h=48:color=lime:t=2' /dev/video0
```

![malware](/assets/images/235/photo_2026-11-18_19-34-53.jpg){:class="img-responsive"}   

Run for capture:     

```bash
ffmpeg -f v4l2 -input_format mjpeg -framerate 30 -video_size 640x480 -i /dev/video0 -t 70 -an -c:v libx264 -preset ultrafast -crf 18 capture.mp4
```

![malware](/assets/images/235/2026-11-18_19-43.png){:class="img-responsive"}   

![malware](/assets/images/235/photo_2026-11-18_19-43-56.jpg){:class="img-responsive"}   

![malware](/assets/images/235/photo_2026-11-18_19-43-56_2.jpg){:class="img-responsive"}   

Inspect a frame and adjust the crop so the receiver averages only the gray signal patch. Keep the cat, text, plot, status and button outside the ROI; adjust its position and size for your camera view:

```bash
ffmpeg -i capture.mp4 -ss 8 -frames:v 1 -vf 'crop=iw/4:ih/2:3*iw/8:ih/4' roi.png
```

Extract the same region as one grayscale sample per frame, then decode it:

```bash
ffmpeg -i capture.mp4 -an -vf 'crop=iw/4:ih/2:3*iw/8:ih/4,format=gray,scale=1:1:flags=area,fps=30' -f rawvideo -pix_fmt gray capture.u8
./receiver capture.u8 physical.txt
```

or (for my device and Thinkpad X1 camera installation):    

```bash
ffmpeg -y -i capture.mp4 -an -vf 'crop=48:48,format=gray,scale=1:1:flags=area,fps=30' -f rawvideo -pix_fmt gray capture.u8
./receiver capture.u8 physical.txt
```

![malware](/assets/images/235/2026-11-18_19-49.png){:class="img-responsive"}   

![malware](/assets/images/235/2026-11-18_19-50.png){:class="img-responsive"}   

So, as you can see, a physical run succeeded: the camera recording produced the expected `MEOW` frame, CRC `0x0ead`, and `Meow-meow!` output. The receiver found the frame at `7.87` s and estimated a `0.2490` s half-bit. This confirms one physical transmission; of course, repeated runs are needed to estimate reliability. I repeated it three times and everything works. Perfect! Meow =^..^=!     

### for blue teams

The Android app keeps the screen awake and changes the wide gray signal patch while transmitting. A camera recording can expose the frame sequence; the receiver then validates the CRC and calls its statically linked `meow_print()` function. This example does not allocate executable memory or launch a child process yet.    

### conclusion

The synthetic trace, generated MP4, Android screenrecord, and ThinkPad camera recording all reach the C receiver and pass CRC validation. The physical recording also triggers the linked assembly print handler, demonstrating the Android-screen-to-camera-to-Linux infostealer path end to end.     

Of course, I'm not the first one to come up with this; similar concepts are described in [VisiSploit](https://arxiv.org/abs/1607.03946) and [BRIGHTNESS](https://arxiv.org/abs/2002.01078).    

I hope this post is useful for mathematicians, physicists, malware researchers, C and Linux programmers, spreads awareness to the blue teamers of this interesting technique, and adds a weapon to the red teamers arsenal.      

[Manchester code](https://en.wikipedia.org/wiki/Manchester_code)    
[FFmpeg filter documentation](https://ffmpeg.org/ffmpeg-filters.html)    
[source code in github](https://github.com/cocomelonc/optical-malware-delivery-poc)     

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!     
*PS. All drawings and screenshots are mine*
