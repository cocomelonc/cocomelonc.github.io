---
title:  "Anti-DDoS research part 3: SYN flood detection with handshake asymmetry. Simple C, Python examples."
date:   2026-07-01 02:00:00 +0300
header:
  teaser: "/assets/images/213/2026-07-01_12-05.png"
categories:
  - linux
tags:
  - blue team
  - ddos
  - syn flood
  - detection
  - math
  - c
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![syn-asym](/assets/images/213/2026-07-01_12-05.png){:class="img-responsive"}    

In the previous Anti-DDoS posts I used wavelets for traffic anomaly detection. Today I want to switch from generic signal processing to a protocol-aware detector.    

The target is a classic L4 attack:

> TCP SYN flood.

No production architecture. No private telemetry. No attack tooling. Just defensive analysis on the public CICDDoS2019 `Syn.csv` file.

### idea

A simple SYN flood detector can look only at volume:

```bash
TCP flows/sec
packets/sec
SYN packets/sec
```

This is useful, but not enough as a general principle. The cybersecurity meaning of SYN flood is not just "many packets". It is:

> many connection attempts without proportional handshake completion.

The TCP handshake is:

```bash
client -> server: SYN
server -> client: SYN-ACK
client -> server: ACK
```

For a healthy service, request and response directions should have some symmetry. During a SYN flood, the forward direction becomes much stronger than the backward/completed side.

In CICFlowMeter CSV we do not have perfect kernel TCP state. But we do have useful flow-level proxy fields:

```bash
Total Fwd Packets
Total Backward Packets
SYN Flag Count
ACK Flag Count
Label
Timestamp
Protocol
```

So we can build a practical approximation of handshake asymmetry.

### dataset

I use the real CICDDoS2019 file:

```bash
./03-11/Syn.csv
```

![syn-asym](/assets/images/213/2026-07-01_09-53.png){:class="img-responsive"}    

As you can see, this file is large:

```text
1.8 GB
```

The preparation script streams it line by line and aggregates it into seconds. It does not load the whole CSV into memory.

Run:

```bash
python3 prepare_syn_real.py \
  --input /home/cocomelonc/research/datasets/ddos/03-11/Syn.csv \
  -o syn_handshake_timeseries.csv \
  --attack-label Syn
```

![syn-asym](/assets/images/213/2026-07-01_11-46.png){:class="img-responsive"}    


In my case:

```bash
source: /home/cocomelonc/research/datasets/ddos/03-11/Syn.csv
tcp rows converted: 4303967
seconds: 21614
attack-labeled seconds: 2820
wrote syn_handshake_timeseries.csv
```

The output format:

```csv
t,flows,fwd_pkts,bwd_pkts,syn_flags,ack_flags,oneway_flows,label
0,16281.0,56014.0,22770.0,4.0,16277.0,8314.0,1
1,27184.0,112916.0,46152.0,4.0,27180.0,12786.0,1
```

![ddos](/assets/images/213/2026-07-01_11-48.png){:class="img-responsive"}    

where:

- `flows` is TCP flows/sec;
- `fwd_pkts` is sum of `Total Fwd Packets`;
- `bwd_pkts` is sum of `Total Backward Packets`;
- `oneway_flows` counts flows with `Total Backward Packets == 0`;
- `label=1` means `Syn` attack was present in that second.

### math model

The basic volume detector uses:     

$$V_t = flows_t $$

This answers:      

*are there many TCP flows now?*     

But handshake asymmetry should also consider the response side.     

First, define forward/backward packet ratio:     

$$R_t = \frac{F_t + 1}{B_t + 1}$$

where:     

\(F_t\) is forward packets/sec;     
\(B_t\) is backward packets/sec;     
`+1` prevents division by zero.    

Then define one-way flow ratio:    

$$O_t = \frac{W_t}{flows_t}$$

where \(W_t\) is the number of flows with no backward packets.      

If `flows_t = 0`, we set:     

$$O_t = 0$$

The handshake asymmetry score:

$$
A_t =
flows_t \cdot \log(1 + R_t) \cdot (1 + O_t)
$$

Why this form?     

1. \(flows_t\) keeps attack volume.
2. \(\log(1+R_t)\) adds directional imbalance but avoids exploding too much.
3. \((1+O_t)\) increases score when many flows have no backward side.

This is still simple enough to compute in C.     

### robust baseline

Raw values are not enough. We need to compare current values to benign baseline.     

For any feature \(X_t\), robust z-score is:      

$$
Z_t =
\frac{X_t-\operatorname{median}(B)}
{1.4826 \cdot \operatorname{MAD}(B)}
$$

where:     

$$
\operatorname{MAD}(B)=
\operatorname{median}(|B_i-\operatorname{median}(B)|)
$$

Important detail: this file has many idle seconds with `flows=0`. If we include idle seconds in baseline, median and MAD become zero. That is mathematically bad.     

So baseline is learned from active benign seconds only:

$$
B=\{X_t : label_t=0 \land flows_t>0\}
$$

This gives a baseline for normal active TCP traffic, not for idle time.     

### practical example

The core feature calculation:

```cpp
static void compute_raw_features(sample_t *s, int n) {
  for (int i = 0; i < n; i++) {
    s[i].one_way_ratio = s[i].flows > 0.0 ? s[i].oneway_flows / s[i].flows : 0.0;
    s[i].fb_ratio = (s[i].fwd_pkts + 1.0) / (s[i].bwd_pkts + 1.0);

    s[i].volume_score_raw = s[i].flows;
    s[i].asym_score_raw =
      s[i].flows *
      log1p(s[i].fb_ratio) *
      (1.0 + s[i].one_way_ratio);
  }
}
```

Then robust normalization:

```cpp
double volume_med = median(benign_volume, benign_n);
double volume_sigma = 1.4826 * mad(benign_volume, benign_n, volume_med);
double asym_med = median(benign_asym, benign_n);
double asym_sigma = 1.4826 * mad(benign_asym, benign_n, asym_med);

for (int i = 0; i < n; i++) {
  samples[i].volume_z = (samples[i].volume_score_raw - volume_med) / volume_sigma;
  samples[i].asym_z = (samples[i].asym_score_raw - asym_med) / asym_sigma;
  samples[i].volume_alert = samples[i].volume_z > volume_threshold;
  samples[i].asym_alert = samples[i].asym_z > asym_threshold;
}
```

So, the full source code looks like this `hack.c`:    

```cpp
/*
 * hack.c
 * SYN flood detection with handshake asymmetry on CICDDoS2019 Syn.csv
 * this is defensive signal-processing code. It does not generate packets.
 * author @cocomelonc
 */
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SAMPLES 500000
#define LINE_MAX_LEN 4096
#define EVENT_MERGE_GAP 60
#define EVENT_GRACE 3

typedef struct {
  int t;
  double flows;
  double fwd_pkts;
  double bwd_pkts;
  double syn_flags;
  double ack_flags;
  double oneway_flows;
  int label;

  double one_way_ratio;
  double fb_ratio;
  double volume_score_raw;
  double asym_score_raw;
  double volume_z;
  double asym_z;
  int volume_alert;
  int asym_alert;
} sample_t;

typedef struct {
  int tp;
  int fp;
  int fn;
  int events;
} metrics_t;

static int cmp_double(const void *a, const void *b) {
  double x = *(const double *)a;
  double y = *(const double *)b;
  return (x > y) - (x < y);
}

static double median(double *v, int n) {
  double *tmp = (double *)malloc(sizeof(double) * n);
  if (!tmp) {
    perror("malloc");
    exit(1);
  }
  memcpy(tmp, v, sizeof(double) * n);
  qsort(tmp, n, sizeof(double), cmp_double);
  double result = (n % 2 == 0) ? (tmp[n / 2 - 1] + tmp[n / 2]) / 2.0 : tmp[n / 2];
  free(tmp);
  return result;
}

static double mad(double *v, int n, double med) {
  double *dev = (double *)malloc(sizeof(double) * n);
  if (!dev) {
    perror("malloc");
    exit(1);
  }
  for (int i = 0; i < n; i++) {
    dev[i] = fabs(v[i] - med);
  }
  double result = median(dev, n);
  free(dev);
  return result < 1e-9 ? 1e-9 : result;
}

static char *trim(char *s) {
  while (isspace((unsigned char)*s)) {
    s++;
  }
  if (*s == 0) {
    return s;
  }
  char *end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) {
    *end = 0;
    end--;
  }
  return s;
}

static int read_series(const char *path, sample_t *s) {
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
    exit(1);
  }

  char line[LINE_MAX_LEN];
  int n = 0;
  int line_no = 0;
  while (fgets(line, sizeof(line), f)) {
    line_no++;
    char *p = trim(line);
    if (*p == 0) {
      continue;
    }
    if (line_no == 1 && strstr(p, "flows") && strstr(p, "label")) {
      continue;
    }

    char *cols[8];
    for (int i = 0; i < 8; i++) {
      cols[i] = strtok(i == 0 ? p : NULL, ",");
      if (!cols[i]) {
        fprintf(stderr, "invalid CSV line %d\n", line_no);
        exit(1);
      }
    }
    if (n >= MAX_SAMPLES) {
      fprintf(stderr, "too many samples\n");
      exit(1);
    }

    s[n].t = atoi(trim(cols[0]));
    s[n].flows = atof(trim(cols[1]));
    s[n].fwd_pkts = atof(trim(cols[2]));
    s[n].bwd_pkts = atof(trim(cols[3]));
    s[n].syn_flags = atof(trim(cols[4]));
    s[n].ack_flags = atof(trim(cols[5]));
    s[n].oneway_flows = atof(trim(cols[6]));
    s[n].label = atoi(trim(cols[7])) != 0;
    n++;
  }

  fclose(f);
  return n;
}

static void compute_raw_features(sample_t *s, int n) {
  for (int i = 0; i < n; i++) {
    s[i].one_way_ratio = s[i].flows > 0.0 ? s[i].oneway_flows / s[i].flows : 0.0;
    s[i].fb_ratio = (s[i].fwd_pkts + 1.0) / (s[i].bwd_pkts + 1.0);

    /*
     * volume_score_raw is a basic flows/sec detector.
     *
     * asym_score_raw is a handshake-pressure proxy:
     * - more flows/sec increases pressure;
     * - high forward/backward packet ratio means weak response symmetry;
     * - one-way flows increase the score.
     */
    s[i].volume_score_raw = s[i].flows;
    s[i].asym_score_raw =
      s[i].flows *
      log1p(s[i].fb_ratio) *
      (1.0 + s[i].one_way_ratio);
  }
}

static int collect_benign(sample_t *s, int n, double *volume, double *asym) {
  int count = 0;
  for (int i = 0; i < n; i++) {
    if (s[i].label) {
      continue;
    }
    if (s[i].flows <= 0.0) {
      continue;
    }
    volume[count] = s[i].volume_score_raw;
    asym[count] = s[i].asym_score_raw;
    count++;
  }
  return count;
}

static metrics_t event_metrics(sample_t *s, int n, int use_asym) {
  metrics_t m = {0, 0, 0, 0};
  unsigned char *covered = (unsigned char *)calloc(n, sizeof(unsigned char));
  if (!covered) {
    perror("calloc");
    exit(1);
  }

  int i = 0;
  while (i < n) {
    if (!s[i].label) {
      i++;
      continue;
    }

    int start = i;
    int end = i;
    int last_attack = i;
    i++;

    while (i < n) {
      if (s[i].label) {
        last_attack = i;
        end = i;
        i++;
        continue;
      }
      if (i - last_attack <= EVENT_MERGE_GAP) {
        end = i;
        i++;
        continue;
      }
      break;
    }

    int grace_end = end + EVENT_GRACE;
    if (grace_end >= n) {
      grace_end = n - 1;
    }

    int detected = 0;
    for (int j = start; j <= grace_end; j++) {
      covered[j] = 1;
      int alert = use_asym ? s[j].asym_alert : s[j].volume_alert;
      if (alert) {
        detected = 1;
      }
    }

    m.events++;
    if (detected) {
      m.tp++;
    } else {
      m.fn++;
    }
  }

  for (i = 0; i < n; i++) {
    int alert = use_asym ? s[i].asym_alert : s[i].volume_alert;
    if (alert && !covered[i]) {
      m.fp++;
    }
  }

  free(covered);
  return m;
}

static void write_results(const char *path, sample_t *s, int n) {
  FILE *f = fopen(path, "w");
  if (!f) {
    fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
    exit(1);
  }

  fprintf(f, "t,flows,fwd_pkts,bwd_pkts,syn_flags,ack_flags,oneway_flows,label,one_way_ratio,fb_ratio,volume_raw,asym_raw,volume_z,asym_z,volume_alert,asym_alert\n");
  for (int i = 0; i < n; i++) {
    fprintf(f, "%d,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%d,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%d,%d\n",
      s[i].t,
      s[i].flows,
      s[i].fwd_pkts,
      s[i].bwd_pkts,
      s[i].syn_flags,
      s[i].ack_flags,
      s[i].oneway_flows,
      s[i].label,
      s[i].one_way_ratio,
      s[i].fb_ratio,
      s[i].volume_score_raw,
      s[i].asym_score_raw,
      s[i].volume_z,
      s[i].asym_z,
      s[i].volume_alert,
      s[i].asym_alert);
  }

  fclose(f);
}

int main(int argc, char **argv) {
  const char *input = "syn_handshake_timeseries.csv";
  const char *output = "syn_asym_results.csv";
  double volume_threshold = 8.0;
  double asym_threshold = 8.0;

  if (argc > 1) {
    input = argv[1];
  }
  if (argc > 2) {
    output = argv[2];
  }
  if (argc > 3) {
    volume_threshold = atof(argv[3]);
  }
  if (argc > 4) {
    asym_threshold = atof(argv[4]);
  }

  sample_t *samples = (sample_t *)calloc(MAX_SAMPLES, sizeof(sample_t));
  if (!samples) {
    perror("calloc");
    return 1;
  }

  int n = read_series(input, samples);
  if (n < 32) {
    fprintf(stderr, "need at least 32 samples\n");
    free(samples);
    return 1;
  }

  compute_raw_features(samples, n);

  double *benign_volume = (double *)malloc(sizeof(double) * n);
  double *benign_asym = (double *)malloc(sizeof(double) * n);
  if (!benign_volume || !benign_asym) {
    perror("malloc");
    free(samples);
    return 1;
  }

  int benign_n = collect_benign(samples, n, benign_volume, benign_asym);
  if (benign_n < 16) {
    fprintf(stderr, "not enough benign samples\n");
    free(benign_volume);
    free(benign_asym);
    free(samples);
    return 1;
  }

  double volume_med = median(benign_volume, benign_n);
  double volume_sigma = 1.4826 * mad(benign_volume, benign_n, volume_med);
  double asym_med = median(benign_asym, benign_n);
  double asym_sigma = 1.4826 * mad(benign_asym, benign_n, asym_med);

  for (int i = 0; i < n; i++) {
    samples[i].volume_z = (samples[i].volume_score_raw - volume_med) / volume_sigma;
    samples[i].asym_z = (samples[i].asym_score_raw - asym_med) / asym_sigma;
    samples[i].volume_alert = samples[i].volume_z > volume_threshold;
    samples[i].asym_alert = samples[i].asym_z > asym_threshold;
  }

  metrics_t volume_m = event_metrics(samples, n, 0);
  metrics_t asym_m = event_metrics(samples, n, 1);

  printf("input: %s\n", input);
  printf("samples: %d\n", n);
  printf("benign samples for baseline: %d\n", benign_n);
  printf("volume median: %.8f robust sigma: %.8f threshold z: %.2f\n",
    volume_med, volume_sigma, volume_threshold);
  printf("asym median: %.8f robust sigma: %.8f threshold z: %.2f\n\n",
    asym_med, asym_sigma, asym_threshold);

  printf("event-level volume detector:             TP=%d FP=%d FN=%d events=%d\n",
    volume_m.tp, volume_m.fp, volume_m.fn, volume_m.events);
  printf("event-level handshake asymmetry detector: TP=%d FP=%d FN=%d events=%d\n",
    asym_m.tp, asym_m.fp, asym_m.fn, asym_m.events);

  write_results(output, samples, n);
  printf("\nwrote %s\n", output);

  free(benign_volume);
  free(benign_asym);
  free(samples);
  return 0;
}
```

### demo

First of all, compile the C detector:     

```bash
gcc -O2 -Wall -Wextra hack.c -lm -o hack
```

![ddos](/assets/images/213/2026-07-01_11-53.png){:class="img-responsive"}     

Run with equal robust z-score thresholds for both detectors:

```bash
./hack syn_handshake_timeseries.csv syn_asym_results.csv 8 8
```

![ddos](/assets/images/213/2026-07-01_11-54.png){:class="img-responsive"}     

In my case:

```bash
input: syn_handshake_timeseries.csv
samples: 21614
benign samples for baseline: 2787
volume median: 4.00000000 robust sigma: 4.44780000 threshold z: 8.00
asym median: 4.15888308 robust sigma: 4.96367492 threshold z: 8.00

event-level volume detector:             TP=8 FP=0 FN=4 events=12
event-level handshake asymmetry detector: TP=11 FP=0 FN=1 events=12

wrote syn_asym_results.csv
```

The important result:     

```bash
volume detector:              TP=8  FP=0 FN=4
handshake asymmetry detector: TP=11 FP=0 FN=1
```

At the same threshold \(z=8\), both detectors have zero false positives at campaign level. But handshake asymmetry detects more SYN campaigns.     

### campaign-level events

Raw `CICDDoS2019` labels are per second after aggregation. Attack labels can be intermittent. For DDoS detection, it is usually more useful to evaluate incident/campaign detection, not every individual second.     

So I merge attack-labeled seconds into one campaign when the gap between them is at most:    

```bash
60 seconds
```

This is the campaign event definition:    

$$
event_i = \{t_s,\ldots,t_e\}
$$

where consecutive attack-labeled seconds separated by:    

$$
\Delta t \le 60
$$

belong to the same campaign.    

A campaign is detected if at least one alert happens inside the campaign or within a small grace window:    

$$
t \in [t_s, t_e + 3]
$$

This avoids punishing a detector for alerting on the immediate boundary of the same attack.    

### plots

Then, generate the main plot:        

```bash
python3 plot_syn_asym.py
```

Result:    

![syn-asym](/assets/images/213/2026-07-01_11-56.png){:class="img-responsive"}    

![syn-asym](/assets/images/213/syn_asym_detection.png){:class="img-responsive"}    

The plot contains:     

1. real TCP flows/sec from `Syn.csv`;
2. zoom into a SYN campaign;
3. forward/backward asymmetry components;
4. robust z-scores;
5. campaign-level TP/FP/FN comparison.

Then generate threshold scan:    

```bash
python3 plot_threshold_scan.py
```

Result:

![syn-threshold-scan](/assets/images/213/2026-07-01_12-00.png){:class="img-responsive"}    

![syn-threshold-scan](/assets/images/213/syn_threshold_scan.png){:class="img-responsive"}    

This plot is important because it shows the result is not only one lucky threshold. Across a wide threshold range, handshake asymmetry keeps more true positives than volume-only detection while false positives stay zero at campaign level in this experiment.     

### proof that this works

Mathematical proof:    

Volume-only detection uses:    

$$
V_t=flows_t
$$

It ignores whether those flows are balanced by response traffic.     

Handshake asymmetry uses:    

$$
A_t =
flows_t \cdot \log(1 + R_t) \cdot (1 + O_t)
$$

with:     

$$
R_t = \frac{F_t + 1}{B_t + 1}
$$

and:    

$$
O_t = \frac{W_t}{flows_t}
$$

If traffic volume is high and response side is weak:       

$$
flows_t \uparrow,\quad R_t \uparrow,\quad O_t \uparrow
$$

then:     

$$
A_t \gg V_t
$$

relative to benign baseline.    

If traffic volume rises but forward/backward behavior remains balanced:    

$$
R_t \approx 1,\quad O_t \approx 0
$$

then asymmetry does not grow as aggressively.     

That is exactly the cybersecurity idea:     

*not just "many flows"*    
*but "many connection attempts with abnormal response symmetry"*     

Practical proof on real CICDDoS2019 `Syn.csv`:     

```bash
volume detector:              TP=8  FP=0 FN=4
handshake asymmetry detector: TP=11 FP=0 FN=1
```

So:      

$$
TP_{asym}-TP_{volume}=11-8=3
$$

$$
FN_{volume}-FN_{asym}=4-1=3
$$

$$
FP_{volume}=FP_{asym}=0
$$

At the same threshold \(z=8\), handshake asymmetry detects 3 more campaigns without increasing false positives.     

Threshold scan proof:      

At multiple thresholds, handshake asymmetry remains stronger. For example:       

```bash
z=5:  volume TP=10 FN=2, asymmetry TP=11 FN=1
z=8:  volume TP=8  FN=4, asymmetry TP=11 FN=1
z=20: volume TP=4  FN=8, asymmetry TP=11 FN=1
```

This is useful because a detector that only works at one threshold is fragile. A detector that dominates across a range is more reliable.       

### limitations

This is not perfect TCP state tracking.          

CICFlowMeter gives flow features, not raw kernel connection state. So:     

- `Total Fwd Packets` and `Total Backward Packets` are proxy values;
- `SYN Flag Count` may not fully represent all SYN packets after flow aggregation;
- labels are dataset labels, not real-time ground truth;
- campaign merge gap changes event-level metrics.

For production-grade SYN flood detection, I would add:        

- SYN packets/sec;
- SYN-ACK packets/sec;
- final ACK packets/sec;
- half-open connection table pressure;
- SYN cookie counters;
- conntrack drops;
- listen queue overflows;
- server p99 latency.

The better score would be:      

$$
S_t =
w_1Z_{flows}+
w_2Z_{syn/synack}+
w_3Z_{halfopen}+
w_4Z_{queue\_drops}+
w_5Z_{handshake\_asym}
$$

But this post intentionally stays with fields available in `CICDDoS2019` CSV and a simple C implementation.      

### conclusion

The main lesson:      

*SYN flood detection should not be only volume-based. It should measure handshake asymmetry.*

On real CICDDoS2019 `Syn.csv`, the simple asymmetry score:      

$$
A_t =
flows_t \cdot \log(1 + R_t) \cdot (1 + O_t)
$$

outperformed a plain flow-volume detector at campaign level:

```bash
volume:     TP=8  FP=0 FN=4
asymmetry:  TP=11 FP=0 FN=1
```

This is a practical defensive building block for Anti-DDoS research.       

[DDoS2019 Dataset: Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ddos-2019.html)     
[CICDoS2019 Dataset: Telegram channel](https://t.me/maldevcc/224)    
[source code in github](https://github.com/cocomelonc/meow/tree/master/2026-07-01-ddos-syn-flood-detection-1)        

> This is a practical defensive case for educational purposes only.

Thanks for your time happy hacking and good bye!    
*PS. All drawings and screenshots are mine*   


