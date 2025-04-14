# SeeThroughPackets
Enhanced PacketWorx with Explainable AI (SHAP &amp; LIME) for interpretable intrusion detection. Uses CIC-IDS2017-based ML models to classify and explain packet-level threats. Built for cybersecurity analysts and product managers seeking transparency in detection logic.

# MyPacketWorx

PacketWorx is a Python-based AI assistant for Wireshark, tailored for packet-level threat analysis using machine learning and explainable AI techniques. Originally inspired by [PacketWorx](https://github.com/FreeSoftWorks/PacketWorx), this enhanced version integrates multiple ML classifiers, global and local explainability using SHAP and LIME, and interactive summaries to support product managers and security engineers in understanding, auditing, and showcasing packet-level intrusion detection.

## Features

- ✅ PCAP and live packet capture analysis using `pyshark`
- 📊 Anomaly detection via Isolation Forest
- 🔍 Attack type prediction with a multiclass Gradient Boosting classifier
- 🧠 Global explainability using SHAP (binary model)
- 💡 Local explainability using LIME (PCA-reduced anomaly detection)
- 📈 Time-series anomaly visualizations and interactive summaries
- ⚠️ Packet highlighting for anomalies and suspicious patterns
- 🛠 CLI support to toggle each mode of analysis

---

## Installation

First, ensure Python 3.9+ is installed and create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Additional setup:
- Make sure `tshark` is installed and accessible to `pyshark`
- Models (`attack_classifier.joblib`, `attack_classifier_binary.joblib`, `anomaly_detector.joblib`) will be trained as needed or loaded from disk if available

---

## Usage

Use the script via CLI:

```bash
python myPacketWorx.py [--pcap FILE] [--interface IFACE] [--option]
```

### Examples:

1. **Analyze a PCAP file**:

```bash
python myPacketWorx.py --pcap Monday-WorkingHours.pcap
```

2. **Run live packet capture**:

```bash
python myPacketWorx.py --interface en0
```

3. **Suggest a Wireshark filter**:

```bash
python myPacketWorx.py --filter
```

4. **Highlight suspicious packets**:

```bash
python myPacketWorx.py --highlight
```

5. **Highlight anomalous packets**:

```bash
python myPacketWorx.py --anomalies
```

6. **Generate time-series of anomalies**:

```bash
python myPacketWorx.py --timeseries
```

7. **Interactive attack/anomaly summary**:

```bash
python myPacketWorx.py --summary
```

8. **SHAP global explanation of attack classifier (binary model)**:

```bash
python myPacketWorx.py --pcap Monday-WorkingHours.pcap --explain-shap
```

9. **LIME local explanation for anomalies explanation**:

```bash
python myPacketWorx.py --pcap Monday-WorkingHours.pcap --explain-lime
```

---

## How It Works

### 1. Preprocessing & Feature Engineering

- Supports both live and file-based packet ingestion
- Extracts features like `protocol_number`, `packet_size_variance`, rolling variance, and port-based metadata
- Maintains running counts of source/destination bytes

### 2. Attack Detection (Multiclass)

- **Dataset**: Trained on the CIC-IDS2017 dataset, with label column `label_multiclass`
- **Preprocessing**: Removed constant, zero-only, and infinite-value features; selected top 20 using Pearson correlation and RFE with Random Forest
- **Model**: Gradient Boosting Classifier
- **Balancing**: Undersampling applied to balance benign and malicious classes
- **Performance**: Achieved ~0.97 accuracy; macro-F1 ~0.63
- **Mapping**: Human-readable attack names mapped using `attack_label_map.json`

### 3. Binary Classifier for SHAP

- Separate Gradient Boosting Classifier trained using same CIC-IDS2017 features, but with binary labels (BENIGN vs ATTACK)
- Same preprocessing and downsampling applied
- Output used for SHAP global explanations

### 4. Anomaly Detection

- Isolation Forest trained on PCA-reduced data from 8 PacketWorx-compatible features
- Anomaly score added per packet
- Visual anomaly time series supported

### 5. Explainable AI

- **SHAP (binary attack classifier)**: Provides global feature importance via summary plots
- **LIME**: Provides per-sample explanations on anomaly predictions using PCA-transformed space

### 6. CLI Modes

| Option                | Description |
|-----------------------|-------------|
| `--filter`            | Suggests protocol-based filter |
| `--highlight`         | Flags suspicious packets via protocol classification |
| `--anomalies`         | Flags Isolation Forest anomalies |
| `--summary`           | Provides an interactive anomaly breakdown |
| `--timeseries`        | Plots anomalies across packet timestamps |
| `--explain-shap`      | Generates SHAP summary for binary classifier |
| `--explain-lime`      | Interactive explanation of PCA-anomaly space via LIME |

---

## Contributing

Improvements or new modes of explanation (e.g., counterfactuals, permutation importance) are welcome. Open a PR or issue on GitHub.

---

## License

MIT License © 2024 – This project builds on the original [PacketWorx repository](https://github.com/FreeSoftWorks/PacketWorx) under the same terms.
