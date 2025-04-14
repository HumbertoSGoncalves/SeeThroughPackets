import pyshark
import pandas as pd
import numpy as np
import os
import json
import matplotlib.pyplot as plt
from datetime import datetime
from joblib import dump, load
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

class PacketWorx:
    def __init__(self, pcap_file=None, interface=None, packet_limit=20000):
        self.pcap_file = pcap_file
        self.interface = interface
        self.packet_limit = packet_limit

        self.model_file = 'packet_classifier.joblib'
        self.anomaly_model_file = 'anomaly_detector.joblib'
        self.attack_model_file = 'attack_classifier.joblib'
        self.label_map_file = 'attack_label_map.json'
        self.attack_model_binary_file = 'attack_classifier_binary.joblib'

        self.features_raw = [
            'length', 'source_port', 'destination_port', 'time_of_day',
            'protocol_number', 'packet_size_variance', 'source_bytes', 'destination_bytes'
        ]

        self.features_cic = [
            'length', 'source_port', 'destination port', 'time_of_day',
            'protocol_number', 'packet length variance', 'source_bytes', 'destination_bytes'
        ]

        self.model = self.load_model(self.model_file)
        self.anomaly_model = self.load_model(self.anomaly_model_file)
        self.attack_model = self.load_model(self.attack_model_file)
        self.label_mapping = self.load_label_mapping()
        self.attack_model_binary = self.load_model(self.attack_model_binary_file)

    def load_model(self, path):
        return load(path) if os.path.exists(path) else None

    def load_label_mapping(self):
        if os.path.exists(self.label_map_file):
            with open(self.label_map_file, 'r') as f:
                return json.load(f)
        return {}

    def get_protocol_number(self, protocol):
        return {'TCP': 6, 'UDP': 17}.get(protocol, 0)

    def read_pcap(self):
        if self.pcap_file:
            capture = pyshark.FileCapture(self.pcap_file)
        elif self.interface:
            capture = pyshark.LiveCapture(interface=self.interface)
            capture.sniff(packet_count=300)
        else:
            raise ValueError("No pcap file or interface provided.")

        packets, source_bytes, destination_bytes = [], {}, {}

        for i, packet in enumerate(capture):
            if i >= self.packet_limit:
                break
            try:
                length = int(packet.length)
                src_ip, dst_ip = packet.ip.src, packet.ip.dst
                source_bytes[src_ip] = source_bytes.get(src_ip, 0) + length
                destination_bytes[dst_ip] = destination_bytes.get(dst_ip, 0) + length

                pkt_info = {
                    'packet_number': packet.number,
                    'timestamp': packet.sniff_time,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'protocol': packet.transport_layer,
                    'length': length,
                    'time_of_day': packet.sniff_time.hour * 3600 + packet.sniff_time.minute * 60 + packet.sniff_time.second,
                    'protocol_number': self.get_protocol_number(packet.transport_layer),
                    'source_bytes': source_bytes[src_ip],
                    'destination_bytes': destination_bytes[dst_ip],
                }

                if hasattr(packet, 'tcp'):
                    pkt_info['source_port'] = int(packet.tcp.srcport)
                    pkt_info['destination_port'] = int(packet.tcp.dstport)
                    pkt_info['init_win_bytes_forward'] = int(getattr(packet.tcp, 'window_size_value', 0))
                    pkt_info['min_seg_size_forward'] = int(getattr(packet.tcp, 'options_mss_val', 0))
                elif hasattr(packet, 'udp'):
                    pkt_info['source_port'] = int(packet.udp.srcport)
                    pkt_info['destination_port'] = int(packet.udp.dstport)
                    pkt_info['init_win_bytes_forward'] = 0
                    pkt_info['min_seg_size_forward'] = 0
                else:
                    pkt_info['source_port'] = 0
                    pkt_info['destination_port'] = 0
                    pkt_info['init_win_bytes_forward'] = 0
                    pkt_info['min_seg_size_forward'] = 0

                pkt_info['fwd packet length mean'] = length if packet.ip.src == src_ip else 0
                pkt_info['fwd packet length max'] = length if packet.ip.src == src_ip else 0
                pkt_info['bwd packet length max'] = length if packet.ip.dst == src_ip else 0
                pkt_info['init_win_bytes_backward'] = int(getattr(getattr(packet, 'tcp', None), 'window_size_value', 0)) if packet.ip.dst == src_ip else 0

                packets.append(pkt_info)
            except AttributeError:
                pass

        df = pd.DataFrame(packets)
        self.total_packets_analyzed = len(packets)
        df['packet_size_variance'] = df['length'].rolling(window=10).var().fillna(0)

        self.df_for_attack = df.rename(columns={
            'destination_port': 'destination port',
            'packet_size_variance': 'packet length variance',
            'init_win_bytes_forward': 'init_win_bytes_forward',
            'init_win_bytes_backward': 'init_win_bytes_backward',
            'min_seg_size_forward': 'min_seg_size_forward',
            'fwd packet length mean': 'fwd packet length mean',
            'fwd packet length max': 'fwd packet length max',
            'bwd packet length max': 'bwd packet length max'
        })

        return df

    def train_model(self, df):
        X = df[self.features_raw].fillna(0)
        y = df['protocol'].apply(lambda x: 1 if x == 'TCP' else 0)
        model = GradientBoostingClassifier().fit(X, y)
        dump(model, self.model_file)

    def train_anomaly_model(self, df):
        X = df[self.features_raw].fillna(0)
        scaler = StandardScaler().fit(X)
        X_scaled = scaler.transform(X)
        pca = PCA(n_components=0.95).fit(X_scaled)
        X_reduced = pca.transform(X_scaled)
        model = IsolationForest(contamination=0.01).fit(X_reduced)
        dump((scaler, pca, model), self.anomaly_model_file)

    def train_multiclass_attack_model_from_csv(self, csv_path="CICIDS2017_rfe_selected.csv"):
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.metrics import classification_report
        from joblib import dump
        import json

        print(f"📥 Loading dataset from {csv_path}...")

        # 1. Load and clean
        df = pd.read_csv(csv_path)
        packetworx_features = [
            'packet length variance',
            'destination port',
            'init_win_bytes_forward',
            'init_win_bytes_backward',
            'min_seg_size_forward',
            'fwd packet length mean',
            'fwd packet length max',
            'bwd packet length max'
        ]
        df = df[packetworx_features + ['label_multiclass', 'label']]
        df.dropna(inplace=True)

        # 2. Undersample BENIGN
        benign = df[df['label_multiclass'] == 0]
        attacks = df[df['label_multiclass'] != 0]
        benign_sampled = benign.sample(n=len(attacks), random_state=42)
        balanced_df = pd.concat([benign_sampled, attacks]).sample(frac=1, random_state=42)

        # 3. Split
        X = balanced_df[packetworx_features]
        y = balanced_df['label_multiclass']
        X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)

        # 4. Train and evaluate
        model = GradientBoostingClassifier()
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        print("\n📊 Multiclass Classifier Evaluation:\n")
        print(classification_report(y_test, y_pred))

        # 5. Save model and label map
        dump(model, self.attack_model_file)
        label_mapping = balanced_df[['label_multiclass', 'label']].drop_duplicates().set_index('label_multiclass')['label'].to_dict()
        with open(self.label_map_file, 'w') as f:
            json.dump(label_mapping, f)

        print("✅ Multiclass attack model and label map saved!")

    def train_binary_attack_model(self, df):
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.utils import resample
        from joblib import dump

        # 1️⃣ Create binary label: 1 = Attack, 0 = Benign
        df['binary_label'] = df['attack_type'].apply(lambda x: 0 if x == 'BENIGN' else 1)

        # 2️⃣ Undersample the majority class
        df_majority = df[df['binary_label'] == 0]
        df_minority = df[df['binary_label'] == 1]

        df_majority_downsampled = resample(
            df_majority,
            replace=False,
            n_samples=len(df_minority),
            random_state=42
        )

        df_balanced = pd.concat([df_majority_downsampled, df_minority])

        # 3️⃣ Define features from the renamed attack dataframe
        features = [
            'packet_length_variance',
            'destination_port',
            'init_win_bytes_forward',
            'init_win_bytes_backward',
            'min_seg_size_forward',
            'fwd packet length mean',
            'fwd packet length max',
            'bwd packet length max'
        ]

        X = self.df_for_attack.loc[df_balanced.index, features].fillna(0)
        y = df_balanced['binary_label']

        # 4️⃣ Train and save the model
        model = GradientBoostingClassifier()
        model.fit(X, y)
        dump(model, 'binary_attack_classifier.joblib')
        print("✅ Binary attack classifier saved as 'binary_attack_classifier.joblib'")

    def classify_packets(self, df):
        if not self.model:
            df['classification'] = np.nan
            return df
        X = df[self.features_raw].fillna(0)
        df['classification'] = self.model.predict(X)
        return df

    def detect_anomalies(self, df):
        if not self.anomaly_model:
            df['anomaly_score'], df['anomaly'] = np.nan, np.nan
            return df
        scaler, pca, model = self.anomaly_model
        X = df[self.features_raw].fillna(0)
        X_scaled = scaler.transform(X)
        X_reduced = pca.transform(X_scaled)
        df['anomaly_score'] = model.decision_function(X_reduced)
        df['anomaly'] = model.predict(X_reduced)
        return df

    def detect_attack_type(self, df):
        if not self.attack_model:
            df['attack_prediction'], df['attack_type'] = np.nan, 'No model'
            return df
        try:
            # Use CIC-style renamed dataframe and corresponding features
            cic_features = [
                'packet length variance',
                'destination port',
                'init_win_bytes_forward',
                'init_win_bytes_backward',
                'min_seg_size_forward',
                'fwd packet length mean',
                'fwd packet length max',
                'bwd packet length max'
            ]
            X = self.df_for_attack[cic_features].fillna(0)
            df['attack_prediction'] = self.attack_model.predict(X)
            df['attack_type'] = df['attack_prediction'].astype(str).map(self.label_mapping).fillna("Unknown")
        except Exception as e:
            print("⚠️ Attack detection error:", e)
            df['attack_prediction'], df['attack_type'] = np.nan, 'Error'
        return df

    def run(self):
        df = self.read_pcap()

        if not self.model:
            self.train_model(df)
            self.model = self.load_model(self.model_file)
        if not self.anomaly_model:
            self.train_anomaly_model(df)
            self.anomaly_model = self.load_model(self.anomaly_model_file)

        df = self.classify_packets(df)
        df = self.detect_anomalies(df)
        df = self.detect_attack_type(df)
        
        print(df)
        print("\n📊 Attack Type Summary:\n")
        print(df['attack_type'].value_counts())  # Summary of attack types
        # 🔍 Show packet numbers of non-BENIGN attacks
        non_benign_packets = df[df['attack_type'] != 'BENIGN']
        if not non_benign_packets.empty:
            print("\n🧨 Packets with attack types other than BENIGN:")
            print(non_benign_packets[['packet_number', 'attack_type']].to_string(index=False))
        else:
            print("\n✅ No malicious packets detected (all BENIGN).")

    def suggest_filter(self):
        print("Suggested filter: tcp or udp")

    def highlight_suspicious_packets(self):
        df = self.classify_packets(self.read_pcap())
        print("Suspicious packets:\n", df[df['classification'] == 1])

    def highlight_anomalous_packets(self):
        df = self.read_pcap()
        df = self.detect_anomalies(df)
        df = self.detect_attack_type(df)
        anomalous_packets = df[df['anomaly'] == -1]
        print("Anomalous packets:\n", anomalous_packets)

    def visualize_anomalies(self):
        df = self.read_pcap()
        df = self.detect_anomalies(df)
        df = self.detect_attack_type(df)

        print("Attack model loaded:", bool(self.attack_model))
        print("Label mapping loaded:", bool(self.label_mapping))
        print("attack_type column present:", 'attack_type' in df.columns)

        # Sort by time
        df = df.sort_values(by='timestamp')
        df.set_index('timestamp', inplace=True)

        # Plot anomaly score
        plt.figure(figsize=(14, 6))
        plt.plot(df.index, df['anomaly_score'], label='Anomaly Score', color='blue', alpha=0.6)

        # Highlight anomalies
        anomalies = df[df['anomaly'] == -1]
        plt.scatter(anomalies.index, anomalies['anomaly_score'], color='red', label='Anomalies', zorder=3)

        plt.title("Anomaly Time Series")
        plt.xlabel("Time")
        plt.ylabel("Anomaly Score")
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.show()

        # Breakdown
        if 'attack_type' in df.columns:
            print("\n📊 Anomaly attack type breakdown:")
            print(df[df['anomaly'] == -1]['attack_type'].value_counts())
        else:
            print("⚠️ 'attack_type' column missing in DataFrame.")

    def show_summary(self):
        df = self.read_pcap()
        df = self.classify_packets(df)
        df = self.detect_anomalies(df)
        df = self.detect_attack_type(df)

        print("\n\U0001F4CA PacketWorx Summary")
        print("=" * 40)

        # Count anomalies
        anomaly_count = df[df['anomaly'] == -1].shape[0]
        print(f"\U0001F539 Anomalies detected: {anomaly_count}")

        # Attack type distribution
        if 'attack_type' in df.columns:
            print("\n🧠 Top 3 Attack Types:")
            attack_counts = df['attack_type'].value_counts()
            # Exclude BENIGN and get top 3
            top_attacks = attack_counts.drop('BENIGN', errors='ignore').head(3)
            for attack, count in top_attacks.items():
                print(f"   - {attack}: {count}")

            print("\n🚨 Anomaly Breakdown by Attack Type:")
            anomaly_attacks = df[df['anomaly'] == -1]['attack_type'].value_counts()
            # Exclude BENIGN
            anomaly_attacks = anomaly_attacks.drop('BENIGN', errors='ignore')
            for attack, count in anomaly_attacks.items():
                print(f"   - {attack}: {count}")

            # Print all BENIGNs separately
            benign_count = df[df['attack_type'] == 'BENIGN'].shape[0]
            print(f"\n✅ BENIGN packets: {benign_count}")

        # Time range of anomalies
        if 'timestamp' in df.columns and not df[df['anomaly'] == -1].empty:
            time_range = df[df['anomaly'] == -1]['timestamp']
            print("\n\U0001F552 Time Range of Anomalies:")
            print(f"   From: {time_range.min()}\n   To  : {time_range.max()}")

    def explain_attack_classification_with_shap(self):
        import shap
        import matplotlib.pyplot as plt

        if not self.attack_model_binary:
            print("❌ No binary attack model loaded.")
            return

        df = self.read_pcap()
        df = self.detect_attack_type(df)  # still helpful for creating binary label

        # Create binary label column
        df['binary_label'] = df['attack_type'].apply(lambda x: 0 if x == 'BENIGN' else 1)

        features = [
            'packet length variance',
            'destination port',
            'init_win_bytes_forward',
            'init_win_bytes_backward',
            'min_seg_size_forward',
            'fwd packet length mean',
            'fwd packet length max',
            'bwd packet length max'
        ]
        X = self.df_for_attack[features].fillna(0)

        print("\n🌐 Generating SHAP global explanation for binary classifier...")

        explainer = shap.TreeExplainer(self.attack_model_binary)
        shap_values = explainer.shap_values(X)

        # 🧠 Handle binary vs multiclass SHAP output automatically
        if isinstance(shap_values, list) and len(shap_values) == 2:
            shap.summary_plot(shap_values[1], features=X, feature_names=features)
        else:
            shap.summary_plot(shap_values, features=X, feature_names=features)

    def explain_anomaly_with_lime(self):
        from lime.lime_tabular import LimeTabularExplainer
        import numpy as np
        import matplotlib.pyplot as plt
        from sklearn.preprocessing import MinMaxScaler

        if not self.anomaly_model:
            print("❌ No anomaly model loaded.")
            return

        df = self.read_pcap()
        df = self.detect_anomalies(df)

        X = df[self.features_raw].fillna(0).values
        scaler, pca, model = self.anomaly_model
        X_scaled = scaler.transform(X)
        X_reduced = pca.transform(X_scaled)

        # Normalize PCA output for LIME and add slight noise
        normalizer = MinMaxScaler()
        X_norm = normalizer.fit_transform(X_reduced)

        try:
            num_samples = int(input("\n🔍 How many samples do you want to explain with LIME? "))
        except ValueError:
            print("Invalid input. Defaulting to 5 samples.")
            num_samples = 5

        def soft_predict_fn(X_perturbed_norm):
            X_perturbed = normalizer.inverse_transform(X_perturbed_norm)
            scores = model.decision_function(X_perturbed)

            # 🚨 Add tiny noise to avoid flat predictions
            scores += np.random.normal(0, 1e-4, size=scores.shape)

            # Normalize decision_function to [0, 1]
            probs = (scores - scores.min()) / (scores.max() - scores.min() + 1e-6)
            return np.vstack([1 - probs, probs]).T

        explainer = LimeTabularExplainer(
            training_data=X_norm,
            feature_names=[f'PC{i+1}' for i in range(X_norm.shape[1])],
            class_names=['Normal', 'Anomaly'],
            mode='classification',
            discretize_continuous=True
        )

        print(f"\n🧠 Showing LIME explanations for {num_samples} samples:")
        for i in range(min(num_samples, len(X_norm))):
            exp = explainer.explain_instance(X_norm[i], soft_predict_fn, num_features=5)
            fig = exp.as_pyplot_figure()
            plt.title(f"LIME Explanation for Sample #{i} (Class: Anomaly)")
            plt.tight_layout()
            plt.show()

            # Decode PCs into original features
            for pc_num in range(5):  # Top 5 PCs
                print(f"\n📊 Top original features contributing to PC{pc_num + 1}:")
                top_features = np.argsort(np.abs(pca.components_[pc_num]))[::-1][:3]
                for j in top_features:
                    weight = pca.components_[pc_num][j]
                    print(f"   - {self.features_raw[j]} (weight: {weight:.3f})")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PacketWorx: An AI assistant for Wireshark.")
    parser.add_argument('--pcap', type=str, help="Path to the pcap file.")
    parser.add_argument('--interface', type=str, help="Network interface for live capture.")
    parser.add_argument('--filter', action='store_true', help="Suggest a filter for Wireshark.")
    parser.add_argument('--highlight', action='store_true', help="Highlight suspicious packets.")
    parser.add_argument('--anomalies', action='store_true', help="Highlight anomalous packets.")
    parser.add_argument('--timeseries', action='store_true', help="Show anomaly time series visualization.")
    parser.add_argument('--summary', action='store_true', help="Show interactive summary of analysis.")
    parser.add_argument('--explain-shap', action='store_true', help="Explain binary attack model globally using SHAP.")
    parser.add_argument('--explain-lime', action='store_true', help="Explain anomaly detection using LIME.")

    args = parser.parse_args()

    try:
        limit = int(input("🔢 Enter the number of packets to analyze: "))
    except ValueError:
        print("Invalid input. Using default of 20000 packets.")
        limit = 50000

    pw = PacketWorx(pcap_file=args.pcap, interface=args.interface, packet_limit=limit)

    if args.filter:
        pw.suggest_filter()
    elif args.highlight:
        pw.highlight_suspicious_packets()
    elif args.anomalies:
        pw.highlight_anomalous_packets()
    elif args.timeseries:
        pw.visualize_anomalies()
    elif args.summary:
        pw.show_summary()
    elif args.explain_shap:
        pw.explain_attack_classification_with_shap()
    elif args.explain_lime:
        pw.explain_anomaly_with_lime()
    else:
        pw.run()
