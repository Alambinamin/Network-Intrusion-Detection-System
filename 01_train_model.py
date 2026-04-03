import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import pickle
import os

print("--- Step 1: Loading Dataset ---")
cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
        'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate', 'label', 'difficulty_level']

if not os.path.exists('KDDTrain+.txt'):
    print("ERROR: KDDTrain+.txt not found! Please download it.")
    exit()

df = pd.read_csv('KDDTrain+.txt', names=cols)
print(f"Loaded {len(df)} rows.")


df['binary_label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)


print("--- Step 2: Encoding Data ---")
le_proto = LabelEncoder()
le_service = LabelEncoder()
le_flag = LabelEncoder()

df['protocol_type'] = le_proto.fit_transform(df['protocol_type'])
df['service'] = le_service.fit_transform(df['service'])
df['flag'] = le_flag.fit_transform(df['flag'])


with open('encoders.pkl', 'wb') as f:
    pickle.dump((le_proto, le_service, le_flag), f)


X = df.drop(['label', 'difficulty_level', 'binary_label'], axis=1)
y = df['binary_label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("--- Step 3: Training Model ---")
clf = RandomForestClassifier(n_estimators=20, random_state=42)
clf.fit(X_train, y_train)

print(f"Model Accuracy: {clf.score(X_test, y_test)*100:.2f}%")

with open('nids_model.pkl', 'wb') as f:
    pickle.dump(clf, f)
print("SUCCESS: Model saved as 'nids_model.pkl'")
