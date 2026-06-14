import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

def load_data(train_path, test_path):
    cols = ['duration','protocol_type','service','flag','src_bytes',
            'dst_bytes','land','wrong_fragment','urgent','hot',
            'num_failed_logins','logged_in','num_compromised','root_shell',
            'su_attempted','num_root','num_file_creations','num_shells',
            'num_access_files','num_outbound_cmds','is_host_login',
            'is_guest_login','count','srv_count','serror_rate',
            'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
            'diff_srv_rate','srv_diff_host_rate','dst_host_count',
            'dst_host_srv_count','dst_host_same_srv_rate',
            'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate','dst_host_serror_rate',
            'dst_host_srv_serror_rate','dst_host_rerror_rate',
            'dst_host_srv_rerror_rate','label','difficulty']
    
    train = pd.read_csv(train_path, names=cols)
    test  = pd.read_csv(test_path,  names=cols)
    return train, test

def map_labels(df):
    # Group 40+ attack names into 5 categories
    dos_attacks   = ['back','land','neptune','pod','smurf','teardrop',
                     'apache2','udpstorm','processtable','worm']
    probe_attacks = ['satan','ipsweep','nmap','portsweep','mscan','saint']
    r2l_attacks   = ['guess_passwd','ftp_write','imap','phf','multihop',
                     'warezmaster','warezclient','spy','xlock','xsnoop',
                     'snmpguess','snmpgetattack','httptunnel','sendmail','named']
    u2r_attacks   = ['buffer_overflow','loadmodule','rootkit','perl',
                     'sqlattack','xterm','ps']
    
    def categorize(label):
        if label == 'normal':   return 'Normal'
        if label in dos_attacks:   return 'DoS'
        if label in probe_attacks: return 'Probe'
        if label in r2l_attacks:   return 'R2L'
        if label in u2r_attacks:   return 'U2R'
        return 'Unknown'
    
    df['attack_category'] = df['label'].apply(categorize)
    return df

def preprocess(train, test):
    train = map_labels(train)
    test  = map_labels(test)
    
    # Drop raw label columns
    train.drop(['label','difficulty'], axis=1, inplace=True)
    test.drop(['label','difficulty'],  axis=1, inplace=True)
    
    # Encode categorical text columns → numbers
    le = LabelEncoder()
    for col in ['protocol_type', 'service', 'flag']:
        train[col] = le.fit_transform(train[col])
        test[col]  = le.transform(test[col])
    
    # Separate features (X) from target label (y)
    X_train = train.drop('attack_category', axis=1)
    y_train = train['attack_category']
    X_test  = test.drop('attack_category', axis=1)
    y_test  = test['attack_category']
    
    # Normalize: scale all numbers to 0–1 range
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)
    
    # Save scaler so we can use it for live predictions later
    os.makedirs('models', exist_ok=True)
    joblib.dump(scaler, 'models/scaler.pkl')
    print(" Preprocessing done!")
    print(f"   Training samples: {X_train.shape[0]}")
    print(f"   Testing samples:  {X_test.shape[0]}")
    return X_train, X_test, y_train, y_test

if __name__ == "__main__":
    train, test = load_data('data/KDDTrain+.txt', 'data/KDDTest+.txt')
    X_train, X_test, y_train, y_test = preprocess(train, test)
    print("Label distribution:", y_train.value_counts().to_dict())
