from preprocess import load_data, preprocess
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def train_random_forest(X_train, y_train):
    print("🌲 Training Random Forest... (takes 2–5 mins)")
    rf = RandomForestClassifier(
        n_estimators=100,    # 100 decision trees
        max_depth=20,        # how deep each tree grows
        random_state=42,     # for reproducibility
        n_jobs=-1            # use all CPU cores → faster
    )
    rf.fit(X_train, y_train)
    print("✅ Training complete!")
    return rf

def evaluate(model, X_test, y_test):
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n📊 Test Accuracy: {acc*100:.2f}%")
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred))
    return y_pred

def plot_confusion_matrix(y_test, y_pred):
    labels = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    
    plt.figure(figsize=(8,6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=labels, yticklabels=labels)
    plt.title('Confusion Matrix — AI-IDS')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    plt.savefig('models/confusion_matrix.png', dpi=150)
    plt.show()
    print("📸 Confusion matrix saved to models/confusion_matrix.png")

def plot_feature_importance(model, X_train):
    feature_names = [
        'duration','protocol_type','service','flag','src_bytes','dst_bytes',
        'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
        'num_compromised','root_shell','su_attempted','num_root',
        'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
        'is_host_login','is_guest_login','count','srv_count','serror_rate',
        'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
        'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
        'dst_host_same_srv_rate','dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
        'dst_host_serror_rate','dst_host_srv_serror_rate',
        'dst_host_rerror_rate','dst_host_srv_rerror_rate'
    ]
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:15]  # top 15
    
    plt.figure(figsize=(10,6))
    plt.title('Top 15 Most Important Features')
    plt.bar(range(15), importances[indices])
    plt.xticks(range(15), [feature_names[i] for i in indices], rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('models/feature_importance.png', dpi=150)
    plt.show()
    print("📸 Feature importance chart saved.")

if __name__ == "__main__":
    train, test = load_data('data/KDDTrain+.txt', 'data/KDDTest+.txt')
    X_train, X_test, y_train, y_test = preprocess(train, test)
    
    model = train_random_forest(X_train, y_train)
    y_pred = evaluate(model, X_test, y_test)
    
    # Save the trained model
    joblib.dump(model, 'models/rf_model.pkl')
    print("\n💾 Model saved to models/rf_model.pkl")
    
    plot_confusion_matrix(y_test, y_pred)
    plot_feature_importance(model, X_train)