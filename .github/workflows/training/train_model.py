import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression, LogisticRegressionCV
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import json

df = pd.read_csv('features.csv')
print(f"Dataset: {len(df)} rows ({(df.label=='ai').sum()} AI, {(df.label=='real').sum()} real)\n")

FEATURES = [
    'aspect', 'isSquarePow2', 'megapixels', 'hasCameraExif', 'hasPipelineTag',
    'elaGlobalMean', 'elaGlobalStd', 'elaHotBlockRatio', 'elaMaxBlock',
    'noiseMeanEnergy', 'noiseStdEnergy', 'noiseCoeffVar',
    'freqHighBand', 'freqMidBand', 'freqHighMidRatio', 'freqMaxProminence', 'freqMeanProminence', 'freqOutlierRatio',
    'lsbMaxP', 'lsbHighPWindows'
]
X = df[FEATURES].values.astype(float)
y = (df['label'] == 'ai').astype(int).values
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

scaler = StandardScaler()
Xs = scaler.fit_transform(X)

# L1 (lasso-style) regularization for automatic, robust feature selection: with only 141
# samples and 20 candidate features, we want a SPARSE model (fewer, more reliable features)
# rather than RFECV's ~18/20 "keep almost everything" result from the first attempt.
l1_clf = LogisticRegressionCV(Cs=np.logspace(-2, 1.5, 25), cv=cv, max_iter=5000,
                                penalty='l1', solver='liblinear', class_weight='balanced',
                                scoring='roc_auc')
l1_clf.fit(Xs, y)
nonzero = np.abs(l1_clf.coef_[0]) > 1e-6
selected = [f for f, keep in zip(FEATURES, nonzero) if keep]
print(f"L1 selected {len(selected)}/{len(FEATURES)} features: {selected}\n")

# Refit a plain (unpenalized-ish, light L2) model on just the selected features for cleaner
# final coefficients, evaluated honestly via cross-validation on this same feature subset.
Xsel = df[selected].values.astype(float)
scaler2 = StandardScaler()
Xsel_s = scaler2.fit_transform(Xsel)

final_cv_clf = LogisticRegressionCV(Cs=np.logspace(-2, 2, 20), cv=cv, max_iter=5000,
                                      class_weight='balanced', scoring='roc_auc')
oof_proba = cross_val_predict(final_cv_clf, Xsel_s, y, cv=cv, method='predict_proba')[:, 1]
oof_pred = (oof_proba >= 0.5).astype(int)

print("=== Cross-validated performance on selected features (out-of-fold, 5-fold) ===")
print(classification_report(y, oof_pred, target_names=['real', 'ai']))
print("Confusion matrix [rows=true, cols=pred], order [real, ai]:")
print(confusion_matrix(y, oof_pred))
print(f"ROC-AUC (out-of-fold): {roc_auc_score(y, oof_proba):.3f}\n")

# Final fit on ALL data for deployment
final_clf = LogisticRegressionCV(Cs=np.logspace(-2, 2, 20), cv=cv, max_iter=5000,
                                   class_weight='balanced', scoring='roc_auc')
final_clf.fit(Xsel_s, y)
print(f"Best C: {final_clf.C_[0]:.4f}\n")

print("=== Learned coefficients (standardized space — well-scaled, numerically safe) ===")
for f, c, m, s in sorted(zip(selected, final_clf.coef_[0], scaler2.mean_, scaler2.scale_), key=lambda x: -abs(x[1])):
    print(f"  {f:20s} coef={c:+.4f}  (feature mean={m:.5g}, std={s:.5g})")
print(f"  {'intercept':20s} {final_clf.intercept_[0]:+.4f}\n")

# Sanity check the exported form reproduces sklearn's predictions exactly
def score_raw(row):
    z = final_clf.intercept_[0]
    for f, c, m, s in zip(selected, final_clf.coef_[0], scaler2.mean_, scaler2.scale_):
        z += ((row[f] - m) / s) * c
    return 1 / (1 + np.exp(-z))

df['_check'] = df.apply(score_raw, axis=1)
direct = final_clf.predict_proba(Xsel_s)[:, 1]
max_diff = np.max(np.abs(df['_check'].values - direct))
print(f"Sanity check — max diff (manual formula vs sklearn): {max_diff:.2e} (should be ~0)\n")

model_export = {
    'features': selected,
    'params': [
        {'feature': f, 'mean': float(m), 'std': float(s), 'coef': float(c)}
        for f, c, m, s in zip(selected, final_clf.coef_[0], scaler2.mean_, scaler2.scale_)
    ],
    'intercept': float(final_clf.intercept_[0]),
    'cv_roc_auc': float(roc_auc_score(y, oof_proba)),
    'cv_accuracy': float((oof_pred == y).mean()),
    'n_train': int(len(df)),
    'n_ai': int((df.label == 'ai').sum()),
    'n_real': int((df.label == 'real').sum()),
}
with open('trained_model.json', 'w') as fh:
    json.dump(model_export, fh, indent=2)
print("Wrote trained_model.json")
print(json.dumps(model_export, indent=2))
