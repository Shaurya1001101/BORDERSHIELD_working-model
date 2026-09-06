# Training pipeline

This is how `js/trained-model.js` was produced, kept here so the model can be retrained
as more labeled data becomes available.

## Current model
- 141 training examples: 71 AI-generated (2 different generator/source batches), 70 real photos
- 5-fold cross-validated ROC-AUC: 0.77, accuracy: ~69%
- Zero false "strong AI" verdicts across 71 held-out real photos in manual testing
- A plain logistic regression (linear, fully inspectable) — deliberately not a black-box
  neural net, to match the rest of this tool's explainability requirement

## Retraining with more data
**Important: `features.csv` in this folder already contains the 141 rows used to train the
current model (71 AI, 70 real). Don't delete or overwrite it — `--append` only works if this
file already exists; if it's missing, extraction silently starts a brand-new file instead of
adding to the existing dataset, and training will then fail with "needs samples of at least
2 classes" because the fresh file only has whatever single batch you just extracted.**

1. Collect labeled images into two folders, e.g. `ai_images/` and `real_images/`.
2. Extract features (reuses the actual browser JS via Node+jsdom, so training features
   exactly match what the live tool computes):
   ```
   node extract_features.js ai_images/ ai features.csv --append
   node extract_features.js real_images/ real features.csv --append
   ```
   (`--append` supports resuming/adding more data later — it skips rows already present,
   keyed by (label, filename), and writes each row incrementally so an interrupted run
   doesn't lose progress.)
   
   Sanity-check before training:
   ```
   node -e "const l=require('fs').readFileSync('features.csv','utf8').trim().split('\n'); console.log(l.length-1, 'total rows')"
   ```
   This should print a number bigger than 141 (or however many you had last time) — if it
   only shows your new batch's count, `features.csv` got reset and you should stop and fix
   that before training (restore this folder's original `features.csv` and re-run the
   `--append` commands above).
3. Train:
   ```
   pip install scikit-learn pandas numpy
   python3 train_model.py
   ```
   This prints cross-validated performance, feature coefficients, and writes
   `trained_model.json`.
4. Copy the `params`/`intercept`/`features` from `trained_model.json` into the `MODEL`
   object at the top of `../js/trained-model.js`, updating the doc-comment stats
   (nTrain/nAi/nReal/cvRocAuc/cvAccuracy) to match.
5. Re-run the app's test suite (see `/test` in the project repo if available) or at minimum
   manually verify a few known AI and known real images still score sensibly before shipping.

## Requirements for useful additional data
- Real (non-AI) examples matter just as much as AI ones — a classifier trained on one
  class alone cannot learn anything.
- Diversity matters more than raw count: different AI generators, different real-photo
  sources (phone cameras, DSLRs, screenshots, downloaded web images), different
  resolutions. A dataset that's all one generator or all one camera will not generalize.
- Node.js + the `canvas` npm package are required to run `extract_features.js` (needs
  real 2D canvas support outside a browser — see package.json in this folder if present,
  otherwise `npm install canvas jsdom`).
