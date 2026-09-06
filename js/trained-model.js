// TeckThorn Sentinel — trained model (logistic regression)
// Trained on 141 real labeled examples (71 AI-generated across 2 different generator/source
// batches, 70 genuine photos from mixed sources) using the SAME feature-extraction code as
// this browser app (js/*.js run via Node+jsdom during training — see /training/ folder in the
// project repo for the extraction + training scripts). This is a small, honest, linear model —
// not a deep neural net — chosen deliberately so it stays inspectable and auditable rather than
// a black box, matching the rest of this tool's philosophy.
//
// HONEST PERFORMANCE: 5-fold cross-validated ROC-AUC 0.77, accuracy ~69% on the training data.
// That is real signal (meaningfully better than a coin flip) but far from a solved problem —
// treat its output as one more weak/moderate indicator, not a verdict. It will improve as more
// labeled training images are added; see the Methodology tab for details.
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  const MODEL = {
    intercept: -0.3160561231850826,
    params: [
      { feature: 'aspect', mean: 1.3055251826909797, std: 0.3689960975056739, coef: 0.38557181418251774 },
      { feature: 'isSquarePow2', mean: 0.09219858156028368, std: 0.2893060716932076, coef: 2.2529883797621064 },
      { feature: 'megapixels', mean: 4.929762156028368, std: 9.64503772447395, coef: -3.3961234464318864 },
      { feature: 'hasCameraExif', mean: 0.02127659574468085, std: 0.14430489325798443, coef: -1.2682869597421302 },
      { feature: 'hasPipelineTag', mean: 0.12056737588652482, std: 0.3256238378226665, coef: -0.30978862295353926 },
      { feature: 'elaGlobalMean', mean: 1.125782524721, std: 0.8033314065750556, coef: 0.8688391413221752 },
      { feature: 'elaGlobalStd', mean: 0.6821618421195229, std: 0.39848838111061724, coef: -0.10585335626825862 },
      { feature: 'elaMaxBlock', mean: 4.300416565925209, std: 2.158351455229247, coef: 0.12612881149200628 },
      { feature: 'noiseMeanEnergy', mean: 9.364483696747845, std: 5.54767612168138, coef: -1.4755963240391117 },
      { feature: 'noiseStdEnergy', mean: 8.494799942218542, std: 3.8633342759618623, coef: -0.9214819256162617 },
      { feature: 'noiseCoeffVar', mean: 1.0329807467974266, std: 0.3731817328510169, coef: 0.41197215907197915 },
      { feature: 'freqHighBand', mean: 3.4892735843145615, std: 0.1891989969137775, coef: 0.5966189184329949 },
      { feature: 'freqMidBand', mean: 3.970829757168937, std: 0.14078717378341785, coef: 0.6406047423187301 },
      { feature: 'freqMaxProminence', mean: 0.7252471775964345, std: 0.11908343609088137, coef: -0.044906749064063604 },
      { feature: 'freqMeanProminence', mean: -9.991832949179148e-05, std: 0.00010919107360832255, coef: 0.3279529686891726 },
      { feature: 'lsbMaxP', mean: 0.8455551072495051, std: 0.3297164299679504, coef: 0.00892273078790052 },
      { feature: 'lsbHighPWindows', mean: 9.113475177304965, std: 9.519738507778248, coef: -0.17611577668026723 },
    ],
    cvRocAuc: 0.7678068410462776,
    cvAccuracy: 0.6879432624113475,
    nTrain: 141, nAi: 71, nReal: 70,
  };

  /** Builds the feature vector this model expects from the same objects combineImageVerdict receives. */
  function buildFeatureVector({ ela, noise, freq, lsb, pipelineTags, hasCameraExif, width, height }) {
    const isSquarePow2 = width === height && (width & (width - 1)) === 0;
    return {
      aspect: width / height,
      isSquarePow2: isSquarePow2 ? 1 : 0,
      megapixels: (width * height) / 1e6,
      hasCameraExif: hasCameraExif ? 1 : 0,
      hasPipelineTag: (pipelineTags && pipelineTags.length) ? 1 : 0,
      elaGlobalMean: ela.globalMean, elaGlobalStd: ela.globalStd, elaMaxBlock: ela.maxBlock,
      noiseMeanEnergy: noise.meanEnergy, noiseStdEnergy: noise.stdEnergy, noiseCoeffVar: noise.coeffVar,
      freqHighBand: freq.highBand, freqMidBand: freq.midBand, freqMaxProminence: freq.maxProminence, freqMeanProminence: freq.meanProminence,
      lsbMaxP: lsb ? lsb.maxP : 0.5, lsbHighPWindows: lsb ? lsb.highPWindows : 0,
    };
  }

  function predict(featureObj) {
    let z = MODEL.intercept;
    for (const p of MODEL.params) {
      const x = featureObj[p.feature];
      z += ((x - p.mean) / p.std) * p.coef;
    }
    const probability = 1 / (1 + Math.exp(-z));
    return { probability, z };
  }

  TT.trainedModel = { MODEL, buildFeatureVector, predict };
})(window.TT);
