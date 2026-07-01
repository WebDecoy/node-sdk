/**
 * Advanced fingerprint detectors: WebRTC, Speech API, worker consistency, CSS
 * media queries, fonts, permissions, DOMRect. Ported from FCaptcha detection.js.
 */

import type {
  Detection,
  Signals,
  WebRTCInfo,
  SpeechInfo,
  WorkerConsistencyInfo,
  CSSMediaQueriesInfo,
  FontsInfo,
  PermissionsInfo,
  DOMRectInfo,
} from '../types';
import { analyzeAudioContext } from './audio';
import { analyzeLies } from './lies';

export function analyzeWebRTC(webrtcInfo?: WebRTCInfo): Detection[] {
  if (!webrtcInfo || !webrtcInfo.supported) return [];
  const detections: Detection[] = [];
  const mediaDevices = webrtcInfo.mediaDevices ?? {};

  if (mediaDevices.supported && mediaDevices.totalDevices === 0) {
    detections.push({
      category: 'headless',
      score: 0.7,
      confidence: 0.75,
      reason: 'No media devices detected (typical of headless browsers)',
    });
  }

  if (mediaDevices.supported && (mediaDevices.videoInputs ?? 0) > 0 && mediaDevices.audioInputs === 0) {
    detections.push({
      category: 'bot',
      score: 0.4,
      confidence: 0.5,
      reason: 'Has video devices but no audio devices (unusual configuration)',
    });
  }

  if (webrtcInfo.hasLocalIP === false && !webrtcInfo.localIPError) {
    detections.push({
      category: 'headless',
      score: 0.4,
      confidence: 0.5,
      reason: 'No local IP addresses detected via WebRTC',
    });
  }

  return detections;
}

export function analyzeSpeechAPI(speechInfo?: SpeechInfo): Detection[] {
  if (!speechInfo || !speechInfo.supported) return [];
  const detections: Detection[] = [];
  const totalVoices = speechInfo.totalVoices ?? 0;

  if (totalVoices === 0) {
    detections.push({
      category: 'headless',
      score: 0.6,
      confidence: 0.7,
      reason: 'No speech synthesis voices available',
    });
  }

  if (totalVoices > 0 && totalVoices < 5) {
    detections.push({
      category: 'headless',
      score: 0.3,
      confidence: 0.4,
      reason: `Very few speech voices available (${totalVoices})`,
    });
  }

  if (speechInfo.localVoices === 0 && totalVoices > 0) {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'No local speech synthesis voices',
    });
  }

  return detections;
}

export function analyzeWorkerConsistency(workerConsistency?: WorkerConsistencyInfo): Detection[] {
  if (!workerConsistency || !workerConsistency.supported) return [];
  const detections: Detection[] = [];

  if (!workerConsistency.consistent && (workerConsistency.mismatchCount ?? 0) > 0) {
    const score = Math.min(0.9, 0.3 + (workerConsistency.mismatchCount ?? 0) * 0.15);
    detections.push({
      category: 'bot',
      score,
      confidence: 0.85,
      reason: `Worker/main thread mismatch detected: ${(workerConsistency.mismatches ?? []).join(', ')}`,
    });
  }

  return detections;
}

export function analyzeCSSMediaQueries(cssMedia: CSSMediaQueriesInfo | undefined, signals: Signals): Detection[] {
  if (!cssMedia || !cssMedia.supported) return [];
  const detections: Detection[] = [];
  const maxTouch = signals.environmental?.navigator?.maxTouchPoints ?? 0;

  if (cssMedia.pointer === 'coarse' && maxTouch === 0) {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: 'CSS reports coarse pointer but no touch support',
    });
  }

  if (cssMedia.hover === false && cssMedia.pointer === 'fine') {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'Fine pointer reported but no hover capability',
    });
  }

  return detections;
}

export function analyzeFonts(fontsInfo: FontsInfo | undefined, userAgent: string): Detection[] {
  if (!fontsInfo || !fontsInfo.supported) return [];
  const detections: Detection[] = [];
  const count = fontsInfo.count ?? 0;

  if (count < 3) {
    detections.push({
      category: 'headless',
      score: 0.5,
      confidence: 0.5,
      reason: `Very few fonts detected (${count})`,
    });
  }

  const ua = (userAgent || '').toLowerCase();

  if (ua.includes('windows') && fontsInfo.hasSegoeUI === false && count > 5) {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: 'Windows UA but Segoe UI font not detected',
    });
  }

  if (
    (ua.includes('mac os x') || ua.includes('macintosh')) &&
    fontsInfo.hasSFPro === false &&
    !ua.includes('10_15') &&
    !ua.includes('10_14') &&
    count > 5
  ) {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'Modern macOS UA but SF Pro font not detected',
    });
  }

  if (ua.includes('linux') && !ua.includes('android') && fontsInfo.hasDejaVuSans === false && count > 5) {
    detections.push({
      category: 'bot',
      score: 0.4,
      confidence: 0.5,
      reason: 'Linux UA but DejaVu Sans font not detected',
    });
  }

  return detections;
}

const PERMISSION_API_KEYS = [
  'hasPermissionsAPI', 'hasClipboard', 'hasShare', 'hasCredentials',
  'hasBluetooth', 'hasUsb', 'hasSerial', 'hasHid', 'hasXR',
  'hasGeolocation', 'hasMIDI',
];

export function analyzePermissions(permissionsInfo?: PermissionsInfo): Detection[] {
  if (!permissionsInfo || !permissionsInfo.supported) return [];
  const detections: Detection[] = [];

  const availableApis = PERMISSION_API_KEYS.filter((key) => permissionsInfo[key] === true).length;

  if (availableApis < 3) {
    detections.push({
      category: 'headless',
      score: 0.4,
      confidence: 0.5,
      reason: `Very few navigator APIs available (${availableApis})`,
    });
  }

  return detections;
}

export function analyzeDOMRect(domRectInfo?: DOMRectInfo): Detection[] {
  if (!domRectInfo || !domRectInfo.supported) return [];
  const detections: Detection[] = [];

  if (domRectInfo.rectAWidth === 0 || domRectInfo.rectBWidth === 0) {
    detections.push({
      category: 'headless',
      score: 0.6,
      confidence: 0.7,
      reason: 'DOMRect rendering returned zero-width elements',
    });
  }

  if (
    domRectInfo.rectAWidth !== undefined &&
    domRectInfo.rectBWidth !== undefined &&
    domRectInfo.rangeWidth !== undefined &&
    domRectInfo.rectAWidth === Math.floor(domRectInfo.rectAWidth) &&
    domRectInfo.rectBWidth === Math.floor(domRectInfo.rectBWidth) &&
    domRectInfo.rangeWidth === Math.floor(domRectInfo.rangeWidth)
  ) {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'DOMRect measurements are all exact integers (unusual)',
    });
  }

  return detections;
}

/** Run every advanced-fingerprint detector present in the signals. */
export function analyzeAdvancedSignals(signals: Signals, userAgent: string): Detection[] {
  const detections: Detection[] = [];
  const env = signals.environmental ?? {};

  if (env.webrtcInfo) detections.push(...analyzeWebRTC(env.webrtcInfo));
  if (env.speechInfo) detections.push(...analyzeSpeechAPI(env.speechInfo));
  if (env.workerConsistency) detections.push(...analyzeWorkerConsistency(env.workerConsistency));
  if (env.cssMediaQueries) detections.push(...analyzeCSSMediaQueries(env.cssMediaQueries, signals));
  if (env.fontsInfo) detections.push(...analyzeFonts(env.fontsInfo, userAgent));
  if (env.permissionsInfo) detections.push(...analyzePermissions(env.permissionsInfo));
  if (env.domRectFingerprint) detections.push(...analyzeDOMRect(env.domRectFingerprint));
  if (env.audioInfo) detections.push(...analyzeAudioContext(env.audioInfo));
  if (env.lieDetection) detections.push(...analyzeLies(env.lieDetection));

  return detections;
}
